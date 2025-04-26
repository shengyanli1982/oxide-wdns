// tests/server/upstream_tests.rs

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};
    
    use axum::{response::IntoResponse, Router, routing::post};
    use axum::extract::State;
    use bytes::Bytes;
    use futures::future;
    use futures::future::join_all;
    use hyper::StatusCode;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::oneshot;
    use tokio::time::sleep;
    use tracing::{debug, info, warn};
    use trust_dns_proto::op::{Message, MessageType, ResponseCode, OpCode, Query};
    use trust_dns_proto::rr::{Name, RData, Record, RecordType, rdata::A};
    
    use oxide_wdns::server::config::{ResolverConfig, ResolverProtocol, ServerConfig};
    use oxide_wdns::server::config::UpstreamConfig;
    use oxide_wdns::server::upstream::UpstreamManager;
    use oxide_wdns::common::error::AppError;
    
    // === 辅助函数 / 模拟 ===
    
    // 创建测试用的DNS请求消息
    fn create_test_query(domain: &str, record_type: RecordType) -> Message {
        let name = Name::from_ascii(domain).unwrap();
        let mut query = Message::new();
        query.set_id(1234)
             .set_message_type(MessageType::Query)
             .set_op_code(OpCode::Query)
             .add_query(Query::query(name, record_type));
        query
    }
    
    // 创建测试响应消息
    fn create_test_response(query: &Message, ip: Ipv4Addr) -> Message {
        let mut response = Message::new();
        response.set_id(query.id())
                .set_message_type(MessageType::Response)
                .set_op_code(query.op_code())
                .set_recursion_desired(query.recursion_desired())
                .set_recursion_available(true);
                
        // 复制所有查询
        for q in query.queries() {
            response.add_query(q.clone());
        }
        
        // 添加A记录响应
        if let Some(query) = query.queries().first() {
            if query.query_type() == RecordType::A {
                let mut record = Record::new();
                record.set_name(query.name().clone())
                      .set_ttl(300)
                      .set_record_type(RecordType::A)
                      .set_data(Some(RData::A(A(ip))));
                
                response.add_answer(record);
            }
        }
        
        response
    }
    
    // 创建简单的ServerConfig用于测试
    fn create_test_config() -> ServerConfig {
        let config_str = r#"
        http_server:
          listen_addr: "127.0.0.1:8053"
          timeout: 10
          rate_limit:
            enabled: false
        dns_resolver:
          upstream:
            resolvers:
              - address: "8.8.8.8:53"
                protocol: udp
            query_timeout: 3
            enable_dnssec: false
          http_client:
            timeout: 5
            pool:
              idle_timeout: 60
              max_idle_connections: 20
            request:
              user_agent: "oxide-wdns-test/0.1.0"
          cache:
            enabled: false
        "#;
        
        serde_yaml::from_str(config_str).unwrap()
    }
    
    // 创建一个临时的测试DoH服务器
    async fn start_mock_doh_server(response_ip: Ipv4Addr) -> (SocketAddr, Arc<Mutex<usize>>, oneshot::Sender<()>) {
        // 创建请求计数器
        let counter = Arc::new(Mutex::new(0));
        let counter_clone = Arc::clone(&counter);
        
        // 创建处理函数
        let response_ip_final = response_ip;
        async fn handle_post(
            body: Bytes,
            counter: Arc<Mutex<usize>>,
            ip: Ipv4Addr,
        ) -> impl IntoResponse {
            // 增加计数器
            {
                let mut count = counter.lock().unwrap();
                *count += 1;
            }
            
            // 解析请求
            let query_message = match Message::from_vec(&body) {
                Ok(msg) => msg,
                Err(_) => return (StatusCode::BAD_REQUEST, "Invalid DNS message").into_response(),
            };
            
            // 创建响应
            let response_message = create_test_response(&query_message, ip);
            
            // 转换为字节
            let response_bytes = match response_message.to_vec() {
                Ok(bytes) => bytes,
                Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to create response").into_response(),
            };
            
            // 返回响应
            (
                StatusCode::OK,
                [("Content-Type", "application/dns-message")],
                response_bytes,
            ).into_response()
        }
        
        // 创建应用
        let app = Router::new().route("/dns-query", post(move |body: Bytes| {
            let counter = Arc::clone(&counter_clone);
            let ip = response_ip_final;
            handle_post(body, counter, ip)
        }));
        
        // 启动服务器
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        
        // 创建关闭通道
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        
        // 启动服务器
        tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await
                .unwrap();
        });
        
        // 返回服务器地址和信号发送器
        (addr, counter, shutdown_tx)
    }
    
    #[tokio::test]
    async fn test_upstream_resolve_doh_post() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_upstream_resolve_doh_post");

        // 启动模拟DoH服务器
        info!("Starting mock DoH server...");
        let (addr, counter, shutdown_tx) = start_mock_doh_server(Ipv4Addr::new(192, 168, 1, 1)).await;
        info!("Mock DoH server started at address: {}", addr);

        // 创建一个上游配置，使用我们的模拟DoH服务器
        info!("Creating upstream configuration with mock DoH server...");
        let mut config = create_test_config();
        config.dns.upstream.resolvers = vec![
            ResolverConfig {
                address: format!("http://{}/dns-query", addr),
                protocol: ResolverProtocol::Doh,
            }
        ];

        // 创建UpstreamManager
        info!("Creating UpstreamManager...");
        let upstream_manager = UpstreamManager::new(&config).await.unwrap();
        info!("UpstreamManager created successfully.");

        // 创建测试查询
        info!("Creating test query...");
        let query = create_test_query("example.com", RecordType::A);

        // 执行查询
        info!("Executing query via UpstreamManager...");
        let response = upstream_manager.resolve(&query).await.unwrap();
        info!("Query executed successfully.");
        
        // 验证响应
        assert_eq!(response.response_code(), ResponseCode::NoError, "Response code should be NoError");
        assert!(!response.answers().is_empty(), "Response should contain answers");
        
        // 验证DoH服务器收到请求
        let request_count = *counter.lock().unwrap();
        assert_eq!(request_count, 1, "DoH server should have received 1 request");
        
        // 关闭DoH服务器
        let _ = shutdown_tx.send(());
        
        info!("Test completed: test_upstream_resolve_doh_post");
    }
    
    // 其他测试用例暂时注释掉，等配置测试通过后再逐一修改
    // ... 
} 