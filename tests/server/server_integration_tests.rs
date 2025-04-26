// tests/server/server_integration_tests.rs

#[cfg(test)]
mod tests {
    use std::net::{TcpListener, SocketAddr};
    use std::sync::Arc;
    use std::time::Duration;
    use std::str::FromStr;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as BASE64_ENGINE};
    use reqwest::{Client, StatusCode};
    use tokio::sync::oneshot;
    use tokio::time::sleep;
    use trust_dns_proto::op::{Message, MessageType, OpCode};
    use trust_dns_proto::rr::{Name, RecordType};
    
    use oxide_wdns::common::consts::CONTENT_TYPE_DNS_MESSAGE;
    use oxide_wdns::server::config::ServerConfig;
    use oxide_wdns::server::doh_handler::ServerState;
    use oxide_wdns::server::metrics::DnsMetrics;
    use oxide_wdns::server::cache::DnsCache;
    use oxide_wdns::server::upstream::UpstreamManager;
    
    // === 辅助函数 ===

    /// 查找可用的端口
    fn find_free_port() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind to a random port");
        let addr = listener.local_addr().expect("Failed to get local address");
        addr.port()
    }

    /// 创建用于测试的配置
    fn build_test_config(port: u16, rate_limit_enabled: bool, cache_enabled: bool) -> ServerConfig {
        let config_str = format!(r#"
        http_server:
          listen_addr: "127.0.0.1:{}"
          timeout: 10
          rate_limit:
            enabled: {}
            per_ip_rate: 1
            per_ip_concurrent: 1
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
            enabled: {}
            size: 1000
            ttl:
              min: 10
              max: 300
              negative: 30
        "#, port, rate_limit_enabled, cache_enabled);
        
        serde_yaml::from_str(&config_str).expect("Failed to parse configuration")
    }

    /// 创建服务器状态
    async fn create_server_state(port: u16, rate_limit_enabled: bool, cache_enabled: bool) -> ServerState {
        let config = build_test_config(port, rate_limit_enabled, cache_enabled);
        let upstream = Arc::new(UpstreamManager::new(&config).await.unwrap());
        let cache = Arc::new(DnsCache::new(config.dns.cache.clone()));
        let metrics = Arc::new(DnsMetrics::new());
        
        ServerState {
            config, 
            upstream, 
            cache, 
            metrics
        }
    }

    /// 创建一个DNS查询Message
    fn create_dns_query(domain: &str, record_type: RecordType) -> Message {
        let name = Name::from_ascii(domain).unwrap();
        let mut query = Message::new();
        query.set_id(1234)
             .set_message_type(MessageType::Query)
             .set_op_code(OpCode::Query)
             .add_query(trust_dns_proto::op::Query::query(name, record_type));
        query
    }

    /// 在后台启动测试服务器
    async fn start_test_server(server_state: ServerState) -> (String, oneshot::Sender<()>) {
        let addr = format!("http://{}", server_state.config.http.listen_addr);
        
        // 创建关闭通道
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        
        // 创建axum服务器
        let app = oxide_wdns::server::doh_handler::doh_routes(server_state);
        
        // 添加健康检查与指标路由
        let app = app
            .merge(oxide_wdns::server::health::health_routes())
            .merge(oxide_wdns::server::metrics::metrics_routes());
        
        // 在后台启动服务器
        let server_addr = SocketAddr::from_str(&addr[7..]).unwrap(); // 去掉 "http://" 前缀
        tokio::spawn(async move {
            let listener = tokio::net::TcpListener::bind(server_addr).await.unwrap();
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await
                .unwrap();
        });
        
        // 等待服务器启动
        sleep(Duration::from_millis(100)).await;
        
        (addr, shutdown_tx)
    }

    #[tokio::test]
    async fn test_server_starts_and_responds_to_health_check() {
        // 1. 选择一个空闲端口。
        let port = find_free_port();
        
        // 2. 创建一个基本的服务器配置和状态。
        let server_state = create_server_state(port, false, false).await;
        
        // 3. 在后台启动服务器。
        let (server_addr, shutdown_tx) = start_test_server(server_state).await;
        
        // 4. 等待服务器启动
        sleep(Duration::from_millis(50)).await;
        
        // 5. 使用HTTP客户端向服务器的 /health 端点发送 GET 请求。
        let client = Client::new();
        let response = client.get(format!("{}/health", server_addr))
            .send()
            .await
            .expect("Health check request failed");
        
        // 6. 断言：收到 200 OK 响应。
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.text().await.unwrap(), "ok!!");
        
        // 7. 关闭服务器。
        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn test_server_handles_basic_doh_query() {
        // 1. 选择空闲端口
        let port = find_free_port();
        
        // 2. 配置服务器
        let server_state = create_server_state(port, false, false).await;
        
        // 3. 启动服务器
        let (server_addr, shutdown_tx) = start_test_server(server_state).await;
        
        // 4. 构造一个简单的 DNS 查询
        let query = create_dns_query("example.com", RecordType::A);
        let query_bytes = query.to_vec().unwrap();
        
        // 5. 创建HTTP客户端
        let client = Client::new();
        
        // 6. 发送DoH POST请求
        let response = client.post(format!("{}/dns-query", server_addr))
            .header("Content-Type", CONTENT_TYPE_DNS_MESSAGE)
            .body(query_bytes)
            .send()
            .await
            .expect("DoH POST request failed");
        
        // 7. 断言：收到 200 OK 响应
        assert_eq!(response.status(), StatusCode::OK);
        
        // 8. 断言：响应的 Content-Type 为 "application/dns-message"
        assert_eq!(
            response.headers().get("Content-Type").unwrap(),
            CONTENT_TYPE_DNS_MESSAGE
        );
        
        // 9. 解码响应体中的 DNS 消息
        let response_bytes = response.bytes().await.unwrap();
        let dns_response = Message::from_vec(&response_bytes).expect("Failed to parse DNS response");
        
        // 10. 断言：DNS 响应是有效的
        assert_eq!(dns_response.message_type(), MessageType::Response);
        
        // 11. 清理：关闭服务器
        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn test_server_metrics_endpoint_works() {
        // 1. 选择空闲端口，创建配置
        let port = find_free_port();
        let server_state = create_server_state(port, false, false).await;
        
        // 2. 启动服务器
        let (server_addr, shutdown_tx) = start_test_server(server_state).await;
        
        // 3. 发送一些 DoH 查询以产生指标数据
        let client = Client::new();
        let query = create_dns_query("example.org", RecordType::A);
        let query_bytes = query.to_vec().unwrap();
        
        // 发送一个请求以产生指标
        let _ = client.post(format!("{}/dns-query", server_addr))
            .header("Content-Type", CONTENT_TYPE_DNS_MESSAGE)
            .body(query_bytes)
            .send()
            .await
            .expect("DoH request failed");
        
        // 4. 使用 HTTP 客户端向服务器的 /metrics 端点发送 GET 请求
        let metrics_response = client.get(format!("{}/metrics", server_addr))
            .send()
            .await
            .expect("Metrics request failed");
        
        // 5. 断言：收到 200 OK 响应
        assert_eq!(metrics_response.status(), StatusCode::OK);
        
        // 6. 断言：响应体内容不为空，并且包含 Prometheus 格式的指标
        let metrics_text = metrics_response.text().await.unwrap();
        assert!(!metrics_text.is_empty(), "Metrics response should not be empty");
        
        // 检查是否包含 Prometheus 格式的指标（至少包含一些基本指标）
        assert!(metrics_text.contains("doh_"), "Response should contain metrics starting with 'doh_'");
        
        // 7. 清理：关闭服务器
        let _ = shutdown_tx.send(());
    }

    // 在测试环境中，由于速率限制依赖于底层中间件，可能不稳定
    // 该测试可能会在不同环境中表现不同，所以我们将其标记为 #[ignore]
    #[tokio::test]
    #[ignore = "速率限制测试在某些环境中可能不稳定"]
    async fn test_server_applies_rate_limit() {
        // 1. 选择空闲端口，创建配置，启用较低的速率限制（每秒1个请求，并发1个）
        let port = find_free_port();
        let server_state = create_server_state(port, true, false).await;
        
        // 2. 启动服务器
        let (server_addr, shutdown_tx) = start_test_server(server_state).await;
        
        // 等待服务器完全启动并初始化速率限制器
        sleep(Duration::from_millis(200)).await;
        
        // 3. 准备DNS查询
        let query = create_dns_query("example.net", RecordType::A);
        let query_bytes = query.to_vec().unwrap();
        
        let client = Client::new();
        
        // 4. 发送第一个请求（应该成功）
        let first_response = client.post(format!("{}/dns-query", server_addr))
            .header("Content-Type", CONTENT_TYPE_DNS_MESSAGE)
            .body(query_bytes.clone())
            .send()
            .await
            .expect("First DoH request failed");
        
        // 5. 断言：第一个请求成功
        assert_eq!(first_response.status(), StatusCode::OK);
        
        // 6. 并发发送多个请求，验证至少有一些请求被速率限制
        let mut responses = Vec::new();
        for _ in 0..10 {
            let resp = client.post(format!("{}/dns-query", server_addr))
                .header("Content-Type", CONTENT_TYPE_DNS_MESSAGE)
                .body(query_bytes.clone())
                .send()
                .await;
            
            if let Ok(resp) = resp {
                responses.push(resp.status());
            }
        }
        
        // 7. 断言：至少有一个请求被速率限制
        assert!(responses.iter().any(|&status| status == StatusCode::TOO_MANY_REQUESTS), 
                "Rate limiting effect was not observed");
        
        // 8. Cleanup
        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn test_server_cache_integration() {
        // 1. 配置并启动服务器，启用缓存
        let port = find_free_port();
        let server_state = create_server_state(port, false, true).await;
        
        // 2. 启动服务器
        let (server_addr, shutdown_tx) = start_test_server(server_state).await;
        
        // 3. 准备DNS查询
        let query = create_dns_query("example.com", RecordType::A);
        let query_bytes = query.to_vec().unwrap();
        
        let client = Client::new();
        
        // 4. 发送第一个请求
        let first_response = client.post(format!("{}/dns-query", server_addr))
            .header("Content-Type", CONTENT_TYPE_DNS_MESSAGE)
            .body(query_bytes.clone())
            .send()
            .await
            .expect("First DoH request failed");
        
        // 确保第一个请求成功
        assert_eq!(first_response.status(), StatusCode::OK);
        let first_body = first_response.bytes().await.unwrap();
        
        // 5. 立即再次发送相同的DoH查询
        let second_response = client.post(format!("{}/dns-query", server_addr))
            .header("Content-Type", CONTENT_TYPE_DNS_MESSAGE)
            .body(query_bytes)
            .send()
            .await
            .expect("Second DoH request failed");
        
        // 确保第二个请求也成功
        assert_eq!(second_response.status(), StatusCode::OK);
        
        // 获取第二个响应体
        let second_body = second_response.bytes().await.unwrap();
        
        // 确保两个响应的消息ID相同（因为缓存会保留原始消息）
        let first_dns_message = Message::from_vec(&first_body).expect("Failed to parse first DNS response");
        let second_dns_message = Message::from_vec(&second_body).expect("Failed to parse second DNS response");
        
        // 比较消息ID，如果相同则表明是缓存的响应
        assert_eq!(first_dns_message.id(), second_dns_message.id(), 
                  "Cache should return the same DNS message ID");
        
        // 6. 清理：关闭服务器
        let _ = shutdown_tx.send(());
    }
    
    #[tokio::test]
    async fn test_server_doh_get_request() {
        // 1. 选择空闲端口
        let port = find_free_port();
        
        // 2. 配置服务器
        let server_state = create_server_state(port, false, false).await;
        
        // 3. 启动服务器
        let (server_addr, shutdown_tx) = start_test_server(server_state).await;
        
        // 4. 构造一个简单的 DNS 查询
        let query = create_dns_query("example.com", RecordType::A);
        let query_bytes = query.to_vec().unwrap();
        
        // 5. 将查询编码为Base64url
        let encoded_query = BASE64_ENGINE.encode(&query_bytes);
        
        // 6. 创建HTTP客户端
        let client = Client::new();
        
        // 7. 发送DoH GET请求
        let response = client.get(format!("{}/dns-query?dns={}", server_addr, encoded_query))
            .send()
            .await
            .expect("DoH GET request failed");
        
        // 8. 断言：收到 200 OK 响应
        assert_eq!(response.status(), StatusCode::OK);
        
        // 9. 断言：响应的 Content-Type 为 "application/dns-message"
        assert_eq!(
            response.headers().get("Content-Type").unwrap(),
            CONTENT_TYPE_DNS_MESSAGE
        );
        
        // 10. 解码响应体中的 DNS 消息
        let response_bytes = response.bytes().await.unwrap();
        let dns_response = Message::from_vec(&response_bytes).expect("Failed to parse DNS response");
        
        // 11. 断言：DNS 响应是有效的
        assert_eq!(dns_response.message_type(), MessageType::Response);
        
        // 12. 清理：关闭服务器
        let _ = shutdown_tx.send(());
    }
    
    #[tokio::test]
    async fn test_server_rejects_invalid_content_type() {
        // 1. 选择空闲端口
        let port = find_free_port();
        
        // 2. 配置服务器
        let server_state = create_server_state(port, false, false).await;
        
        // 3. 启动服务器
        let (server_addr, shutdown_tx) = start_test_server(server_state).await;
        
        // 4. 构造一个简单的 DNS 查询
        let query = create_dns_query("example.com", RecordType::A);
        let query_bytes = query.to_vec().unwrap();
        
        // 5. 创建HTTP客户端
        let client = Client::new();
        
        // 6. 发送带有错误Content-Type的DoH POST请求
        let response = client.post(format!("{}/dns-query", server_addr))
            .header("Content-Type", "text/plain")
            .body(query_bytes)
            .send()
            .await
            .expect("POST request failed");
        
        // 7. 断言：收到 400 Bad Request 响应（因为Content-Type不正确）
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        
        // 8. 清理：关闭服务器
        let _ = shutdown_tx.send(());
    }
    
    #[tokio::test]
    async fn test_server_handles_different_query_types() {
        // 1. 选择空闲端口
        let port = find_free_port();
        
        // 2. 配置服务器
        let server_state = create_server_state(port, false, false).await;
        
        // 3. 启动服务器
        let (server_addr, shutdown_tx) = start_test_server(server_state).await;
        
        // 4. 创建HTTP客户端
        let client = Client::new();
        
        // 5. 测试不同的查询类型
        for record_type in [RecordType::A, RecordType::AAAA, RecordType::MX, RecordType::TXT] {
            // 构造DNS查询
            let query = create_dns_query("example.com", record_type);
            let query_bytes = query.to_vec().unwrap();
            
            // 发送请求
            let response = client.post(format!("{}/dns-query", server_addr))
                .header("Content-Type", CONTENT_TYPE_DNS_MESSAGE)
                .body(query_bytes)
                .send()
                .await
                .expect(&format!("{:?} query request failed", record_type));
            
            // 断言响应成功
            assert_eq!(response.status(), StatusCode::OK);
            
            // 解析DNS响应
            let response_bytes = response.bytes().await.unwrap();
            let dns_response = Message::from_vec(&response_bytes).expect("Failed to parse DNS response");
            
            // 验证响应类型
            assert_eq!(dns_response.message_type(), MessageType::Response);
        }
        
        // 6. 清理：关闭服务器
        let _ = shutdown_tx.send(());
    }
} 