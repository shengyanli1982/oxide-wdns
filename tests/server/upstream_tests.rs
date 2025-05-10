// tests/server/upstream_tests.rs

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    
    use tracing::info;
    use trust_dns_proto::op::ResponseCode;
    use trust_dns_proto::rr::RecordType;
    use reqwest::Client;
    
    use oxide_wdns::server::config::{ResolverConfig, ResolverProtocol, ServerConfig};
    use oxide_wdns::server::upstream::{UpstreamManager, UpstreamSelection};
    use oxide_wdns::server::routing::Router;
    use oxide_wdns::common::consts::CONTENT_TYPE_DNS_MESSAGE;
    
    // 引入 wiremock 库和公共测试模块
    use wiremock::{Mock, MockServer, ResponseTemplate};
    use wiremock::matchers::{method, path};
    
    // 导入公共测试工具
    use crate::server::mock_http_server::{create_test_query, create_test_response, setup_mock_doh_server};
    
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
    
    #[tokio::test]
    async fn test_upstream_resolve_doh_post() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_upstream_resolve_doh_post");

        // 启动模拟DoH服务器
        info!("Starting mock DoH server with wiremock...");
        let (mock_server, counter) = setup_mock_doh_server(Ipv4Addr::new(192, 168, 1, 1)).await;
        info!("Mock DoH server started at address: {}", mock_server.uri());

        // 创建一个上游配置，使用我们的模拟DoH服务器
        info!("Creating upstream configuration with mock DoH server...");
        let mut config = create_test_config();
        config.dns.upstream.resolvers = vec![
            ResolverConfig {
                address: format!("{}/dns-query", mock_server.uri()),
                protocol: ResolverProtocol::Doh,
            }
        ];

        // 创建UpstreamManager
        info!("Creating UpstreamManager...");
        let http_client = Client::new();
        let upstream_manager = UpstreamManager::new(Arc::new(config), http_client).await.unwrap();
        info!("UpstreamManager created successfully.");

        // 创建测试查询
        info!("Creating test query...");
        let query = create_test_query("example.com", RecordType::A);

        // 执行查询
        info!("Executing query via UpstreamManager...");
        let response = upstream_manager.resolve(&query, UpstreamSelection::Global, None, None).await.unwrap();
        info!("Query executed successfully.");
        
        // 验证响应
        assert_eq!(response.response_code(), ResponseCode::NoError, "Response code should be NoError");
        assert!(!response.answers().is_empty(), "Response should contain answers");
        
        // 验证DoH服务器收到请求
        let request_count = *counter.lock().unwrap();
        assert_eq!(request_count, 1, "DoH server should have received 1 request");
        
        info!("Test completed: test_upstream_resolve_doh_post");
    }
    
    // 添加 DoH GET 请求测试
    #[tokio::test]
    async fn test_upstream_resolve_doh_get() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_upstream_resolve_doh_get");

        // 启动 MockServer
        let mock_server = MockServer::start().await;
        
        // 创建一个 mock DNS 响应
        let query = create_test_query("example.com", RecordType::A);
        let response_message = create_test_response(&query, Ipv4Addr::new(192, 168, 1, 1));
        let response_bytes = response_message.to_vec().unwrap();
        
        // 设置 GET 请求处理
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(ResponseTemplate::new(200)
                .insert_header("Content-Type", CONTENT_TYPE_DNS_MESSAGE)
                .set_body_bytes(response_bytes.clone()))
            .mount(&mock_server)
            .await;
            
        // 设置 POST 请求处理（防止测试只发 POST 请求）
        Mock::given(method("POST"))
            .and(path("/dns-query"))
            .respond_with(ResponseTemplate::new(200)
                .insert_header("Content-Type", CONTENT_TYPE_DNS_MESSAGE)
                .set_body_bytes(response_bytes.clone()))
            .mount(&mock_server)
            .await;
        
        // 创建上游配置
        let mut config = create_test_config();
        config.dns.upstream.resolvers = vec![
            ResolverConfig {
                address: format!("{}/dns-query", mock_server.uri()),
                protocol: ResolverProtocol::Doh,
            }
        ];
        
        // 创建 UpstreamManager
        let _router = Arc::new(Router::new(config.dns.routing.clone(), Some(Client::new())).await.unwrap());
        let http_client = Client::new();
        let upstream_manager = UpstreamManager::new(Arc::new(config), http_client).await.unwrap();
        
        // 执行查询
        let query = create_test_query("example.com", RecordType::A);
        let response = upstream_manager.resolve(&query, UpstreamSelection::Global, None, None).await.unwrap();
        
        // 验证响应
        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert!(!response.answers().is_empty());
        
        info!("Test completed: test_upstream_resolve_doh_get");
    }
} 