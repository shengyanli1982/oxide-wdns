// tests/server/doh_handler_advanced_tests.rs

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    
    use axum::{
        http::{Request, StatusCode, header, Method},
        body::{Body, to_bytes},
    };
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as BASE64_ENGINE};
    use tower::util::ServiceExt; // 用于oneshot方法的trait
    use trust_dns_proto::op::{Message, MessageType, OpCode};
    use trust_dns_proto::rr::{Name, RecordType};
    
    use oxide_wdns::common::consts::CONTENT_TYPE_DNS_MESSAGE;
    use oxide_wdns::server::config::ServerConfig;
    use oxide_wdns::server::upstream::UpstreamManager;
    use oxide_wdns::server::cache::DnsCache;
    use oxide_wdns::server::metrics::DnsMetrics;
    use oxide_wdns::server::doh_handler::{ServerState, doh_routes};
    
    // === 辅助函数 / 模拟 ===
    
    /// 创建测试用ServerConfig
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
    
    /// 创建模拟的服务器状态，用于测试
    async fn create_mock_server_state() -> ServerState {
        let config = create_test_config();
        let upstream = Arc::new(UpstreamManager::new(&config).await.unwrap());
        let cache = Arc::new(DnsCache::new(config.dns.cache.clone())); // 移除unwrap并传递值而非引用
        let metrics = Arc::new(DnsMetrics::new());
        
        ServerState {
            config,
            upstream,
            cache,
            metrics,
        }
    }
    
    /// 创建一个DNS查询Message
    fn create_test_query(domain: &str, record_type: RecordType) -> Message {
        let name = Name::from_ascii(domain).unwrap();
        let mut query = Message::new();
        query.set_id(1234)
             .set_message_type(MessageType::Query)
             .set_op_code(OpCode::Query)
             .add_query(trust_dns_proto::op::Query::query(name, record_type));
        query
    }
    
    /// 构建HTTP请求
    fn build_http_request(method: Method, uri: &str, headers: Vec<(&str, &str)>, body: Vec<u8>) -> Request<Body> {
        let mut builder = Request::builder()
            .method(method)
            .uri(uri);
            
        for (name, value) in headers {
            builder = builder.header(name, value);
        }
        
        builder.body(Body::from(body)).unwrap()
    }
    
    /// 将DNS消息编码为Base64 URL安全格式
    fn encode_dns_message_base64url(message: &Message) -> String {
        let bytes = message.to_vec().unwrap();
        BASE64_ENGINE.encode(bytes)
    }
    
    /// 从HTTP响应正文解码DNS响应消息
    async fn decode_dns_response(body: &[u8]) -> Result<Message, String> {
        Message::from_vec(body).map_err(|e| format!("Failed to parse DNS message: {}", e))
    }
    
    #[tokio::test]
    async fn test_doh_post_invalid_content_type() {
        // 创建服务器状态
        let state = create_mock_server_state().await;
        
        // 创建一个DNS查询
        let query = create_test_query("example.com", RecordType::A);
        let query_bytes = query.to_vec().unwrap();
        
        // 构建一个POST请求，使用错误的Content-Type
        let request = build_http_request(
            Method::POST, 
            "/dns-query", 
            vec![("Content-Type", "application/json")], // 错误的Content-Type
            query_bytes
        );
        
        // 使用doh_routes代替直接调用handle_dns_wire_post
        let app = doh_routes(state);
        let response = app
            .oneshot(request)
            .await
            .unwrap();
        
        // 验证返回了400 Bad Request (而非415 Unsupported Media Type，实际实现可能有所不同)
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_doh_get_missing_dns_param() {
        // 创建服务器状态
        let state = create_mock_server_state().await;
        
        // 构建GET请求，不包含dns参数
        let request = build_http_request(
            Method::GET, 
            "/dns-query", // 没有dns=参数
            vec![], 
            vec![]
        );
        
        // 调用DoH处理函数
        let app = doh_routes(state);
        let response = app
            .oneshot(request)
            .await
            .unwrap();
        
        // 验证返回了400 Bad Request
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_doh_get_invalid_base64url_param() {
        // 创建服务器状态
        let state = create_mock_server_state().await;
        
        // 构建GET请求，dns参数值不是有效的Base64URL编码
        let request = build_http_request(
            Method::GET, 
            "/dns-query?dns=invalid@base64^characters!", // 无效的Base64编码
            vec![], 
            vec![]
        );
        
        // 调用DoH处理函数
        let app = doh_routes(state);
        let response = app
            .oneshot(request)
            .await
            .unwrap();
        
        // 验证返回了400 Bad Request
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_doh_post_empty_body() {
        // 创建服务器状态
        let state = create_mock_server_state().await;
        
        // 构建POST请求，空请求体
        let request = build_http_request(
            Method::POST, 
            "/dns-query", 
            vec![("Content-Type", CONTENT_TYPE_DNS_MESSAGE)], 
            vec![] // 空请求体
        );
        
        // 使用doh_routes代替直接调用handle_dns_wire_post
        let app = doh_routes(state);
        let response = app
            .oneshot(request)
            .await
            .unwrap();
        
        // 验证返回了400 Bad Request
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_doh_post_malformed_dns_query() {
        // 创建服务器状态
        let state = create_mock_server_state().await;
        
        // 构建包含无效DNS消息的POST请求
        let request = build_http_request(
            Method::POST, 
            "/dns-query", 
            vec![("Content-Type", CONTENT_TYPE_DNS_MESSAGE)], 
            vec![1, 2, 3, 4] // 无效的DNS消息
        );
        
        // 使用doh_routes代替直接调用handle_dns_wire_post
        let app = doh_routes(state);
        let response = app
            .oneshot(request)
            .await
            .unwrap();
        
        // 验证返回了400 Bad Request
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_doh_handler_preserves_query_id() {
        // 创建服务器状态
        let state = create_mock_server_state().await;
        
        // 创建一个具有特定ID的DNS查询
        let mut query = create_test_query("example.org", RecordType::A);
        let specific_id = 4321;
        query.set_id(specific_id);
        
        // 将查询编码为二进制格式
        let query_bytes = query.to_vec().unwrap();
        
        // 构建POST请求
        let request = build_http_request(
            Method::POST, 
            "/dns-query", 
            vec![("Content-Type", CONTENT_TYPE_DNS_MESSAGE)], 
            query_bytes
        );
        
        // 使用doh_routes代替直接调用handle_dns_wire_post
        let app = doh_routes(state);
        let response = app
            .oneshot(request)
            .await
            .unwrap();
        
        // 检查响应状态码
        assert_eq!(response.status(), StatusCode::OK);
        
        // 提取响应体并解码DNS响应
        let response_bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        
        let dns_response = decode_dns_response(&response_bytes).await.unwrap();
        
        // 验证响应ID与查询ID相同
        assert_eq!(dns_response.id(), specific_id);
    }

    #[tokio::test]
    async fn test_doh_handler_valid_get_request() {
        // 创建服务器状态
        let state = create_mock_server_state().await;
        
        // 创建一个DNS查询，并编码为Base64URL格式
        let query = create_test_query("example.com", RecordType::A);
        let dns_param = encode_dns_message_base64url(&query);
        
        // 构建GET请求
        let uri = format!("/dns-query?dns={}", dns_param);
        let request = build_http_request(
            Method::GET, 
            &uri, 
            vec![], 
            vec![]
        );
        
        // 调用DoH处理函数
        let app = doh_routes(state);
        let response = app
            .oneshot(request)
            .await
            .unwrap();
        
        // 验证返回了200 OK
        assert_eq!(response.status(), StatusCode::OK);
        
        // 验证Content-Type正确
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            CONTENT_TYPE_DNS_MESSAGE
        );
        
        // 提取响应体并验证DNS响应有效
        let response_bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        
        let dns_response = decode_dns_response(&response_bytes).await.unwrap();
        assert_eq!(dns_response.message_type(), MessageType::Response);
    }

    #[tokio::test]
    async fn test_doh_handler_valid_post_request() {
        // 创建服务器状态
        let state = create_mock_server_state().await;
        
        // 创建一个DNS查询
        let query = create_test_query("example.net", RecordType::A);
        let query_bytes = query.to_vec().unwrap();
        
        // 构建POST请求
        let request = build_http_request(
            Method::POST, 
            "/dns-query", 
            vec![("Content-Type", CONTENT_TYPE_DNS_MESSAGE)], 
            query_bytes
        );
        
        // 使用doh_routes代替直接调用handle_dns_wire_post
        let app = doh_routes(state);
        let response = app
            .oneshot(request)
            .await
            .unwrap();
        
        // 验证返回了200 OK
        assert_eq!(response.status(), StatusCode::OK);
        
        // 验证Content-Type正确
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            CONTENT_TYPE_DNS_MESSAGE
        );
        
        // 提取响应体并验证DNS响应有效
        let response_bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        
        let dns_response = decode_dns_response(&response_bytes).await.unwrap();
        assert_eq!(dns_response.message_type(), MessageType::Response);
    }

    #[tokio::test]
    async fn test_doh_handler_unsupported_http_method() {
        // 创建服务器状态
        let state = create_mock_server_state().await;
        
        // 构建PUT请求（不支持的方法）
        let request = build_http_request(
            Method::PUT, 
            "/dns-query", 
            vec![("Content-Type", CONTENT_TYPE_DNS_MESSAGE)], 
            vec![]
        );
        
        // 调用DoH路由
        let app = doh_routes(state);
        let response = app
            .oneshot(request)
            .await
            .unwrap();
        
        // 验证返回了405 Method Not Allowed
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }
} 