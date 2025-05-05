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
    use tracing::info; // 添加 tracing 引用
    use oxide_wdns::server::routing::Router;
    use reqwest::Client;

    // === 辅助函数 / 模拟 ===
    
    // 创建测试用ServerConfig
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
    
    // 创建模拟的服务器状态，用于测试
    async fn create_mock_server_state() -> ServerState {
        let config = create_test_config();
        let router = Arc::new(Router::new(config.dns.routing.clone(), Some(Client::new())).await.unwrap());
        let http_client = Client::new();
        let upstream = Arc::new(UpstreamManager::new(&config, router.clone(), http_client).await.unwrap());
        let cache = Arc::new(DnsCache::new(config.dns.cache.clone())); // 移除unwrap并传递值而非引用
        let metrics = Arc::new(DnsMetrics::new());
        
        ServerState {
            config,
            upstream,
            cache,
            metrics,
            router,
        }
    }
    
    // 创建一个DNS查询Message
    fn create_test_query(domain: &str, record_type: RecordType) -> Message {
        let name = Name::from_ascii(domain).unwrap();
        let mut query = Message::new();
        query.set_id(1234)
             .set_message_type(MessageType::Query)
             .set_op_code(OpCode::Query)
             .add_query(trust_dns_proto::op::Query::query(name, record_type));
        query
    }
    
    // 构建HTTP请求
    fn build_http_request(method: Method, uri: &str, headers: Vec<(&str, &str)>, body: Vec<u8>) -> Request<Body> {
        let mut builder = Request::builder()
            .method(method)
            .uri(uri);
            
        for (name, value) in headers {
            builder = builder.header(name, value);
        }
        
        builder.body(Body::from(body)).unwrap()
    }
    
    // 将DNS消息编码为Base64 URL安全格式
    fn encode_dns_message_base64url(message: &Message) -> String {
        let bytes = message.to_vec().unwrap();
        BASE64_ENGINE.encode(bytes)
    }
    
    // 从HTTP响应正文解码DNS响应消息
    async fn decode_dns_response(body: &[u8]) -> Result<Message, String> {
        Message::from_vec(body).map_err(|e| format!("Failed to parse DNS message: {}", e))
    }
    
    #[tokio::test]
    async fn test_doh_post_invalid_content_type() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_doh_post_invalid_content_type");

        // 创建服务器状态
        info!("Creating mock server state...");
        let state = create_mock_server_state().await;
        info!("Mock server state created.");

        // 创建一个DNS查询
        let query = create_test_query("example.com", RecordType::A);
        let query_bytes = query.to_vec().unwrap();
        info!("Created test query for example.com (A)");

        // 构建一个POST请求，使用错误的Content-Type
        info!("Building POST request with invalid Content-Type (application/json)...");
        let request = build_http_request(
            Method::POST, 
            "/dns-query", 
            vec![("Content-Type", "application/json")], // 错误的Content-Type
            query_bytes
        );

        // 使用doh_routes代替直接调用handle_dns_wire_post
        info!("Sending request to DoH handler...");
        let app = doh_routes(state);
        let response = app
            .oneshot(request)
            .await
            .unwrap();
        info!("Received response with status: {}", response.status());

        // 验证返回了400 Bad Request (而非415 Unsupported Media Type，实际实现可能有所不同)
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "Expected Bad Request for invalid Content-Type");
        info!("Validated response status is BAD_REQUEST as expected.");
        info!("Test completed: test_doh_post_invalid_content_type");
    }

    #[tokio::test]
    async fn test_doh_get_missing_dns_param() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_doh_get_missing_dns_param");

        // 创建服务器状态
        info!("Creating mock server state...");
        let state = create_mock_server_state().await;
        info!("Mock server state created.");

        // 构建GET请求，不包含dns参数
        info!("Building GET request without 'dns' parameter...");
        let request = build_http_request(
            Method::GET, 
            "/dns-query", // 没有dns=参数
            vec![], 
            vec![]
        );

        // 调用DoH处理函数
        info!("Sending request to DoH handler...");
        let app = doh_routes(state);
        let response = app
            .oneshot(request)
            .await
            .unwrap();
        info!("Received response with status: {}", response.status());

        // 验证返回了400 Bad Request
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "Expected Bad Request for missing 'dns' parameter");
        info!("Validated response status is BAD_REQUEST as expected.");
        info!("Test completed: test_doh_get_missing_dns_param");
    }

    #[tokio::test]
    async fn test_doh_get_invalid_base64url_param() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_doh_get_invalid_base64url_param");

        // 创建服务器状态
        info!("Creating mock server state...");
        let state = create_mock_server_state().await;
        info!("Mock server state created.");

        // 构建GET请求，dns参数值不是有效的Base64URL编码
        info!("Building GET request with invalid Base64URL 'dns' parameter...");
        let request = build_http_request(
            Method::GET, 
            "/dns-query?dns=invalid@base64^characters!", // 无效的Base64编码
            vec![], 
            vec![]
        );

        // 调用DoH处理函数
        info!("Sending request to DoH handler...");
        let app = doh_routes(state);
        let response = app
            .oneshot(request)
            .await
            .unwrap();
        info!("Received response with status: {}", response.status());

        // 验证返回了400 Bad Request
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "Expected Bad Request for invalid Base64URL parameter");
        info!("Validated response status is BAD_REQUEST as expected.");
        info!("Test completed: test_doh_get_invalid_base64url_param");
    }

    #[tokio::test]
    async fn test_doh_post_empty_body() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_doh_post_empty_body");

        // 创建服务器状态
        info!("Creating mock server state...");
        let state = create_mock_server_state().await;
        info!("Mock server state created.");

        // 构建POST请求，空请求体
        info!("Building POST request with empty body...");
        let request = build_http_request(
            Method::POST, 
            "/dns-query", 
            vec![("Content-Type", CONTENT_TYPE_DNS_MESSAGE)], 
            vec![] // 空请求体
        );

        // 使用doh_routes代替直接调用handle_dns_wire_post
        info!("Sending request to DoH handler...");
        let app = doh_routes(state);
        let response = app
            .oneshot(request)
            .await
            .unwrap();
        info!("Received response with status: {}", response.status());

        // 验证返回了400 Bad Request
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "Expected Bad Request for empty body");
        info!("Validated response status is BAD_REQUEST as expected.");
        info!("Test completed: test_doh_post_empty_body");
    }

    #[tokio::test]
    async fn test_doh_post_malformed_dns_query() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_doh_post_malformed_dns_query");

        // 创建服务器状态
        info!("Creating mock server state...");
        let state = create_mock_server_state().await;
        info!("Mock server state created.");

        // 构建包含无效DNS消息的POST请求
        info!("Building POST request with malformed DNS query data...");
        let request = build_http_request(
            Method::POST, 
            "/dns-query", 
            vec![("Content-Type", CONTENT_TYPE_DNS_MESSAGE)], 
            vec![1, 2, 3, 4] // 无效的DNS消息
        );

        // 使用doh_routes代替直接调用handle_dns_wire_post
        info!("Sending request to DoH handler...");
        let app = doh_routes(state);
        let response = app
            .oneshot(request)
            .await
            .unwrap();
        info!("Received response with status: {}", response.status());

        // 验证返回了400 Bad Request
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "Expected Bad Request for malformed DNS query");
        info!("Validated response status is BAD_REQUEST as expected.");
        info!("Test completed: test_doh_post_malformed_dns_query");
    }

    #[tokio::test]
    async fn test_doh_handler_preserves_query_id() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug,trust_dns_proto=info").try_init();
        info!("Starting test: test_doh_handler_preserves_query_id");

        // 创建服务器状态
        info!("Creating mock server state...");
        let state = create_mock_server_state().await;
        info!("Mock server state created.");

        // 创建一个具有特定ID的DNS查询
        let mut query = create_test_query("example.org", RecordType::A);
        let specific_id = 4321;
        query.set_id(specific_id);
        info!("Created test query for example.org (A) with specific ID: {}", specific_id);

        // 将查询编码为二进制格式
        let query_bytes = query.to_vec().unwrap();

        // 构建POST请求
        info!("Building POST request with the specific query...");
        let request = build_http_request(
            Method::POST, 
            "/dns-query", 
            vec![("Content-Type", CONTENT_TYPE_DNS_MESSAGE)], 
            query_bytes
        );

        // 使用doh_routes代替直接调用handle_dns_wire_post
        info!("Sending request to DoH handler...");
        let app = doh_routes(state);
        let response = app
            .oneshot(request)
            .await
            .unwrap();
        let status = response.status();
        info!("Received response with status: {}", status);
        assert_eq!(status, StatusCode::OK, "Expected OK status for valid query");

        // 从响应体中解析DNS消息
        info!("Decoding DNS response from body...");
        let body_bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let response_message = decode_dns_response(&body_bytes).await.unwrap();
        info!("Decoded DNS response with ID: {}", response_message.id());

        // 验证响应ID与请求ID是否一致
        assert_eq!(response_message.id(), specific_id, "Response ID should match request ID");
        info!("Validated that response ID matches the original query ID.");
        info!("Test completed: test_doh_handler_preserves_query_id");
    }

    #[tokio::test]
    async fn test_doh_handler_valid_get_request() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug,trust_dns_proto=info").try_init();
        info!("Starting test: test_doh_handler_valid_get_request");

        // 创建服务器状态
        info!("Creating mock server state...");
        let state = create_mock_server_state().await;
        info!("Mock server state created.");

        // 创建一个DNS查询
        let query = create_test_query("google.com", RecordType::A);
        info!("Created test query for google.com (A)");

        // 将查询编码为Base64URL
        let query_base64 = encode_dns_message_base64url(&query);
        info!("Encoded query to Base64URL (length: {} chars)", query_base64.len());

        // 构建GET请求
        let uri = format!("/dns-query?dns={}", query_base64);
        info!("Building GET request to URI: {}", uri);
        let request = build_http_request(
            Method::GET,
            &uri,
            vec![],
            vec![],
        );

        // 调用DoH处理函数
        info!("Sending request to DoH handler...");
        let app = doh_routes(state);
        let response = app
            .oneshot(request)
            .await
            .unwrap();
        let status = response.status();
        info!("Received response with status: {}", status);

        // 验证响应状态码是200 OK
        assert_eq!(status, StatusCode::OK, "Expected OK status for valid GET request");

        // 验证Content-Type是application/dns-message
        let content_type = response.headers().get(header::CONTENT_TYPE).unwrap().to_str().unwrap();
        info!("Response Content-Type: {}", content_type);
        assert_eq!(content_type, CONTENT_TYPE_DNS_MESSAGE, "Incorrect Content-Type header");

        // 解析响应体中的DNS消息
        info!("Decoding DNS response from body...");
        let body_bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let response_message = decode_dns_response(&body_bytes).await.unwrap();
        info!("Decoded DNS response with ID: {}", response_message.id());

        // 验证响应是DNS响应消息
        assert_eq!(response_message.message_type(), MessageType::Response, "Expected DNS response message");
        assert!(response_message.answer_count() > 0, "Expected at least one answer in the response");
        info!("Validated response is a valid DNS response with answers.");
        info!("Test completed: test_doh_handler_valid_get_request");
    }

    #[tokio::test]
    async fn test_doh_handler_valid_post_request() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug,trust_dns_proto=info").try_init();
        info!("Starting test: test_doh_handler_valid_post_request");

        // 创建服务器状态
        info!("Creating mock server state...");
        let state = create_mock_server_state().await;
        info!("Mock server state created.");

        // 创建一个DNS查询
        let query = create_test_query("cloudflare.com", RecordType::AAAA);
        info!("Created test query for cloudflare.com (AAAA)");

        // 将查询编码为二进制格式
        let query_bytes = query.to_vec().unwrap();

        // 构建POST请求
        info!("Building POST request...");
        let request = build_http_request(
            Method::POST,
            "/dns-query",
            vec![("Content-Type", CONTENT_TYPE_DNS_MESSAGE)],
            query_bytes,
        );

        // 使用doh_routes代替直接调用handle_dns_wire_post
        info!("Sending request to DoH handler...");
        let app = doh_routes(state);
        let response = app
            .oneshot(request)
            .await
            .unwrap();
        let status = response.status();
        info!("Received response with status: {}", status);

        // 验证响应状态码是200 OK
        assert_eq!(status, StatusCode::OK, "Expected OK status for valid POST request");

        // 验证Content-Type是application/dns-message
        let content_type = response.headers().get(header::CONTENT_TYPE).unwrap().to_str().unwrap();
        info!("Response Content-Type: {}", content_type);
        assert_eq!(content_type, CONTENT_TYPE_DNS_MESSAGE, "Incorrect Content-Type header");

        // 解析响应体中的DNS消息
        info!("Decoding DNS response from body...");
        let body_bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let response_message = decode_dns_response(&body_bytes).await.unwrap();
        info!("Decoded DNS response with ID: {}", response_message.id());

        // 验证响应是DNS响应消息
        assert_eq!(response_message.message_type(), MessageType::Response, "Expected DNS response message");
        assert!(response_message.answer_count() > 0, "Expected at least one answer in the response");
        info!("Validated response is a valid DNS response with answers.");
        info!("Test completed: test_doh_handler_valid_post_request");
    }

    #[tokio::test]
    async fn test_doh_handler_unsupported_http_method() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_doh_handler_unsupported_http_method");

        // 创建服务器状态
        info!("Creating mock server state...");
        let state = create_mock_server_state().await;
        info!("Mock server state created.");

        // 构建PUT请求
        info!("Building PUT request (unsupported method)...");
        let request = build_http_request(
            Method::PUT,
            "/dns-query",
            vec![],
            vec![],
        );

        // 调用DoH处理函数
        info!("Sending request to DoH handler...");
        let app = doh_routes(state);
        let response = app
            .oneshot(request)
            .await
            .unwrap();
        info!("Received response with status: {}", response.status());

        // 验证返回了405 Method Not Allowed
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED, "Expected Method Not Allowed for PUT request");
        info!("Validated response status is METHOD_NOT_ALLOWED as expected.");
        info!("Test completed: test_doh_handler_unsupported_http_method");
    }
} 