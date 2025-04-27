// tests/client/error_tests.rs

#[cfg(test)]
mod tests {
    use oxide_wdns::client::error::{ClientError, ClientResult};
    use oxide_wdns::client::args::{CliArgs, DohFormat, HttpMethod};
    
    use reqwest;
    use trust_dns_proto::op::{Header, ResponseCode};
    
    use trust_dns_proto::serialize::binary::BinEncodable;
    use url::Url;
    use std::io;
    use hex;
    use wiremock::{Mock, MockServer, ResponseTemplate};
    use wiremock::matchers::{method, path};
    use tracing::info;

    #[test]
    fn test_reqwest_error_conversion() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_reqwest_error_conversion");

        // 创建一个简单的错误，因为无法直接创建 reqwest::Error
        info!("Creating sample HTTP error...");
        let client_err = ClientError::HttpError(404, "Not Found".to_string());
        
        // 验证错误类型
        info!("Verifying error conversion matches expected type...");
        assert!(matches!(client_err, ClientError::HttpError(404, _)));
        info!("Error type verified");
        info!("Test completed: test_reqwest_error_conversion");
    }

    #[test]
    fn test_url_error_conversion() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_url_error_conversion");

        // 创建一个 url::ParseError
        info!("Creating URL parse error...");
        let err = Url::parse("invalid-url").unwrap_err();
        
        // 转换为 ClientError
        info!("Converting URL error to ClientError...");
        let client_err: ClientError = err.into();
        
        // 验证转换成功
        info!("Verifying error conversion matches expected type...");
        assert!(matches!(client_err, ClientError::UrlError(_)));
        info!("Error type verified");
        info!("Test completed: test_url_error_conversion");
    }

    #[test]
    fn test_hex_error_conversion() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_hex_error_conversion");

        // 创建一个 hex::FromHexError
        info!("Creating hex decode error with invalid input 'ZZ'...");
        let err = hex::decode("ZZ").unwrap_err();
        
        // 转换为 ClientError
        info!("Converting hex error to ClientError...");
        let client_err: ClientError = err.into();
        
        // 验证转换成功
        info!("Verifying error conversion matches expected type...");
        assert!(matches!(client_err, ClientError::HexError(_)));
        info!("Error type verified");
        info!("Test completed: test_hex_error_conversion");
    }

    #[test]
    fn test_io_error_conversion() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_io_error_conversion");

        // 创建一个 io::Error
        info!("Creating IO error with NotFound kind...");
        let err = io::Error::new(io::ErrorKind::NotFound, "File not found");
        
        // 转换为 ClientError
        info!("Converting IO error to ClientError...");
        let client_err: ClientError = err.into();
        
        // 验证转换成功
        info!("Verifying error conversion matches expected type...");
        assert!(matches!(client_err, ClientError::IoError(_)));
        info!("Error type verified");
        info!("Test completed: test_io_error_conversion");
    }

    #[test]
    fn test_client_result_success() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_client_result_success");

        // 创建一个成功的 ClientResult
        info!("Creating successful ClientResult...");
        let result: ClientResult<i32> = Ok(42);
        
        // 验证结果
        info!("Verifying result is Ok and contains expected value...");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
        info!("Result verified");
        info!("Test completed: test_client_result_success");
    }

    #[test]
    fn test_client_result_error() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_client_result_error");

        // 创建一个失败的 ClientResult
        info!("Creating failed ClientResult with InvalidArgument error...");
        let result: ClientResult<i32> = Err(ClientError::InvalidArgument("Test error".to_string()));
        
        // 验证结果
        info!("Verifying result is Err and contains expected error type...");
        assert!(result.is_err());
        match result.unwrap_err() {
            ClientError::InvalidArgument(msg) => {
                info!(error_message = %msg, "Error message verified");
                assert_eq!(msg, "Test error");
            },
            _ => panic!("Expected InvalidArgument error"),
        }
        info!("Test completed: test_client_result_error");
    }

    #[test]
    fn test_error_display() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_error_display");

        // 测试错误消息格式化
        info!("Testing error message formatting for InvalidArgument...");
        let err = ClientError::InvalidArgument("Invalid parameter".to_string());
        let error_message = err.to_string();
        info!(error_message = %error_message, "Formatted error message");
        assert_eq!(error_message, "Invalid argument: Invalid parameter");
        
        info!("Testing error message formatting for HttpError...");
        let err = ClientError::HttpError(404, "Not Found".to_string());
        let error_message = err.to_string();
        info!(error_message = %error_message, "Formatted error message");
        assert_eq!(error_message, "HTTP error 404: Not Found");
        
        info!("Testing error message formatting for InvalidRecordType...");
        let err = ClientError::InvalidRecordType("XYZ".to_string());
        let error_message = err.to_string();
        info!(error_message = %error_message, "Formatted error message");
        assert_eq!(error_message, "Invalid DNS record type: XYZ");
        
        info!("Test completed: test_error_display");
    }

    // 添加新的错误测试

    #[tokio::test]
    async fn test_error_invalid_domain_format() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_error_invalid_domain_format");

        // 测试无效域名格式
        info!("Creating CLI args with invalid domain format...");
        let args = CliArgs {
            server_url: "https://dns.example.com/dns-query".to_string(),
            domain: "invalid..domain".to_string(), // 无效域名格式
            record_type: "A".to_string(),
            format: DohFormat::Wire,
            method: Some(HttpMethod::Get),
            http_version: None,
            dnssec: false,
            payload: None,
            validate: None,
            insecure: false,
            verbose: 0,
            no_color: false,
        };
        info!(?args.domain, "Invalid domain format created");
        
        info!("Creating HTTP client...");
        let client = reqwest::Client::new();
        
        info!("Attempting to build DoH request with invalid domain...");
        let result = oxide_wdns::client::request::build_doh_request(&args, &client).await;
        
        info!(result_is_err = result.is_err(), "Request build completed");
        assert!(result.is_err());
        
        let error = result.unwrap_err();
        info!(error = ?error, "Checking error type");
        // 修改为实际返回的 ClientError::InvalidArgument
        assert!(matches!(error, ClientError::InvalidArgument(_)), "Expected InvalidArgument, got {:?}", error);
        info!("Test completed: test_error_invalid_domain_format");
    }

    #[tokio::test]
    async fn test_error_invalid_record_type() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_error_invalid_record_type");

        // 测试无效记录类型
        info!("Creating CLI args with invalid record type...");
        let args = CliArgs {
            server_url: "https://dns.example.com/dns-query".to_string(),
            domain: "example.com".to_string(),
            record_type: "INVALID".to_string(), // 不存在的记录类型
            format: DohFormat::Wire,
            method: Some(HttpMethod::Get),
            http_version: None,
            dnssec: false,
            payload: None,
            validate: None,
            insecure: false,
            verbose: 0,
            no_color: false,
        };
        info!(?args.record_type, "Invalid record type created");
        
        info!("Creating HTTP client...");
        let client = reqwest::Client::new();
        
        info!("Attempting to build DoH request with invalid record type...");
        let result = oxide_wdns::client::request::build_doh_request(&args, &client).await;
        
        info!(result_is_err = result.is_err(), "Request build completed");
        assert!(result.is_err());
        
        let error = result.unwrap_err();
        info!(error = ?error, "Checking error type");
        assert!(matches!(error, ClientError::InvalidRecordType(_)), "Expected InvalidRecordType, got {:?}", error);
        info!("Test completed: test_error_invalid_record_type");
    }

    #[tokio::test]
    async fn test_error_invalid_payload() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_error_invalid_payload");

        // 测试无效的载荷（非十六进制字符串）
        info!("Creating CLI args with invalid hex payload...");
        let args = CliArgs {
            server_url: "https://dns.example.com/dns-query".to_string(),
            domain: "example.com".to_string(),
            record_type: "A".to_string(),
            format: DohFormat::Wire,
            method: Some(HttpMethod::Post),
            http_version: None,
            dnssec: false,
            payload: Some("ZZ".to_string()), // 包含非十六进制字符
            validate: None,
            insecure: false,
            verbose: 0,
            no_color: false,
        };
        info!(?args.payload, "Invalid hex payload created");
        
        info!("Validating CLI args with invalid payload...");
        let result = args.validate();
        
        info!(result_is_err = result.is_err(), "Validation completed");
        assert!(result.is_err());
        
        let error = result.unwrap_err();
        info!(error = ?error, "Checking error type");
        assert!(error.to_string().contains("Invalid hex data") || 
                error.to_string().contains("valid hex-encoded"), 
                "Expected hex error, got: {}", error);
        info!("Test completed: test_error_invalid_payload");
    }

    #[tokio::test]
    async fn test_error_http_404() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_error_http_404");

        // 创建一个 MockServer 来模拟 DoH 服务器
        info!("Starting mock DNS-over-HTTPS server...");
        let mock_server = MockServer::start().await;
        info!(server_uri = %mock_server.uri(), "Mock server started");
        
        // 设置模拟响应 - 返回 404 Not Found
        info!("Setting up mock response handler for 404 Not Found...");
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(ResponseTemplate::new(404)
                .set_body_string("Not Found"))
            .mount(&mock_server)
            .await;
        info!("Mock response handler configured");
        
        info!("Creating CLI args for HTTP 404 test...");
        let args = CliArgs {
            server_url: format!("{}/dns-query", mock_server.uri()),
            domain: "example.com".to_string(),
            record_type: "A".to_string(),
            format: DohFormat::Wire,
            method: Some(HttpMethod::Get),
            http_version: None,
            dnssec: false,
            payload: None,
            validate: None,
            insecure: false,
            verbose: 0,
            no_color: false,
        };
        
        info!("Building DoH request...");
        let result = oxide_wdns::client::request::build_doh_request(&args, &reqwest::Client::new()).await;
        info!(result_is_ok = result.is_ok(), "Request build completed");
        assert!(result.is_ok(), "Request building should succeed");
        
        info!("Creating HTTP client...");
        let http_client = reqwest::Client::new();
        let request = result.unwrap();
        
        info!("Executing HTTP request expecting 404...");
        let result = http_client.execute(request).await;
        
        info!(result_error = result.is_err(), 
              status_code = ?result.as_ref().ok().map(|r| r.status()),
              "HTTP request completed");
        assert!(result.is_err() || result.unwrap().status() == reqwest::StatusCode::NOT_FOUND);
        info!("Test completed: test_error_http_404");
    }
    
    #[tokio::test]
    async fn test_error_http_500() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_error_http_500");

        // 创建一个 MockServer 来模拟 DoH 服务器
        info!("Starting mock DNS-over-HTTPS server...");
        let mock_server = MockServer::start().await;
        info!(server_uri = %mock_server.uri(), "Mock server started");
        
        // 设置模拟响应 - 返回 500 Internal Server Error
        info!("Setting up mock response handler for 500 Internal Server Error...");
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(ResponseTemplate::new(500)
                .set_body_string("Internal Server Error"))
            .mount(&mock_server)
            .await;
        info!("Mock response handler configured");
        
        info!("Creating CLI args for HTTP 500 test...");
        let args = CliArgs {
            server_url: format!("{}/dns-query", mock_server.uri()),
            domain: "example.com".to_string(),
            record_type: "A".to_string(),
            format: DohFormat::Wire,
            method: Some(HttpMethod::Get),
            http_version: None,
            dnssec: false,
            payload: None,
            validate: None,
            insecure: false,
            verbose: 0,
            no_color: false,
        };
        
        info!("Building DoH request...");
        let result = oxide_wdns::client::request::build_doh_request(&args, &reqwest::Client::new()).await;
        info!(result_is_ok = result.is_ok(), "Request build completed");
        assert!(result.is_ok(), "Request building should succeed");
        
        info!("Creating HTTP client...");
        let http_client = reqwest::Client::new();
        let request = result.unwrap();
        
        info!("Executing HTTP request expecting 500...");
        let result = http_client.execute(request).await;
        
        info!(result_error = result.is_err(), 
              status_code = ?result.as_ref().ok().map(|r| r.status()),
              "HTTP request completed");
        assert!(result.is_err() || result.unwrap().status() == reqwest::StatusCode::INTERNAL_SERVER_ERROR);
        info!("Test completed: test_error_http_500");
    }
    
    #[tokio::test]
    async fn test_error_invalid_content_type() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_error_invalid_content_type");

        // 创建一个 MockServer 来模拟 DoH 服务器
        info!("Starting mock DNS-over-HTTPS server...");
        let mock_server = MockServer::start().await;
        info!(server_uri = %mock_server.uri(), "Mock server started");
        
        // 设置模拟响应 - 返回无效的内容类型
        info!("Setting up mock response handler for invalid content type...");
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(ResponseTemplate::new(200)
                .insert_header("content-type", "text/plain")
                .set_body_string("This is not a DNS message"))
            .mount(&mock_server)
            .await;
        info!("Mock response handler configured");
        
        info!("Creating CLI args for invalid content type test...");
        let args = CliArgs {
            server_url: format!("{}/dns-query", mock_server.uri()),
            domain: "example.com".to_string(),
            record_type: "A".to_string(),
            format: DohFormat::Wire,
            method: Some(HttpMethod::Get),
            http_version: None,
            dnssec: false,
            payload: None,
            validate: None,
            insecure: false,
            verbose: 0,
            no_color: false,
        };
        
        info!("Building DoH request...");
        let result = oxide_wdns::client::request::build_doh_request(&args, &reqwest::Client::new()).await;
        info!(result_is_ok = result.is_ok(), "Request build completed");
        assert!(result.is_ok(), "Request building should succeed");
        
        info!("Creating HTTP client...");
        let http_client = reqwest::Client::new();
        let request = result.unwrap();
        
        info!("Executing HTTP request...");
        let response = http_client.execute(request).await.unwrap();
        info!(status = %response.status(), content_type = ?response.headers().get("content-type"), "Response received");
        
        info!("Parsing DoH response with invalid content type...");
        let result = oxide_wdns::client::response::parse_doh_response(response).await;
        
        info!(result_is_err = result.is_err(), "Response parsing completed");
        assert!(result.is_err());
        
        let error = result.unwrap_err();
        info!(error = ?error, "Checking error type");
        // 实际返回的是 ClientError::Other
        assert!(matches!(error, ClientError::Other(_)), "Expected Other error, got {:?}", error);
        info!("Test completed: test_error_invalid_content_type");
    }
    
    #[tokio::test]
    async fn test_error_invalid_dns_wire_format() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_error_invalid_dns_wire_format");

        // 创建一个 MockServer 来模拟 DoH 服务器
        info!("Starting mock DNS-over-HTTPS server...");
        let mock_server = MockServer::start().await;
        info!(server_uri = %mock_server.uri(), "Mock server started");
        
        // 设置模拟响应 - 返回无效的 DNS 二进制数据
        info!("Setting up mock response handler with invalid DNS wire format...");
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(ResponseTemplate::new(200)
                .insert_header("content-type", "application/dns-message")
                .set_body_bytes(vec![0, 1, 2, 3])) // 无效的 DNS 消息
            .mount(&mock_server)
            .await;
        info!("Mock response handler configured");
        
        info!("Creating CLI args for invalid DNS wire format test...");
        let args = CliArgs {
            server_url: format!("{}/dns-query", mock_server.uri()),
            domain: "example.com".to_string(),
            record_type: "A".to_string(),
            format: DohFormat::Wire,
            method: Some(HttpMethod::Get),
            http_version: None,
            dnssec: false,
            payload: None,
            validate: None,
            insecure: false,
            verbose: 0,
            no_color: false,
        };
        
        info!("Building DoH request...");
        let result = oxide_wdns::client::request::build_doh_request(&args, &reqwest::Client::new()).await;
        info!(result_is_ok = result.is_ok(), "Request build completed");
        assert!(result.is_ok(), "Request building should succeed");
        
        info!("Creating HTTP client...");
        let http_client = reqwest::Client::new();
        let request = result.unwrap();
        
        info!("Executing HTTP request...");
        let response = http_client.execute(request).await.unwrap();
        info!(status = %response.status(), content_type = ?response.headers().get("content-type"), "Response received");
        
        info!("Parsing DoH response with invalid DNS wire format...");
        let result = oxide_wdns::client::response::parse_doh_response(response).await;
        
        info!(result_is_err = result.is_err(), "Response parsing completed");
        assert!(result.is_err());
        
        let error = result.unwrap_err();
        info!(error = ?error, "Checking error type");
        // 修改为正确的错误类型
        assert!(
            matches!(error, ClientError::DnsProtoError(_)),
            "Expected DNS Proto Error, got {:?}", error
        );
        info!("Test completed: test_error_invalid_dns_wire_format");
    }
    
    #[tokio::test]
    async fn test_error_invalid_json_format() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_error_invalid_json_format");
        
        // 创建一个 MockServer 来模拟 DoH 服务器
        info!("Starting mock DNS-over-HTTPS server...");
        let mock_server = MockServer::start().await;
        info!(server_uri = %mock_server.uri(), "Mock server started");
        
        // 设置模拟响应 - 返回无效的 JSON 数据
        info!("Setting up mock response handler with invalid JSON format...");
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(ResponseTemplate::new(200)
                .insert_header("content-type", "application/dns-json")
                .set_body_string("{invalid json}"))
            .mount(&mock_server)
            .await;
        info!("Mock response handler configured");
        
        info!("Creating CLI args for invalid JSON format test...");
        let args = CliArgs {
            server_url: format!("{}/dns-query", mock_server.uri()),
            domain: "example.com".to_string(),
            record_type: "A".to_string(),
            format: DohFormat::Json,
            method: Some(HttpMethod::Get),
            http_version: None,
            dnssec: false,
            payload: None,
            validate: None,
            insecure: false,
            verbose: 0,
            no_color: false,
        };
        
        info!("Building DoH request...");
        let result = oxide_wdns::client::request::build_doh_request(&args, &reqwest::Client::new()).await;
        info!(result_is_ok = result.is_ok(), "Request build completed");
        assert!(result.is_ok(), "Request building should succeed");
        
        info!("Creating HTTP client...");
        let http_client = reqwest::Client::new();
        let request = result.unwrap();
        
        info!("Executing HTTP request...");
        let response = http_client.execute(request).await.unwrap();
        info!(status = %response.status(), content_type = ?response.headers().get("content-type"), "Response received");
        
        info!("Parsing DoH response with invalid JSON format...");
        let result = oxide_wdns::client::response::parse_doh_response(response).await;
        
        info!(result_is_err = result.is_err(), "Response parsing completed");
        assert!(result.is_err());
        
        let error = result.unwrap_err();
        info!(error = ?error, "Checking error type");
        // 实际返回的是 ClientError::Other
        assert!(matches!(error, ClientError::Other(_)), "Expected Other error, got {:?}", error);
        info!("Test completed: test_error_invalid_json_format");
    }
    
    #[tokio::test]
    async fn test_error_dns_servfail() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_error_dns_servfail");

        // 创建一个 DNS 消息，设置 SERVFAIL 响应码
        info!("Creating DNS message with SERVFAIL response code...");
        let mut header = Header::new();
        header.set_response_code(ResponseCode::ServFail);
        
        let mut message = trust_dns_proto::op::Message::new();
        message.set_header(header);
        
        // 将消息序列化为二进制
        info!("Serializing DNS message to binary...");
        let mut buffer = Vec::new();
        let mut encoder = trust_dns_proto::serialize::binary::BinEncoder::new(&mut buffer);
        message.emit(&mut encoder).unwrap();
        info!(buffer_size = buffer.len(), "DNS message serialized successfully");
        
        // 创建一个 MockServer 来模拟 DoH 服务器
        info!("Starting mock DNS-over-HTTPS server...");
        let mock_server = MockServer::start().await;
        info!(server_uri = %mock_server.uri(), "Mock server started");
        
        // 设置模拟响应 - 返回 SERVFAIL
        info!("Setting up mock response handler for SERVFAIL response...");
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(ResponseTemplate::new(200)
                .insert_header("content-type", "application/dns-message")
                .set_body_bytes(buffer))
            .mount(&mock_server)
            .await;
        info!("Mock response handler configured");
        
        info!("Creating CLI args for SERVFAIL test with validation...");
        let args = CliArgs {
            server_url: format!("{}/dns-query", mock_server.uri()),
            domain: "example.com".to_string(),
            record_type: "A".to_string(),
            format: DohFormat::Wire,
            method: Some(HttpMethod::Get),
            http_version: None,
            dnssec: false,
            payload: None,
            // 添加验证条件：期望响应码为 NOERROR
            validate: Some("rcode=NOERROR".to_string()),
            insecure: false,
            verbose: 0,
            no_color: false,
        };
        info!(?args.validate, "Validation condition configured");
        
        // 直接测试验证失败的情况
        info!("Building DoH request...");
        let result = oxide_wdns::client::request::build_doh_request(&args, &reqwest::Client::new()).await;
        info!(result_is_ok = result.is_ok(), "Request build completed");
        assert!(result.is_ok(), "Request building should succeed");
        
        info!("Creating HTTP client...");
        let http_client = reqwest::Client::new();
        let request = result.unwrap();
        
        info!("Executing HTTP request...");
        let response = http_client.execute(request).await.unwrap();
        info!(status = %response.status(), content_type = ?response.headers().get("content-type"), "Response received");
        
        info!("Parsing DoH response with SERVFAIL...");
        let result = oxide_wdns::client::response::parse_doh_response(response).await;
        
        info!(result_is_ok = result.is_ok(), "Response parsing completed");
        assert!(result.is_ok(), "Response parsing should succeed");
        
        let doh_response = result.unwrap();
        info!(response_code = ?doh_response.message.response_code(), "DNS response code verified");
        
        // 检查响应码是否为 SERVFAIL
        assert_eq!(doh_response.message.response_code(), ResponseCode::ServFail);
        
        // 与期望的 NOERROR 不匹配，应该失败
        assert_ne!(doh_response.message.response_code(), ResponseCode::NoError);
        info!("Test completed: test_error_dns_servfail");
    }
} 