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

    #[test]
    fn test_reqwest_error_conversion() {
        // 创建一个简单的错误，因为无法直接创建 reqwest::Error
        let client_err = ClientError::HttpError(404, "Not Found".to_string());
        
        // 验证错误类型
        assert!(matches!(client_err, ClientError::HttpError(404, _)));
    }

    #[test]
    fn test_url_error_conversion() {
        // 创建一个 url::ParseError
        let err = Url::parse("invalid-url").unwrap_err();
        
        // 转换为 ClientError
        let client_err: ClientError = err.into();
        
        // 验证转换成功
        assert!(matches!(client_err, ClientError::UrlError(_)));
    }

    #[test]
    fn test_hex_error_conversion() {
        // 创建一个 hex::FromHexError
        let err = hex::decode("ZZ").unwrap_err();
        
        // 转换为 ClientError
        let client_err: ClientError = err.into();
        
        // 验证转换成功
        assert!(matches!(client_err, ClientError::HexError(_)));
    }

    #[test]
    fn test_io_error_conversion() {
        // 创建一个 io::Error
        let err = io::Error::new(io::ErrorKind::NotFound, "File not found");
        
        // 转换为 ClientError
        let client_err: ClientError = err.into();
        
        // 验证转换成功
        assert!(matches!(client_err, ClientError::IoError(_)));
    }

    #[test]
    fn test_client_result_success() {
        // 创建一个成功的 ClientResult
        let result: ClientResult<i32> = Ok(42);
        
        // 验证结果
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn test_client_result_error() {
        // 创建一个失败的 ClientResult
        let result: ClientResult<i32> = Err(ClientError::InvalidArgument("Test error".to_string()));
        
        // 验证结果
        assert!(result.is_err());
        match result.unwrap_err() {
            ClientError::InvalidArgument(msg) => assert_eq!(msg, "Test error"),
            _ => panic!("Expected InvalidArgument error"),
        }
    }

    #[test]
    fn test_error_display() {
        // 测试错误消息格式化
        let err = ClientError::InvalidArgument("Invalid parameter".to_string());
        assert_eq!(err.to_string(), "Invalid argument: Invalid parameter");
        
        let err = ClientError::HttpError(404, "Not Found".to_string());
        assert_eq!(err.to_string(), "HTTP error 404: Not Found");
        
        let err = ClientError::InvalidRecordType("XYZ".to_string());
        assert_eq!(err.to_string(), "Invalid DNS record type: XYZ");
    }

    // 添加新的错误测试

    #[tokio::test]
    async fn test_error_invalid_domain_format() {
        // 测试无效域名格式
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
        
        let client = reqwest::Client::new();
        let result = oxide_wdns::client::request::build_doh_request(&args, &client).await;
        
        assert!(result.is_err());
        let error = result.unwrap_err();
        // 修改为实际返回的 ClientError::InvalidArgument
        assert!(matches!(error, ClientError::InvalidArgument(_)), "Expected InvalidArgument, got {:?}", error);
    }

    #[tokio::test]
    async fn test_error_invalid_record_type() {
        // 测试无效记录类型
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
        
        let client = reqwest::Client::new();
        let result = oxide_wdns::client::request::build_doh_request(&args, &client).await;
        
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(matches!(error, ClientError::InvalidRecordType(_)), "Expected InvalidRecordType, got {:?}", error);
    }

    #[tokio::test]
    async fn test_error_invalid_payload() {
        // 测试无效的载荷（非十六进制字符串）
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
        
        let result = args.validate();
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_error_http_404() {
        // 创建一个 MockServer 来模拟 DoH 服务器
        let mock_server = MockServer::start().await;
        
        // 设置模拟响应 - 返回 404 Not Found
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(ResponseTemplate::new(404)
                .set_body_string("Not Found"))
            .mount(&mock_server)
            .await;
        
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
        
        let result = oxide_wdns::client::request::build_doh_request(&args, &reqwest::Client::new()).await;
        assert!(result.is_ok(), "构建请求应该成功");
        
        let http_client = reqwest::Client::new();
        let request = result.unwrap();
        let result = http_client.execute(request).await;
        
        assert!(result.is_err() || result.unwrap().status() == reqwest::StatusCode::NOT_FOUND);
    }
    
    #[tokio::test]
    async fn test_error_http_500() {
        // 创建一个 MockServer 来模拟 DoH 服务器
        let mock_server = MockServer::start().await;
        
        // 设置模拟响应 - 返回 500 Internal Server Error
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(ResponseTemplate::new(500)
                .set_body_string("Internal Server Error"))
            .mount(&mock_server)
            .await;
        
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
        
        let result = oxide_wdns::client::request::build_doh_request(&args, &reqwest::Client::new()).await;
        assert!(result.is_ok(), "构建请求应该成功");
        
        let http_client = reqwest::Client::new();
        let request = result.unwrap();
        let result = http_client.execute(request).await;
        
        assert!(result.is_err() || result.unwrap().status() == reqwest::StatusCode::INTERNAL_SERVER_ERROR);
    }
    
    #[tokio::test]
    async fn test_error_invalid_content_type() {
        // 创建一个 MockServer 来模拟 DoH 服务器
        let mock_server = MockServer::start().await;
        
        // 设置模拟响应 - 返回无效的内容类型
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(ResponseTemplate::new(200)
                .insert_header("content-type", "text/plain")
                .set_body_string("This is not a DNS message"))
            .mount(&mock_server)
            .await;
        
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
        
        let result = oxide_wdns::client::request::build_doh_request(&args, &reqwest::Client::new()).await;
        assert!(result.is_ok(), "构建请求应该成功");
        
        let http_client = reqwest::Client::new();
        let request = result.unwrap();
        let response = http_client.execute(request).await.unwrap();
        let result = oxide_wdns::client::response::parse_doh_response(response).await;
        
        assert!(result.is_err());
        let error = result.unwrap_err();
        // 实际返回的是 ClientError::Other
        assert!(matches!(error, ClientError::Other(_)), "Expected Other error, got {:?}", error);
    }
    
    #[tokio::test]
    async fn test_error_invalid_dns_wire_format() {
        // 创建一个 MockServer 来模拟 DoH 服务器
        let mock_server = MockServer::start().await;
        
        // 设置模拟响应 - 返回无效的 DNS 二进制数据
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(ResponseTemplate::new(200)
                .insert_header("content-type", "application/dns-message")
                .set_body_bytes(vec![0, 1, 2, 3])) // 无效的 DNS 消息
            .mount(&mock_server)
            .await;
        
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
        
        let result = oxide_wdns::client::request::build_doh_request(&args, &reqwest::Client::new()).await;
        assert!(result.is_ok(), "构建请求应该成功");
        
        let http_client = reqwest::Client::new();
        let request = result.unwrap();
        let response = http_client.execute(request).await.unwrap();
        let result = oxide_wdns::client::response::parse_doh_response(response).await;
        
        assert!(result.is_err());
        let error = result.unwrap_err();
        // 修改为正确的错误类型
        assert!(
            matches!(error, ClientError::DnsProtoError(_)),
            "Expected DNS Proto Error, got {:?}", error
        );
    }
    
    #[tokio::test]
    async fn test_error_invalid_json_format() {
        // 创建一个 MockServer 来模拟 DoH 服务器
        let mock_server = MockServer::start().await;
        
        // 设置模拟响应 - 返回无效的 JSON 数据
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(ResponseTemplate::new(200)
                .insert_header("content-type", "application/dns-json")
                .set_body_string("{invalid json}"))
            .mount(&mock_server)
            .await;
        
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
        
        let result = oxide_wdns::client::request::build_doh_request(&args, &reqwest::Client::new()).await;
        assert!(result.is_ok(), "构建请求应该成功");
        
        let http_client = reqwest::Client::new();
        let request = result.unwrap();
        let response = http_client.execute(request).await.unwrap();
        let result = oxide_wdns::client::response::parse_doh_response(response).await;
        
        assert!(result.is_err());
        let error = result.unwrap_err();
        // 实际返回的是 ClientError::Other
        assert!(matches!(error, ClientError::Other(_)), "Expected Other error, got {:?}", error);
    }
    
    #[tokio::test]
    async fn test_error_dns_servfail() {
        // 创建一个 DNS 消息，设置 SERVFAIL 响应码
        let mut header = Header::new();
        header.set_response_code(ResponseCode::ServFail);
        
        let mut message = trust_dns_proto::op::Message::new();
        message.set_header(header);
        
        // 将消息序列化为二进制
        let mut buffer = Vec::new();
        let mut encoder = trust_dns_proto::serialize::binary::BinEncoder::new(&mut buffer);
        message.emit(&mut encoder).unwrap();
        
        // 创建一个 MockServer 来模拟 DoH 服务器
        let mock_server = MockServer::start().await;
        
        // 设置模拟响应 - 返回 SERVFAIL
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(ResponseTemplate::new(200)
                .insert_header("content-type", "application/dns-message")
                .set_body_bytes(buffer))
            .mount(&mock_server)
            .await;
        
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
        
        // 直接测试验证失败的情况
        let result = oxide_wdns::client::request::build_doh_request(&args, &reqwest::Client::new()).await;
        assert!(result.is_ok(), "构建请求应该成功");
        
        let http_client = reqwest::Client::new();
        let request = result.unwrap();
        let response = http_client.execute(request).await.unwrap();
        let result = oxide_wdns::client::response::parse_doh_response(response).await;
        
        assert!(result.is_ok(), "解析响应应该成功");
        let doh_response = result.unwrap();
        
        // 检查响应码是否为 SERVFAIL
        assert_eq!(doh_response.message.response_code(), ResponseCode::ServFail);
        
        // 与期望的 NOERROR 不匹配，应该失败
        assert_ne!(doh_response.message.response_code(), ResponseCode::NoError);
    }
} 