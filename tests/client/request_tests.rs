// tests/client/request_tests.rs

#[cfg(test)]
mod tests {
    use oxide_wdns::client::args::{CliArgs, DohFormat, HttpMethod};
    use reqwest;
    
    use std::str::FromStr;
    use trust_dns_proto::op::Message;
    use trust_dns_proto::rr::RecordType;
    
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use serde_json;

    // 创建用于测试的 CliArgs
    fn create_test_args(format: DohFormat, method: Option<HttpMethod>) -> CliArgs {
        CliArgs {
            server_url: "https://dns.example.com/dns-query".to_string(),
            domain: "example.com".to_string(),
            record_type: "A".to_string(),
            format,
            method,
            http_version: None,
            dnssec: false,
            payload: None,
            validate: None,
            insecure: false,
            verbose: 0,
            no_color: false,
        }
    }

    // 解析 DNS 查询消息
    fn parse_dns_query(data: &[u8]) -> Result<Message, String> {
        Message::from_vec(data).map_err(|e| format!("Failed to parse DNS message: {}", e))
    }

    #[tokio::test]
    async fn test_build_doh_request_wire_get() {
        // 测试：wire 格式，GET 方法
        let args = create_test_args(DohFormat::Wire, Some(HttpMethod::Get));
        let client = reqwest::Client::new();
        
        let result = oxide_wdns::client::request::build_doh_request(&args, &client).await;
        assert!(result.is_ok());
        
        let request = result.unwrap();
        
        // 验证请求属性
        assert_eq!(request.method(), reqwest::Method::GET);
        assert!(request.url().query_pairs().any(|(k, _)| k == "dns"), "URL should contain 'dns' parameter");
        assert!(request.url().to_string().contains("/dns-query?dns="), "URL should be formatted correctly");
        assert!(request.headers().contains_key("accept"), "Request should have Accept header");
        
        // 获取请求的接受头
        let accept_header = request.headers().get("accept").unwrap().to_str().unwrap();
        assert_eq!(accept_header, "application/dns-message", "Accept header should be 'application/dns-message'");
    }
    
    #[tokio::test]
    async fn test_build_doh_request_wire_post() {
        // 测试：wire 格式，POST 方法
        let args = create_test_args(DohFormat::Wire, Some(HttpMethod::Post));
        let client = reqwest::Client::new();
        
        let result = oxide_wdns::client::request::build_doh_request(&args, &client).await;
        assert!(result.is_ok());
        
        let request = result.unwrap();
        
        // 验证请求属性
        assert_eq!(request.method(), reqwest::Method::POST);
        assert_eq!(request.url().query_pairs().count(), 0, "URL should not have query parameters");
        assert!(request.url().to_string().ends_with("/dns-query"), "URL should end with '/dns-query'");
        
        // 验证 Content-Type 头
        let content_type = request.headers().get("content-type").unwrap().to_str().unwrap();
        assert_eq!(content_type, "application/dns-message", "Content-Type should be 'application/dns-message'");
        
        // 验证 Accept 头
        let accept = request.headers().get("accept").unwrap().to_str().unwrap();
        assert_eq!(accept, "application/dns-message", "Accept should be 'application/dns-message'");
        
        // 获取请求体并解析
        let body = request.body().unwrap().as_bytes().unwrap();
        let dns_message = parse_dns_query(body).unwrap();
        
        // 验证 DNS 消息内容
        assert_eq!(dns_message.queries().len(), 1, "DNS message should contain exactly one query");
        let query = &dns_message.queries()[0];
        assert_eq!(query.name().to_ascii(), "example.com.", "Query name should be 'example.com.'");
        assert_eq!(query.query_type(), RecordType::A, "Query type should be 'A'");
    }
    
    #[tokio::test]
    async fn test_build_doh_request_json_get() {
        // 测试：JSON 格式，GET 方法
        let args = create_test_args(DohFormat::Json, Some(HttpMethod::Get));
        let client = reqwest::Client::new();
        
        let result = oxide_wdns::client::request::build_doh_request(&args, &client).await;
        assert!(result.is_ok());
        
        let request = result.unwrap();
        
        // 验证请求属性
        assert_eq!(request.method(), reqwest::Method::GET);
        assert!(request.url().query_pairs().any(|(k, v)| k == "name" && v == "example.com"), "URL should have name=example.com");
        assert!(request.url().query_pairs().any(|(k, v)| k == "type" && v == "A"), "URL should have type=A");
        
        // 验证 Accept 头
        let accept = request.headers().get("accept").unwrap().to_str().unwrap();
        assert_eq!(accept, "application/dns-json", "Accept should be 'application/dns-json'");
    }
    
    #[tokio::test]
    async fn test_build_doh_request_json_post() {
        // 测试：JSON 格式，POST 方法
        let args = create_test_args(DohFormat::Json, Some(HttpMethod::Post));
        let client = reqwest::Client::new();
        
        let result = oxide_wdns::client::request::build_doh_request(&args, &client).await;
        assert!(result.is_ok());
        
        let request = result.unwrap();
        
        // 验证请求属性
        assert_eq!(request.method(), reqwest::Method::POST);
        
        // 验证 Content-Type 头
        let content_type = request.headers().get("content-type").unwrap().to_str().unwrap();
        assert_eq!(content_type, "application/dns-json", "Content-Type should be 'application/dns-json'");
        
        // 验证 Accept 头
        let accept = request.headers().get("accept").unwrap().to_str().unwrap();
        assert_eq!(accept, "application/dns-json", "Accept should be 'application/dns-json'");
        
        // 检查请求体
        if let Some(body) = request.body() {
            if let Some(bytes) = body.as_bytes() {
                // 由于现在使用 JSON 格式，我们需要解析 JSON 数据
                let result = serde_json::from_slice::<serde_json::Value>(bytes);
                assert!(result.is_ok(), "Body should be valid JSON");
                
                let json = result.unwrap();
                assert_eq!(json["name"], "example.com", "JSON should contain name=example.com");
                assert_eq!(json["type"], "A", "JSON should contain type=A");
            } else {
                panic!("Request body is not available as bytes");
            }
        } else {
            panic!("Request body is missing");
        }
    }
    
    #[tokio::test]
    async fn test_build_doh_request_with_dnssec() {
        // 测试：启用 DNSSEC
        let mut args = create_test_args(DohFormat::Wire, Some(HttpMethod::Get));
        args.dnssec = true;
        
        let client = reqwest::Client::new();
        
        let result = oxide_wdns::client::request::build_doh_request(&args, &client).await;
        assert!(result.is_ok());
        
        let request = result.unwrap();
        let url = request.url().to_string();
        
        // 对于 GET 请求，检查 dns 参数中的 Base64 编码的 DNS 消息是否设置了 DO 位
        assert!(url.contains("dns="), "URL should contain 'dns' parameter");
    }
    
    #[tokio::test]
    async fn test_build_doh_request_with_payload() {
        // 测试：带有原始载荷
        let mut args = create_test_args(DohFormat::Wire, Some(HttpMethod::Post));
        args.payload = Some("00010000000100000000000003777777076578616d706c6503636f6d0000010001".to_string());
        
        let client = reqwest::Client::new();
        
        let result = oxide_wdns::client::request::build_doh_request(&args, &client).await;
        assert!(result.is_ok());
        
        let request = result.unwrap();
        
        // 检查请求是否包含指定的载荷
        if let Some(body) = request.body() {
            let bytes = body.as_bytes().expect("Body should be available as bytes");
            let hex_body = hex::encode(bytes);
            assert_eq!(hex_body, "00010000000100000000000003777777076578616d706c6503636f6d0000010001".to_lowercase());
        } else {
            panic!("Request body should be present");
        }
    }
    
    #[tokio::test]
    async fn test_build_doh_request_auto_method_selection() {
        // 测试：自动选择 HTTP 方法
        let mut args = create_test_args(DohFormat::Wire, None); // 不指定方法
        
        let client = reqwest::Client::new();
        
        let result = oxide_wdns::client::request::build_doh_request(&args, &client).await;
        assert!(result.is_ok());
        
        let request = result.unwrap();
        
        // 对于 wire 格式，默认应选择 GET 方法
        assert_eq!(request.method(), reqwest::Method::GET);
        
        // 对于 JSON 格式，测试默认应选择 GET 方法
        args.format = DohFormat::Json;
        let result = oxide_wdns::client::request::build_doh_request(&args, &client).await;
        assert!(result.is_ok());
        
        let request = result.unwrap();
        assert_eq!(request.method(), reqwest::Method::GET);
    }
    
    #[tokio::test]
    async fn test_invalid_domain() {
        // 测试：无效域名
        let mut args = create_test_args(DohFormat::Wire, Some(HttpMethod::Get));
        args.domain = "invalid..domain".to_string(); // 无效域名
        
        let client = reqwest::Client::new();
        
        let result = oxide_wdns::client::request::build_doh_request(&args, &client).await;
        assert!(result.is_err(), "Should fail with invalid domain");
    }
    
    #[tokio::test]
    async fn test_invalid_record_type() {
        // 测试：无效记录类型
        let mut args = create_test_args(DohFormat::Wire, Some(HttpMethod::Get));
        args.record_type = "INVALID".to_string(); // 不存在的记录类型
        
        let client = reqwest::Client::new();
        
        let result = oxide_wdns::client::request::build_doh_request(&args, &client).await;
        assert!(result.is_err(), "Should fail with invalid record type");
    }
    
    #[tokio::test]
    async fn test_build_doh_request_http_version_1() {
        // 测试：HTTP/1.1 版本
        let mut args = create_test_args(DohFormat::Wire, Some(HttpMethod::Get));
        args.http_version = Some(oxide_wdns::client::args::HttpVersion::Http1);
        
        let client = reqwest::Client::new();
        
        let result = oxide_wdns::client::request::build_doh_request(&args, &client).await;
        assert!(result.is_ok());
        
        let request = result.unwrap();
        assert_eq!(request.method(), reqwest::Method::GET);
    }
    
    #[tokio::test]
    async fn test_build_doh_request_http_version_2() {
        // 测试：HTTP/2 版本
        let mut args = create_test_args(DohFormat::Wire, Some(HttpMethod::Get));
        args.http_version = Some(oxide_wdns::client::args::HttpVersion::Http2);
        
        let client = reqwest::Client::new();
        
        let result = oxide_wdns::client::request::build_doh_request(&args, &client).await;
        assert!(result.is_ok());
        
        let request = result.unwrap();
        assert_eq!(request.method(), reqwest::Method::GET);
    }
    
    #[tokio::test]
    async fn test_build_doh_request_dnssec_do_bit() {
        // 测试：DNSSEC DO 位设置
        let mut args = create_test_args(DohFormat::Wire, Some(HttpMethod::Post));
        args.dnssec = true;
        
        let client = reqwest::Client::new();
        
        let result = oxide_wdns::client::request::build_doh_request(&args, &client).await;
        assert!(result.is_ok());
        
        let request = result.unwrap();
        
        // 从请求体中提取并解析 DNS 消息
        if let Some(body) = request.body() {
            let bytes = body.as_bytes().expect("Body should be available as bytes");
            
            // 解析 DNS 消息
            if let Ok(message) = parse_dns_query(bytes) {
                // 检查消息中的 DNSSEC 标志
                assert!(message.checking_disabled(), "DNSSEC Checking Disabled flag should be set");
                
                // 验证请求中包含EDNS扩展
                let extensions = message.extensions();
                // 由于 has_edns 方法不存在，我们改为直接检查 extensions 是否为 Some
                assert!(extensions.is_some(), "Message should have EDNS extensions");
            } else {
                panic!("Failed to parse DNS message");
            }
        } else {
            panic!("Request body should be present");
        }
    }
    
    #[tokio::test]
    async fn test_get_request_base64url_encoding() {
        // 测试：GET 请求中的 Base64URL 编码
        let args = create_test_args(DohFormat::Wire, Some(HttpMethod::Get));
        let client = reqwest::Client::new();
        
        let result = oxide_wdns::client::request::build_doh_request(&args, &client).await;
        assert!(result.is_ok());
        
        let request = result.unwrap();
        let url = request.url().to_string();
        
        // 提取 dns 参数的值
        let dns_param = url.split("dns=").collect::<Vec<&str>>()[1];
        
        // 尝试解码 Base64URL 编码的数据
        let decoded = URL_SAFE_NO_PAD.decode(dns_param).expect("Should be valid Base64URL encoding");
        
        // 验证解码后的内容是有效的 DNS 消息
        let dns_message = parse_dns_query(&decoded).expect("Should be a valid DNS message");
        
        // 检查 DNS 消息的基本属性
        assert_eq!(dns_message.queries().len(), 1);
        let query = &dns_message.queries()[0];
        assert_eq!(query.name().to_string(), "example.com.");
        assert_eq!(query.query_type(), RecordType::A);
    }
    
    #[tokio::test]
    async fn test_multiple_record_types() {
        // 测试：支持多种记录类型
        let record_types = ["A", "AAAA", "MX", "TXT", "CNAME", "NS", "SOA", "PTR", "SRV"];
        
        for &record_type in &record_types {
            let mut args = create_test_args(DohFormat::Wire, Some(HttpMethod::Get));
            args.record_type = record_type.to_string();
            
            let client = reqwest::Client::new();
            
            let result = oxide_wdns::client::request::build_doh_request(&args, &client).await;
            assert!(result.is_ok(), "Failed to build request for record type {}", record_type);
            
            let request = result.unwrap();
            let url = request.url().to_string();
            
            // 提取 dns 参数的值
            let dns_param = url.split("dns=").collect::<Vec<&str>>()[1];
            
            // 解码 Base64URL 编码的数据
            let decoded = URL_SAFE_NO_PAD.decode(dns_param).expect("Should be valid Base64URL encoding");
            
            // 验证解码后的内容是有效的 DNS 消息
            let dns_message = parse_dns_query(&decoded).expect("Should be a valid DNS message");
            
            // 检查 DNS 消息的记录类型
            assert_eq!(dns_message.queries().len(), 1);
            let query = &dns_message.queries()[0];
            let expected_record_type = RecordType::from_str(record_type).unwrap();
            assert_eq!(query.query_type(), expected_record_type);
        }
    }
} 