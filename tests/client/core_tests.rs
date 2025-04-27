// tests/client/core_tests.rs

#[cfg(test)]
mod tests {
    use oxide_wdns::client::args::{CliArgs, DohFormat, HttpMethod};
    use oxide_wdns::client::core::{ValidationCondition, run_query};
    use oxide_wdns::client::error::ClientError;
    use oxide_wdns::common::consts::{CONTENT_TYPE_DNS_JSON, CONTENT_TYPE_DNS_MESSAGE};
    use std::str::FromStr;
    use trust_dns_proto::op::{Message, MessageType, OpCode, ResponseCode};
    use trust_dns_proto::rr::{Name, Record, RecordType, RData, DNSClass};
    use trust_dns_proto::rr::rdata::A;
    use trust_dns_proto::serialize::binary::{BinEncodable, BinEncoder};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    use wiremock::matchers::method;
    use tracing::info;
    

    #[test]
    fn test_validation_condition_from_str() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_validation_condition_from_str");

        // 响应码
        info!("Testing ResponseCode validation condition parsing...");
        let condition = ValidationCondition::from_str("rcode=NOERROR").unwrap();
        assert!(matches!(condition, ValidationCondition::ResponseCode(ResponseCode::NoError)));
        info!("ResponseCode validation condition parsed successfully");
        
        // IP 地址
        info!("Testing ContainsIP validation condition parsing...");
        let condition = ValidationCondition::from_str("has-ip=1.2.3.4").unwrap();
        assert!(matches!(condition, ValidationCondition::ContainsIP(ip) if ip == "1.2.3.4"));
        info!("ContainsIP validation condition parsed successfully");
        
        // TTL
        info!("Testing MinTTL validation condition parsing...");
        let condition = ValidationCondition::from_str("min-ttl=300").unwrap();
        assert!(matches!(condition, ValidationCondition::MinTTL(ttl) if ttl == 300));
        info!("MinTTL validation condition parsed successfully");
        
        // 回答记录数
        info!("Testing MinAnswers validation condition parsing...");
        let condition = ValidationCondition::from_str("min-answers=2").unwrap();
        assert!(matches!(condition, ValidationCondition::MinAnswers(count) if count == 2));
        info!("MinAnswers validation condition parsed successfully");
        
        // 记录类型
        info!("Testing HasRecordType validation condition parsing...");
        let condition = ValidationCondition::from_str("has-type=A").unwrap();
        assert!(matches!(condition, ValidationCondition::HasRecordType(rt) if rt == RecordType::A));
        info!("HasRecordType validation condition parsed successfully");
        
        // 包含文本
        info!("Testing ContainsText validation condition parsing...");
        let condition = ValidationCondition::from_str("contains=example").unwrap();
        assert!(matches!(condition, ValidationCondition::ContainsText(text) if text == "example"));
        info!("ContainsText validation condition parsed successfully");
        
        // DNSSEC 验证
        info!("Testing DnssecValidated validation condition parsing...");
        let condition = ValidationCondition::from_str("dnssec-validated").unwrap();
        assert!(matches!(condition, ValidationCondition::DnssecValidated));
        info!("DnssecValidated validation condition parsed successfully");
        
        // 无效条件
        info!("Testing invalid validation condition parsing...");
        let condition = ValidationCondition::from_str("invalid=condition");
        assert!(condition.is_err());
        info!("Invalid validation condition correctly rejected");
        
        info!("Test completed: test_validation_condition_from_str");
    }

    // 辅助函数 - 创建 DNS 响应消息
    fn create_dns_response() -> Vec<u8> {
        let mut message = Message::new();
        message.set_id(1234);
        message.set_message_type(MessageType::Response);
        message.set_op_code(OpCode::Query);
        message.set_response_code(ResponseCode::NoError);
        message.set_authoritative(false);
        message.set_recursion_desired(true);
        message.set_recursion_available(true);
        
        // 添加查询部分
        let name = Name::from_ascii("example.com").unwrap();
        let mut query = trust_dns_proto::op::Query::new();
        query.set_name(name.clone());
        query.set_query_type(RecordType::A);
        query.set_query_class(DNSClass::IN);
        message.add_query(query);
        
        // 添加应答部分
        let mut record = Record::new();
        record.set_name(name);
        record.set_ttl(3600);
        record.set_record_type(RecordType::A);
        record.set_dns_class(DNSClass::IN);
        record.set_data(Some(RData::A(A(std::net::Ipv4Addr::new(93, 184, 216, 34)))));
        message.add_answer(record);
        
        // 编码为二进制
        let mut buffer = Vec::with_capacity(512);
        let mut encoder = BinEncoder::new(&mut buffer);
        message.emit(&mut encoder).unwrap();
        
        buffer
    }

    #[tokio::test]
    async fn test_run_query_wireformat_success() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_run_query_wireformat_success");

        // 创建一个 MockServer 来模拟 DoH 服务器
        info!("Starting mock DNS-over-HTTPS server...");
        let mock_server = MockServer::start().await;
        info!(server_uri = %mock_server.uri(), "Mock server started successfully");
        
        // 创建二进制 DNS 响应
        info!("Creating DNS response message in wire format...");
        let dns_response = create_dns_response();
        info!(response_size = dns_response.len(), "DNS response message created");
        
        // 设置模拟响应 - Wire 格式 GET 请求，使用更通用的路径匹配
        info!("Setting up mock response handler for wire format...");
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200)
                .insert_header("content-type", CONTENT_TYPE_DNS_MESSAGE)
                .set_body_bytes(dns_response.clone()))
            .mount(&mock_server)
            .await;
        info!("Mock response handler configured");
        
        // 创建参数
        info!("Creating CLI arguments for wire format query...");
        let args = CliArgs {
            server_url: mock_server.uri(), // 直接使用根URL，不添加路径
            domain: "example.com".to_string(),
            record_type: "A".to_string(),
            format: DohFormat::Wire,
            method: Some(HttpMethod::Get),
            http_version: None,
            dnssec: false,
            payload: None,
            validate: None,
            insecure: true, // 允许自签名证书
            verbose: 0,
            no_color: true,
        };
        info!(?args.domain, ?args.record_type, ?args.format, ?args.method, "CLI arguments created");
        
        // 执行查询
        info!("Executing DNS query...");
        let result = run_query(args).await;
        
        // 由于使用了MockServer，如果连接有问题，可能会报其他错误
        // 仅检查是否成功，不过多断言
        if let Err(ref e) = result {
            info!(error = ?e, "Query failed");
            info!("Test failed, error: {:?}", e);
        } else {
            info!("Query successful");
        }
        assert!(result.is_ok());
        info!("Test completed: test_run_query_wireformat_success");
    }
    
    #[tokio::test]
    async fn test_run_query_json_success() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_run_query_json_success");

        // 创建一个 MockServer 来模拟 DoH 服务器
        info!("Starting mock DNS-over-HTTPS server...");
        let mock_server = MockServer::start().await;
        info!(server_uri = %mock_server.uri(), "Mock server started successfully");
        
        // 创建 JSON 响应
        info!("Creating JSON response for DNS query...");
        let json_response = r#"{
            "Status": 0,
            "TC": false,
            "RD": true,
            "RA": true,
            "AD": false,
            "CD": false,
            "Question": [
                {
                    "name": "example.com",
                    "type": 1
                }
            ],
            "Answer": [
                {
                    "name": "example.com",
                    "type": 1,
                    "TTL": 3600,
                    "data": "93.184.216.34"
                }
            ]
        }"#;
        info!("JSON response created");
        
        // 设置模拟响应 - JSON 格式 GET 请求
        info!("Setting up mock response handler for JSON format...");
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200)
                .insert_header("content-type", CONTENT_TYPE_DNS_JSON)
                .set_body_string(json_response))
            .mount(&mock_server)
            .await;
        info!("Mock response handler configured");
        
        // 创建参数
        info!("Creating CLI arguments for JSON format query...");
        let args = CliArgs {
            server_url: mock_server.uri(), // 直接使用根URL，不添加路径
            domain: "example.com".to_string(),
            record_type: "A".to_string(),
            format: DohFormat::Json,
            method: Some(HttpMethod::Get),
            http_version: None,
            dnssec: false,
            payload: None,
            validate: None,
            insecure: true, // 允许自签名证书
            verbose: 0,
            no_color: true,
        };
        info!(?args.domain, ?args.record_type, ?args.format, ?args.method, "CLI arguments created");
        
        // 执行查询
        info!("Executing DNS query using JSON format...");
        let result = run_query(args).await;
        
        // 由于使用了MockServer，如果连接有问题，可能会报其他错误
        // 仅检查是否成功，不过多断言
        if let Err(ref e) = result {
            info!(error = ?e, "JSON query failed");
            info!("JSON test failed, error: {:?}", e);
        } else {
            info!("JSON query successful");
        }
        assert!(result.is_ok());
        info!("Test completed: test_run_query_json_success");
    }
    
    #[tokio::test]
    async fn test_run_query_with_validation_success() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_run_query_with_validation_success");

        // 创建一个 MockServer 来模拟 DoH 服务器
        info!("Starting mock DNS-over-HTTPS server...");
        let mock_server = MockServer::start().await;
        info!(server_uri = %mock_server.uri(), "Mock server started successfully");
        
        // 创建二进制 DNS 响应
        info!("Creating DNS response message...");
        let dns_response = create_dns_response();
        info!(response_size = dns_response.len(), "DNS response message created");
        
        // 设置模拟响应，使用更通用的路径匹配
        info!("Setting up mock response handler...");
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200)
                .insert_header("content-type", CONTENT_TYPE_DNS_MESSAGE)
                .set_body_bytes(dns_response.clone()))
            .mount(&mock_server)
            .await;
        info!("Mock response handler configured");
        
        // 创建参数，带有验证条件
        info!("Creating CLI arguments with validation conditions...");
        let args = CliArgs {
            server_url: mock_server.uri(), // 直接使用根URL，不添加路径
            domain: "example.com".to_string(),
            record_type: "A".to_string(),
            format: DohFormat::Wire,
            method: Some(HttpMethod::Get),
            http_version: None,
            dnssec: false,
            payload: None,
            validate: Some("rcode=NOERROR,min-answers=1".to_string()), // 验证条件
            insecure: true, // 允许自签名证书
            verbose: 0,
            no_color: true,
        };
        info!(?args.domain, ?args.record_type, ?args.validate, "CLI arguments with validation created");
        
        // 执行查询
        info!("Executing DNS query with validation...");
        let result = run_query(args).await;
        
        // 由于使用了MockServer，如果连接有问题，可能会报其他错误
        // 仅检查是否成功，不过多断言
        if let Err(ref e) = result {
            info!(error = ?e, "Validation query failed");
            info!("Validation test failed, error: {:?}", e);
        } else {
            info!("Validation query successful");
        }
        assert!(result.is_ok());
        info!("Test completed: test_run_query_with_validation_success");
    }
    
    #[tokio::test]
    async fn test_run_query_with_validation_failure() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_run_query_with_validation_failure");

        // 创建一个 MockServer 来模拟 DoH 服务器
        info!("Starting mock DNS-over-HTTPS server...");
        let mock_server = MockServer::start().await;
        info!(server_uri = %mock_server.uri(), "Mock server started successfully");
        
        // 创建 NXDOMAIN 响应
        info!("Creating NXDOMAIN DNS response message...");
        let mut message = Message::new();
        message.set_id(1234);
        message.set_message_type(MessageType::Response);
        message.set_op_code(OpCode::Query);
        message.set_response_code(ResponseCode::NXDomain); // 设置 NXDOMAIN
        message.set_recursion_desired(true);
        message.set_recursion_available(true);
        
        // 添加查询部分
        let name = Name::from_ascii("nonexistent.example.com").unwrap();
        let mut query = trust_dns_proto::op::Query::new();
        query.set_name(name);
        query.set_query_type(RecordType::A);
        query.set_query_class(DNSClass::IN);
        message.add_query(query);
        
        // 没有添加回答部分，因为这是一个 NXDOMAIN 响应
        
        // 编码为二进制
        let mut buffer = Vec::with_capacity(512);
        let mut encoder = BinEncoder::new(&mut buffer);
        message.emit(&mut encoder).unwrap();
        
        let dns_response = buffer;
        info!(response_size = dns_response.len(), "NXDOMAIN response message created");
        
        // 设置模拟响应
        info!("Setting up mock response handler for NXDOMAIN response...");
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200)
                .insert_header("content-type", CONTENT_TYPE_DNS_MESSAGE)
                .set_body_bytes(dns_response))
            .mount(&mock_server)
            .await;
        info!("Mock response handler configured");
        
        // 创建参数，带有验证条件，要求 NOERROR 和至少一个回答记录
        info!("Creating CLI arguments with validation conditions expecting success...");
        let args = CliArgs {
            server_url: mock_server.uri(),
            domain: "nonexistent.example.com".to_string(),
            record_type: "A".to_string(),
            format: DohFormat::Wire,
            method: Some(HttpMethod::Get),
            http_version: None,
            dnssec: false,
            payload: None,
            validate: Some("rcode=NOERROR,min-answers=1".to_string()), // 期望成功的验证条件
            insecure: true,
            verbose: 0,
            no_color: true,
        };
        info!(?args.domain, ?args.validate, "CLI arguments created with validation expecting success");
        
        // 执行查询，因为服务器返回 NXDOMAIN 而不是 NOERROR，所以验证应该失败
        info!("Executing DNS query with validation that should fail...");
        let result = run_query(args).await;
        
        // 检查结果，应该是验证失败的错误
        info!(result_is_err = result.is_err(), "Query with validation completed");
        assert!(result.is_err());
        
        if let Err(e) = result {
            info!(error = ?e, "Validation failed as expected");
            match e {
                ClientError::ValidationFailed(_) => info!("Correct error type: ValidationFailed"),
                _ => {
                    info!(error_type = ?e, "Unexpected error type");
                    panic!("Expected ValidationFailed error, got {:?}", e);
                }
            }
        }
        info!("Test completed: test_run_query_with_validation_failure");
    }
    
    #[tokio::test]
    async fn test_run_query_server_error() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_run_query_server_error");

        // 创建一个 MockServer 来模拟 DoH 服务器
        info!("Starting mock DNS-over-HTTPS server...");
        let mock_server = MockServer::start().await;
        info!(server_uri = %mock_server.uri(), "Mock server started successfully");
        
        // 设置模拟响应 - 返回 500 Internal Server Error
        info!("Setting up mock response handler for 500 Internal Server Error...");
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500)
                .set_body_string("Internal Server Error"))
            .mount(&mock_server)
            .await;
        info!("Mock response handler configured for server error");
        
        // 创建参数
        info!("Creating CLI arguments...");
        let args = CliArgs {
            server_url: mock_server.uri(),
            domain: "example.com".to_string(),
            record_type: "A".to_string(),
            format: DohFormat::Wire,
            method: Some(HttpMethod::Get),
            http_version: None,
            dnssec: false,
            payload: None,
            validate: None,
            insecure: true,
            verbose: 0,
            no_color: true,
        };
        info!(?args.domain, ?args.record_type, "CLI arguments created");
        
        // 执行查询
        info!("Executing DNS query expecting server error...");
        let result = run_query(args).await;
        
        // 检查结果，应该是 HTTP 错误
        info!(result_is_err = result.is_err(), "Query completed with expected error");
        assert!(result.is_err());
        
        if let Err(e) = result {
            info!(error = ?e, "Server error detected as expected");
            match e {
                ClientError::HttpError(status, _) => {
                    info!(status_code = status, "Correct error type: HttpError");
                    assert_eq!(status, 500);
                },
                _ => {
                    info!(error_type = ?e, "Unexpected error type");
                    panic!("Expected HttpError, got {:?}", e);
                }
            }
        }
        info!("Test completed: test_run_query_server_error");
    }
} 