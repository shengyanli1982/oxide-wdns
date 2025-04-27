// tests/client/response_tests.rs

#[cfg(test)]
mod tests {
    
    use oxide_wdns::client::response::parse_doh_response;
    use oxide_wdns::common::consts::{CONTENT_TYPE_DNS_JSON, CONTENT_TYPE_DNS_MESSAGE};
    use reqwest::StatusCode;
    
    use trust_dns_proto::op::{Message, MessageType, OpCode, ResponseCode};
    use trust_dns_proto::rr::{Name, Record, RecordType, RData, DNSClass};
    use trust_dns_proto::rr::rdata::A;
    use trust_dns_proto::serialize::binary::{BinEncodable, BinEncoder};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    use wiremock::matchers::{method, path};
    
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
    
    // 辅助函数 - 创建 JSON 响应
    fn create_json_response() -> Vec<u8> {
        let json = r#"{
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
        
        json.as_bytes().to_vec()
    }

    #[tokio::test]
    async fn test_parse_doh_response_wireformat() {
        // 创建一个 MockServer 来模拟 DoH 服务器
        let mock_server = MockServer::start().await;
        
        // 创建二进制 DNS 响应
        let dns_response = create_dns_response();
        
        // 设置模拟响应
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(ResponseTemplate::new(200)
                .insert_header("content-type", CONTENT_TYPE_DNS_MESSAGE)
                .set_body_bytes(dns_response.clone()))
            .mount(&mock_server)
            .await;
        
        // 发送请求
        let client = reqwest::Client::new();
        let response = client.get(format!("{}/dns-query", mock_server.uri()))
            .send()
            .await
            .unwrap();
        
        // 解析响应
        let doh_response = parse_doh_response(response).await;
        assert!(doh_response.is_ok());
        
        let doh_response = doh_response.unwrap();
        
        // 验证解析结果
        assert_eq!(doh_response.status, StatusCode::OK);
        assert!(!doh_response.is_json);
        assert_eq!(doh_response.raw_body, dns_response);
        assert_eq!(doh_response.message.response_code(), ResponseCode::NoError);
        assert_eq!(doh_response.message.answers().len(), 1);
        
        // 验证 Answer 记录
        let answer = &doh_response.message.answers()[0];
        assert_eq!(answer.record_type(), RecordType::A);
        match answer.data() {
            Some(RData::A(ip)) => assert_eq!(ip.0, std::net::Ipv4Addr::new(93, 184, 216, 34)),
            _ => panic!("Expected A record"),
        }
    }

    #[tokio::test]
    async fn test_parse_doh_response_json() {
        // 创建一个 MockServer 来模拟 DoH 服务器
        let mock_server = MockServer::start().await;
        
        // 创建 JSON 响应
        let json_response = create_json_response();
        
        // 设置模拟响应
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(ResponseTemplate::new(200)
                .insert_header("content-type", CONTENT_TYPE_DNS_JSON)
                .set_body_bytes(json_response.clone()))
            .mount(&mock_server)
            .await;
        
        // 发送请求
        let client = reqwest::Client::new();
        let response = client.get(format!("{}/dns-query", mock_server.uri()))
            .send()
            .await
            .unwrap();
        
        // 解析响应
        let doh_response = parse_doh_response(response).await;
        assert!(doh_response.is_ok());
        
        let doh_response = doh_response.unwrap();
        
        // 验证解析结果
        assert_eq!(doh_response.status, StatusCode::OK);
        assert!(doh_response.is_json);
        assert_eq!(doh_response.message.response_code(), ResponseCode::NoError);
        assert_eq!(doh_response.message.answers().len(), 1);
        
        // 验证 Answer 记录
        let answer = &doh_response.message.answers()[0];
        assert_eq!(answer.record_type(), RecordType::A);
        match answer.data() {
            Some(RData::A(ip)) => assert_eq!(ip.0, std::net::Ipv4Addr::new(93, 184, 216, 34)),
            _ => panic!("Expected A record"),
        }
        
        // 验证 JSON 响应已解析
        assert!(doh_response.json_response.is_some());
    }

    #[tokio::test]
    async fn test_parse_doh_response_error_status() {
        // 创建一个 MockServer 来模拟 DoH 服务器
        let mock_server = MockServer::start().await;
        
        // 设置模拟响应 - 返回 404 错误
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(ResponseTemplate::new(404)
                .set_body_string("Not Found"))
            .mount(&mock_server)
            .await;
        
        // 发送请求
        let client = reqwest::Client::new();
        let response = client.get(format!("{}/dns-query", mock_server.uri()))
            .send()
            .await
            .unwrap();
        
        // 解析响应应当失败
        let doh_response = parse_doh_response(response).await;
        assert!(doh_response.is_err());
    }

    #[tokio::test]
    async fn test_parse_doh_response_invalid_wireformat() {
        // 创建一个 MockServer 来模拟 DoH 服务器
        let mock_server = MockServer::start().await;
        
        // 设置模拟响应 - 返回无效的 DNS 二进制数据
        let invalid_dns = vec![0, 1, 2, 3]; // 无效的 DNS 消息
        
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(ResponseTemplate::new(200)
                .insert_header("content-type", CONTENT_TYPE_DNS_MESSAGE)
                .set_body_bytes(invalid_dns))
            .mount(&mock_server)
            .await;
        
        // 发送请求
        let client = reqwest::Client::new();
        let response = client.get(format!("{}/dns-query", mock_server.uri()))
            .send()
            .await
            .unwrap();
        
        // 解析响应应当失败
        let doh_response = parse_doh_response(response).await;
        assert!(doh_response.is_err());
    }

    #[tokio::test]
    async fn test_parse_doh_response_invalid_json() {
        // 创建一个 MockServer 来模拟 DoH 服务器
        let mock_server = MockServer::start().await;
        
        // 设置模拟响应 - 返回无效的 JSON 数据
        let invalid_json = "{invalid json}"; // 无效的 JSON 格式
        
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(ResponseTemplate::new(200)
                .insert_header("content-type", CONTENT_TYPE_DNS_JSON)
                .set_body_string(invalid_json))
            .mount(&mock_server)
            .await;
        
        // 发送请求
        let client = reqwest::Client::new();
        let response = client.get(format!("{}/dns-query", mock_server.uri()))
            .send()
            .await
            .unwrap();
        
        // 解析响应应当失败
        let doh_response = parse_doh_response(response).await;
        assert!(doh_response.is_err());
    }

    #[tokio::test]
    async fn test_parse_doh_response_unknown_content_type() {
        // 创建一个 MockServer 来模拟 DoH 服务器
        let mock_server = MockServer::start().await;
        
        // 设置模拟响应 - 返回未知内容类型
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .respond_with(ResponseTemplate::new(200)
                .insert_header("content-type", "text/plain")
                .set_body_string("This is not a DNS response"))
            .mount(&mock_server)
            .await;
        
        // 发送请求
        let client = reqwest::Client::new();
        let response = client.get(format!("{}/dns-query", mock_server.uri()))
            .send()
            .await
            .unwrap();
        
        // 解析响应应当失败
        let doh_response = parse_doh_response(response).await;
        assert!(doh_response.is_err());
    }
} 