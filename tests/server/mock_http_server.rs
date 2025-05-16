// tests/server/common.rs

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType, rdata::A};
use wiremock::{Mock, MockServer, ResponseTemplate, matchers};
use oxide_wdns::common::consts::CONTENT_TYPE_DNS_MESSAGE;

// 创建测试用的DNS请求消息
pub fn create_test_query(domain: &str, record_type: RecordType) -> Message {
    let name = Name::from_ascii(domain).unwrap();
    let mut query = Message::new();
    query.set_id(1234)
         .set_message_type(MessageType::Query)
         .set_op_code(OpCode::Query)
         .add_query(Query::query(name, record_type));
    query
}

// 创建测试响应消息
pub fn create_test_response(query: &Message, ip: Ipv4Addr) -> Message {
    let mut response = Message::new();
    response.set_id(query.id())
            .set_message_type(MessageType::Response)
            .set_op_code(query.op_code())
            .set_recursion_desired(query.recursion_desired())
            .set_recursion_available(true)
            .set_response_code(ResponseCode::NoError);
            
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

// 使用 wiremock 创建模拟 DoH 服务器
pub async fn setup_mock_doh_server(response_ip: Ipv4Addr) -> (MockServer, Arc<Mutex<usize>>) {
    // 创建请求计数器
    let counter = Arc::new(Mutex::new(0));
    let counter_clone = Arc::clone(&counter);
    
    // 启动 MockServer
    let mock_server = MockServer::start().await;
    
    // 创建 POST 请求处理逻辑
    Mock::given(matchers::method("POST"))
        .and(matchers::path("/dns-query"))
        .and(matchers::header("Content-Type", CONTENT_TYPE_DNS_MESSAGE))
        .respond_with(move |request: &wiremock::Request| {
            // 增加请求计数
            {
                let mut count = counter_clone.lock().unwrap();
                *count += 1;
            }
            
            // 解析请求体
            let body = request.body.clone();
            let query_message = match Message::from_vec(&body) {
                Ok(msg) => msg,
                Err(_) => {
                    return ResponseTemplate::new(400)
                        .set_body_string("Invalid DNS message");
                }
            };
            
            // 创建响应
            let response_message = create_test_response(&query_message, response_ip);
            
            // 转换为字节
            let response_bytes = match response_message.to_vec() {
                Ok(bytes) => bytes,
                Err(_) => {
                    return ResponseTemplate::new(500)
                        .set_body_string("Failed to create response");
                }
            };
            
            ResponseTemplate::new(200)
                .insert_header("Content-Type", CONTENT_TYPE_DNS_MESSAGE)
                .set_body_bytes(response_bytes)
        })
        .mount(&mock_server)
        .await;
    
    // 创建 GET 请求处理逻辑
    let counter_clone = Arc::clone(&counter);
    Mock::given(matchers::method("GET"))
        .and(matchers::path("/dns-query"))
        .respond_with(move |request: &wiremock::Request| {
            // 增加请求计数
            {
                let mut count = counter_clone.lock().unwrap();
                *count += 1;
            }
            
            // 从查询参数获取 DNS 查询
            let query_params = request.url.query().unwrap_or("");
            if query_params.is_empty() {
                return ResponseTemplate::new(400)
                    .set_body_string("Missing DNS query parameters");
            }
            
            // 简化处理：直接创建响应
            let query = create_test_query("example.com", RecordType::A);
            let response_message = create_test_response(&query, response_ip);
            
            // 转换为字节
            let response_bytes = match response_message.to_vec() {
                Ok(bytes) => bytes,
                Err(_) => {
                    return ResponseTemplate::new(500)
                        .set_body_string("Failed to create response");
                }
            };
            
            ResponseTemplate::new(200)
                .insert_header("Content-Type", CONTENT_TYPE_DNS_MESSAGE)
                .set_body_bytes(response_bytes)
        })
        .mount(&mock_server)
        .await;
    
    (mock_server, counter)
}

// 找到一个可用的端口号
pub async fn find_free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("Failed to bind to a random port");
    let addr = listener.local_addr().expect("Failed to get local address");
    addr.port()
} 