use axum::{
    body::Body,
    http::{header, Request, StatusCode, Method},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as BASE64_ENGINE};
use std::sync::Arc;
use tower::ServiceExt;
use trust_dns_proto::op::{Message, MessageType, OpCode};
use trust_dns_proto::rr::{Name, RecordType};
use axum::body::to_bytes;

use oxide_wdns::common::consts::{CONTENT_TYPE_DNS_MESSAGE, CONTENT_TYPE_DNS_JSON};
use oxide_wdns::server::cache::DnsCache;
use oxide_wdns::server::config::{ServerConfig, CacheConfig, RateLimitConfig, UpstreamConfig, ResolverConfig, ResolverProtocol};
use oxide_wdns::server::doh_handler::{doh_routes, ServerState};
use oxide_wdns::server::metrics::DnsMetrics;
use oxide_wdns::server::upstream::UpstreamManager;

// 工具函数：创建测试用的应用配置和状态
async fn create_test_state() -> ServerState {
    // 创建基本配置
    let config = ServerConfig {
        listen_addr: "127.0.0.1:3053".parse().unwrap(),
        upstream: UpstreamConfig {
            resolvers: vec![
                ResolverConfig {
                    address: "8.8.8.8:53".to_string(),
                    protocol: ResolverProtocol::Udp,
                }
            ],
            enable_dnssec: false,
            query_timeout: 30,
        },
        cache: CacheConfig::default(),
        rate_limit: RateLimitConfig::default(),
    };
    
    // 创建缓存
    let cache = Arc::new(DnsCache::new(CacheConfig::default()));
    
    // 创建上游管理器 - 使用默认配置创建
    let upstream = Arc::new(UpstreamManager::new(&config).await.unwrap());
    
    // 创建指标收集器
    let metrics = Arc::new(DnsMetrics::new());
    
    // 创建服务器状态
    ServerState {
        config: config.clone(),
        upstream,
        cache,
        metrics,
    }
}

// 工具函数：创建测试用的DNS请求消息
fn create_test_dns_message(domain: &str, record_type: RecordType) -> Message {
    let name = Name::parse(domain, None).unwrap();
    
    let mut message = Message::new();
    message
        .set_id(1234) // 测试固定ID
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(true);
        
    // 添加查询
    let query = trust_dns_proto::op::Query::query(name, record_type);
    message.add_query(query);
    
    message
}

#[tokio::test]
async fn test_json_api_get_request() {
    // 创建测试状态
    let state = create_test_state().await;
    
    // 通过doh_routes创建应用
    let app = doh_routes(state);
    
    // 创建测试请求 - JSON API 格式
    let request = Request::builder()
        .uri("/resolve?name=example.com&type_value=1")
        .method(Method::GET)
        .header(header::ACCEPT, CONTENT_TYPE_DNS_JSON)
        .body(Body::empty())
        .unwrap();
    
    // 使用oneshot发送请求
    let response = app.oneshot(request).await.unwrap();
    
    // 检查响应状态
    assert_eq!(response.status(), StatusCode::OK);
    
    // 检查内容类型
    let content_type = response.headers().get(header::CONTENT_TYPE).unwrap();
    assert_eq!(content_type, CONTENT_TYPE_DNS_JSON);
    
    // 将响应体转换为字节
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    
    // 验证响应中包含JSON格式的数据
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    assert!(body_str.contains("\"question\""));
    assert!(body_str.contains("\"name\":\"example.com\""));
}

#[tokio::test]
async fn test_dns_wire_get_request() {
    // 创建测试状态
    let state = create_test_state().await;
    
    // 通过doh_routes创建应用
    let app = doh_routes(state);
    
    // 创建测试DNS消息
    let message = create_test_dns_message("example.com.", RecordType::A);
    let dns_wire = message.to_vec().unwrap();
    
    // Base64url编码
    let dns_param = BASE64_ENGINE.encode(&dns_wire);
    
    // 创建GET请求 - RFC 8484标准
    let request = Request::builder()
        .uri(format!("/dns-query?dns={}", dns_param))
        .method(Method::GET)
        .header(header::ACCEPT, CONTENT_TYPE_DNS_MESSAGE)
        .body(Body::empty())
        .unwrap();
    
    // 使用oneshot发送请求
    let response = app.oneshot(request).await.unwrap();
    
    // 检查响应状态
    assert_eq!(response.status(), StatusCode::OK);
    
    // 检查内容类型
    let content_type = response.headers().get(header::CONTENT_TYPE).unwrap();
    assert_eq!(content_type, CONTENT_TYPE_DNS_MESSAGE);
    
    // 将响应体转换为字节
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    
    // 验证响应是一个有效的DNS消息
    let response_message = Message::from_vec(&body).expect("应该是有效的DNS消息");
    assert_eq!(response_message.message_type(), MessageType::Response);
    assert_eq!(response_message.id(), message.id()); // ID应该匹配
}

#[tokio::test]
async fn test_dns_wire_post_request() {
    // 创建测试状态
    let state = create_test_state().await;
    
    // 通过doh_routes创建应用
    let app = doh_routes(state);
    
    // 创建测试DNS消息
    let message = create_test_dns_message("example.com.", RecordType::A);
    let dns_wire = message.to_vec().unwrap();
    
    // 创建POST请求 - RFC 8484标准
    let request = Request::builder()
        .uri("/dns-query")
        .method(Method::POST)
        .header(header::CONTENT_TYPE, CONTENT_TYPE_DNS_MESSAGE)
        .header(header::ACCEPT, CONTENT_TYPE_DNS_MESSAGE)
        .body(Body::from(dns_wire))
        .unwrap();
    
    // 使用oneshot发送请求
    let response = app.oneshot(request).await.unwrap();
    
    // 检查响应状态
    assert_eq!(response.status(), StatusCode::OK);
    
    // 检查内容类型
    let content_type = response.headers().get(header::CONTENT_TYPE).unwrap();
    assert_eq!(content_type, CONTENT_TYPE_DNS_MESSAGE);
    
    // 将响应体转换为字节
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    
    // 验证响应是一个有效的DNS消息
    let response_message = Message::from_vec(&body).expect("应该是有效的DNS消息");
    assert_eq!(response_message.message_type(), MessageType::Response);
    assert_eq!(response_message.id(), message.id()); // ID应该匹配
}

#[tokio::test]
async fn test_invalid_json_api_parameters() {
    // 创建测试状态
    let state = create_test_state().await;
    
    // 通过doh_routes创建应用
    let app = doh_routes(state);
    
    // 创建无效的测试请求 - 缺少name参数
    let request = Request::builder()
        .uri("/resolve?type_value=1")
        .method(Method::GET)
        .header(header::ACCEPT, CONTENT_TYPE_DNS_JSON)
        .body(Body::empty())
        .unwrap();
    
    // 使用oneshot发送请求
    let response = app.oneshot(request).await.unwrap();
    
    // 检查响应状态 - 应该是错误
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_invalid_dns_wire_get_request() {
    // 创建测试状态
    let state = create_test_state().await;
    
    // 通过doh_routes创建应用
    let app = doh_routes(state);
    
    // 创建无效的Base64url数据
    let dns_param = "invalid-base64-data";
    
    // 创建GET请求
    let request = Request::builder()
        .uri(format!("/dns-query?dns={}", dns_param))
        .method(Method::GET)
        .header(header::ACCEPT, CONTENT_TYPE_DNS_MESSAGE)
        .body(Body::empty())
        .unwrap();
    
    // 使用oneshot发送请求
    let response = app.oneshot(request).await.unwrap();
    
    // 检查响应状态 - 应该是错误
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_invalid_dns_wire_post_content_type() {
    // 创建测试状态
    let state = create_test_state().await;
    
    // 通过doh_routes创建应用
    let app = doh_routes(state);
    
    // 创建测试DNS消息
    let message = create_test_dns_message("example.com.", RecordType::A);
    let dns_wire = message.to_vec().unwrap();
    
    // 创建使用错误Content-Type的POST请求
    let request = Request::builder()
        .uri("/dns-query")
        .method(Method::POST)
        .header(header::CONTENT_TYPE, "application/json") // 错误的Content-Type
        .header(header::ACCEPT, CONTENT_TYPE_DNS_MESSAGE)
        .body(Body::from(dns_wire))
        .unwrap();
    
    // 使用oneshot发送请求
    let response = app.oneshot(request).await.unwrap();
    
    // 检查响应状态 - 应该是错误
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
} 