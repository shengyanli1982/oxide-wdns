use std::sync::Arc;
use std::time::Duration;
use axum::{
    body::Body,
    http::{header, Request, StatusCode, Method},
    routing::get,
    Router, extract::ConnectInfo,
};
use tower::Service;
use std::net::{IpAddr, SocketAddr, Ipv4Addr};

use oxide_wdns::server::config::{ServerConfig, CacheConfig, RateLimitConfig};
use oxide_wdns::server::security::{RateLimitManager, RateLimitLayer, extract_client_ip};

// 创建一个简单的响应内容为"OK"的Handler
async fn ok_handler() -> &'static str {
    "OK"
}

// 创建测试用的应用，带有速率限制
fn create_test_app_with_rate_limit(config: RateLimitConfig) -> Router {
    // 创建一个简单的路由
    let app = Router::new()
        .route("/", get(ok_handler));
    
    // 添加速率限制层
    if config.enabled {
        let rate_limit_layer = RateLimitLayer::new(config);
        app.layer(rate_limit_layer)
    } else {
        app
    }
}

// 工具函数：创建带有客户端IP地址的测试请求
fn create_request_with_ip(ip: IpAddr) -> Request<Body> {
    let mut req = Request::builder()
        .uri("/")
        .method(Method::GET)
        .body(Body::empty())
        .unwrap();
    
    // 添加连接信息到请求扩展
    let socket_addr = SocketAddr::new(ip, 12345);
    req.extensions_mut().insert(ConnectInfo(socket_addr));
    
    req
}

#[test]
fn test_extract_client_ip() {
    // 测试从连接信息中提取IP
    let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    let socket_addr = SocketAddr::new(ip, 12345);
    let mut headers = header::HeaderMap::new();
    
    let binding = ConnectInfo(socket_addr);
    let conn_info = Some(&binding);
    let extracted_ip = extract_client_ip::<Body>(&headers, conn_info);
    
    assert_eq!(extracted_ip, Some(ip));
    
    // 测试从代理头中提取IP
    headers.insert("X-Forwarded-For", "10.0.0.1".parse().unwrap());
    let extracted_ip = extract_client_ip::<Body>(&headers, None);
    
    assert_eq!(extracted_ip, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    
    // 测试多个IP的情况
    headers.insert("X-Forwarded-For", "10.0.0.2, 10.0.0.3".parse().unwrap());
    let extracted_ip = extract_client_ip::<Body>(&headers, None);
    
    assert_eq!(extracted_ip, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));
}

#[test]
fn test_rate_limit_manager() {
    // 创建配置
    let config = RateLimitConfig {
        enabled: true,
        per_ip_rate: 3,      // 每个IP每秒最多3次请求
        per_ip_concurrent: 2, // 每个IP最多2个并发请求
    };
    
    // 创建限速管理器
    let manager = RateLimitManager::new(config);
    let client_ip = "192.168.1.1";
    
    // 测试速率限制 - 初始应该通过
    assert!(manager.check_rate_limit(client_ip));
    assert!(manager.check_rate_limit(client_ip));
    assert!(manager.check_rate_limit(client_ip));
    
    // 超过速率应该被限制
    assert!(!manager.check_rate_limit(client_ip));
    
    // 测试并发限制
    assert!(manager.try_acquire_concurrency(client_ip));
    assert!(manager.try_acquire_concurrency(client_ip));
    
    // 超过并发限制应该被拒绝
    assert!(!manager.try_acquire_concurrency(client_ip));
    
    // 释放一个并发请求后应该可以再次获取
    manager.release_concurrency(client_ip);
    assert!(manager.try_acquire_concurrency(client_ip));
    
    // 释放所有并发请求
    manager.release_concurrency(client_ip);
    manager.release_concurrency(client_ip);
}

#[tokio::test]
async fn test_rate_limit_layer() {
    // 创建限速配置
    let config = RateLimitConfig {
        enabled: true,
        per_ip_rate: 2,      // 每个IP每秒最多2次请求
        per_ip_concurrent: 2, // 每个IP最多2个并发请求
    };
    
    // 创建测试应用
    let app = create_test_app_with_rate_limit(config);
    let mut app = app.into_service();
    
    // 创建测试请求
    let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    let req1 = create_request_with_ip(ip);
    let req2 = create_request_with_ip(ip);
    let req3 = create_request_with_ip(ip);
    
    // 发送前两个请求 - 应该成功
    let response1 = app.call(req1).await.unwrap();
    assert_eq!(response1.status(), StatusCode::OK);
    
    let response2 = app.call(req2).await.unwrap();
    assert_eq!(response2.status(), StatusCode::OK);
    
    // 发送第三个请求 - 应该被限制
    let response3 = app.call(req3).await.unwrap();
    assert_eq!(response3.status(), StatusCode::TOO_MANY_REQUESTS);
    
    // 使用不同的IP应该能够通过
    let different_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
    let req4 = create_request_with_ip(different_ip);
    
    let response4 = app.call(req4).await.unwrap();
    assert_eq!(response4.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_rate_limit_disabled() {
    // 创建禁用限速的配置
    let config = RateLimitConfig {
        enabled: false,
        per_ip_rate: 1,
        per_ip_concurrent: 1,
    };
    
    // 创建测试应用
    let app = create_test_app_with_rate_limit(config);
    let mut app = app.into_service();
    
    // 创建测试请求
    let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    
    // 连续发送多个请求 - 当限速禁用时，所有请求都应该成功
    for _ in 0..5 {
        let req = create_request_with_ip(ip);
        let response = app.call(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}

#[tokio::test]
async fn test_concurrent_requests_limit() {
    // 创建有较慢处理时间的处理函数
    async fn slow_handler() -> &'static str {
        tokio::time::sleep(Duration::from_millis(200)).await;
        "OK"
    }
    
    // 创建测试应用
    let config = RateLimitConfig {
        enabled: true,
        per_ip_rate: 10,     // 设置较高的请求速率
        per_ip_concurrent: 2, // 每个IP最多2个并发请求
    };
    
    let app = Router::new()
        .route("/slow", get(slow_handler))
        .layer(RateLimitLayer::new(config));
    
    let app = app.into_service();
    let app = Arc::new(tower::util::Stacked::new(app));
    
    // 测试并发请求限制
    let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    
    // 创建一组并发请求
    let mut handles = vec![];
    for i in 0..3 {
        let app_clone = app.clone();
        let req = create_request_with_ip(ip);
        
        handles.push(tokio::spawn(async move {
            let mut app = app_clone.clone();
            let response = app.call(req).await.unwrap();
            (i, response.status())
        }));
    }
    
    // 等待所有请求完成
    let mut results = vec![];
    for handle in handles {
        results.push(handle.await.unwrap());
    }
    
    // 排序结果
    results.sort_by_key(|(i, _)| *i);
    
    // 前两个请求应该成功，第三个应该被限制
    assert_eq!(results[0].1, StatusCode::OK);
    assert_eq!(results[1].1, StatusCode::OK);
    assert_eq!(results[2].1, StatusCode::TOO_MANY_REQUESTS);
} 