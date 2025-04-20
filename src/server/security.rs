use std::net::IpAddr;
use std::sync::Arc;
use axum::{
    http::{Request, StatusCode, HeaderMap},
    response::Response,
    extract::ConnectInfo,
    middleware::Next,
    body::Body,
};
use tower::Layer;
use governor::{
    Quota, RateLimiter, 
    clock::DefaultClock,
};
use std::num::NonZeroU32;
use tracing::{warn, debug, info};
use dashmap::DashMap;

use crate::server::config::RateLimitConfig;
use crate::common::consts::IP_HEADER_NAMES;

/// 从请求头或连接信息中提取客户端 IP 地址
pub fn extract_client_ip<B>(
    headers: &HeaderMap,
    connect_info: Option<&ConnectInfo<std::net::SocketAddr>>,
) -> Option<IpAddr> {
    // 1. 尝试从代理头中提取 IP
    for header_name in IP_HEADER_NAMES.iter() {
        if let Some(header_value) = headers.get(*header_name) {
            if let Ok(header_str) = header_value.to_str() {
                // 获取第一个 IP（如果有多个 IP 以逗号分隔）
                let first_ip = header_str.split(',').next().unwrap_or("").trim();
                if !first_ip.is_empty() {
                    if let Ok(ip) = first_ip.parse::<IpAddr>() {
                        debug!("Client IP extracted from header {}: {}", header_name, ip);
                        return Some(ip);
                    }
                }
            }
        }
    }

    // 2. 从连接信息中提取 IP
    if let Some(connect_info) = connect_info {
        let ip = connect_info.0.ip();
        debug!("Client IP extracted from connection info: {}", ip);
        return Some(ip);
    }

    // 无法提取 IP
    None
}

/// 全局限速管理器
#[derive(Debug, Clone)]
pub struct RateLimitManager {
    /// 请求速率限制器（每秒请求数）
    requests_limiter: Arc<RateLimiter<String, governor::state::keyed::DashMapStateStore<String>, DefaultClock>>,
    /// 并发请求计数器 (使用 DashMap 替代 Mutex<HashMap>)
    concurrency_limiter: Arc<DashMap<String, usize>>,
    /// 配置
    config: RateLimitConfig,
}

impl RateLimitManager {
    /// 创建新的限速管理器
    pub fn new(config: RateLimitConfig) -> Self {
        // 确保配置值非零
        let per_ip_rate = NonZeroU32::new(config.per_ip_rate).unwrap_or(NonZeroU32::new(100).unwrap());
        
        // 创建速率限制器
        let quota = Quota::per_second(per_ip_rate);
        
        // 使用 dashmap 作为 keyed 存储
        let limiter = RateLimiter::dashmap(quota);
        
        Self {
            requests_limiter: Arc::new(limiter),
            concurrency_limiter: Arc::new(DashMap::new()),
            config,
        }
    }
    
    /// 检查请求是否超过速率限制
    pub fn check_rate_limit(&self, client_ip: &str) -> bool {
        // 如果速率限制被禁用，总是允许请求
        if !self.config.enabled {
            return true;
        }
        
        // 转换为 String 类型以匹配 check_key 的参数类型
        let ip_string = client_ip.to_string();
        self.requests_limiter.check_key(&ip_string).is_ok()
    }
    
    /// 尝试增加并发请求计数，如果超过限制则返回 false
    pub fn try_acquire_concurrency(&self, client_ip: &str) -> bool {
        // 如果速率限制被禁用，总是允许请求
        if !self.config.enabled {
            return true;
        }
        
        // 原子地增加并发计数
        let result = self.concurrency_limiter.entry(client_ip.to_string())
            .and_modify(|count| {
                if *count < self.config.per_ip_concurrent as usize {
                    *count += 1;
                }
            })
            .or_insert(1);
            
        // 检查计数是否在限制内
        *result <= self.config.per_ip_concurrent as usize
    }
    
    /// 减少并发请求计数
    pub fn release_concurrency(&self, client_ip: &str) {
        // 如果速率限制被禁用，不需要处理
        if !self.config.enabled {
            return;
        }
        
        // 原子地减少并发计数
        self.concurrency_limiter.entry(client_ip.to_string())
            .and_modify(|count| {
                if *count > 0 {
                    *count -= 1;
                }
                
                // 如果计数为0，移除该项（在闭包外处理）
            });
            
        // 尝试删除计数为0的条目
        self.concurrency_limiter.remove_if(client_ip, |_, count| *count == 0);
    }
    
    /// 清理过期的速率限制条目
    pub fn clean_expired_entries(&self) {
        // 移除15分钟内没有请求的IP (将在定期任务中调用)
        let stale_ips: Vec<String> = self.concurrency_limiter.iter()
            .filter(|entry| *entry.value() == 0)
            .map(|entry| entry.key().clone())
            .collect();
            
        for ip in stale_ips {
            self.concurrency_limiter.remove(&ip);
            debug!(client_ip = %ip, "Removed stale rate limit entry");
        }
    }
}

/// 速率限制中间件
pub async fn rate_limit_middleware<B>(
    req: Request<B>,
    next: Next,
    manager: Arc<RateLimitManager>,
) -> Result<Response, StatusCode> 
where
    B: Send + 'static,
{
    // 提取客户端 IP
    let connect_info = req.extensions().get::<ConnectInfo<std::net::SocketAddr>>();
    let client_ip = match extract_client_ip::<B>(req.headers(), connect_info) {
        Some(ip) => ip.to_string(),
        None => {
            warn!("Unable to extract client IP from request");
            return Err(StatusCode::BAD_REQUEST);
        }
    };
    
    // 检查速率限制
    if !manager.check_rate_limit(&client_ip) {
        warn!(client_ip = %client_ip, "Rate limit exceeded");
        // 记录速率限制指标
        crate::server::metrics::METRICS.with(|m| m.record_rate_limit(&client_ip));
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    
    // 检查并发请求限制
    if !manager.try_acquire_concurrency(&client_ip) {
        warn!(client_ip = %client_ip, "Concurrent requests limit exceeded");
        // 记录速率限制指标
        crate::server::metrics::METRICS.with(|m| m.record_rate_limit(&client_ip));
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    
    // 请求计数+1并继续处理
    debug!(client_ip = %client_ip, "Request passed rate limit checks");
    
    // 这里需要将请求转换为 Body 类型
    let (parts, _) = req.into_parts();
    let req = Request::from_parts(parts, Body::empty());
    
    // 创建未来 (future) 来处理请求并在完成时释放并发计数
    let response = next.run(req).await;
    
    // 释放并发请求计数
    manager.release_concurrency(&client_ip);
    
    Ok(response)
}

/// 创建速率限制层
#[derive(Clone)]
pub struct RateLimitLayer {
    manager: Arc<RateLimitManager>,
}

impl RateLimitLayer {
    /// 创建新的速率限制层
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            manager: Arc::new(RateLimitManager::new(config)),
        }
    }
    
    /// 获取速率限制管理器的引用
    pub fn get_manager(&self) -> Arc<RateLimitManager> {
        self.manager.clone()
    }
}

impl<S> Layer<S> for RateLimitLayer {
    type Service = RateLimitService<S>;

    fn layer(&self, service: S) -> Self::Service {
        RateLimitService {
            inner: service,
            manager: self.manager.clone(),
        }
    }
}

/// 速率限制服务
#[derive(Clone)]
pub struct RateLimitService<S> {
    inner: S,
    manager: Arc<RateLimitManager>,
}

impl<S, ReqBody, ResBody> tower::Service<Request<ReqBody>> for RateLimitService<S>
where
    S: tower::Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
    ResBody: From<Body>, // 添加约束，以便 Body 可以转换为 ResBody
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let manager = self.manager.clone();
        let mut inner = self.inner.clone();
        
        let connect_info = req.extensions().get::<ConnectInfo<std::net::SocketAddr>>().cloned();
        let headers = req.headers().clone();
        
        Box::pin(async move {
            // 提取客户端 IP
            let client_ip = match extract_client_ip::<ReqBody>(&headers, connect_info.as_ref()) {
                Some(ip) => ip.to_string(),
                None => {
                    // 如果无法提取 IP，允许请求继续
                    debug!("Unable to extract client IP, bypassing rate limit");
                    return inner.call(req).await;
                }
            };
            
            // 检查速率限制
            if !manager.check_rate_limit(&client_ip) {
                warn!(client_ip = %client_ip, "Rate limit exceeded");
                // 创建 429 响应
                let empty_body = Body::empty();
                let response = Response::builder()
                    .status(StatusCode::TOO_MANY_REQUESTS)
                    .body(ResBody::from(empty_body))
                    .unwrap();
                return Ok(response);
            }
            
            // 检查并发请求限制
            if !manager.try_acquire_concurrency(&client_ip) {
                warn!(client_ip = %client_ip, "Concurrent requests limit exceeded");
                // 创建 429 响应
                let empty_body = Body::empty();
                let response = Response::builder()
                    .status(StatusCode::TOO_MANY_REQUESTS)
                    .body(ResBody::from(empty_body))
                    .unwrap();
                return Ok(response);
            }
            
            // 记录并发请求，确保在函数退出时释放
            debug!(client_ip = %client_ip, "Request passed rate limit checks");
            let result = inner.call(req).await;
            
            // 请求完成后释放并发计数
            manager.release_concurrency(&client_ip);
            
            result
        })
    }
}

/// 为特定请求路径创建速率限制层
pub fn rate_limit_layer(config: &RateLimitConfig) -> Option<RateLimitLayer> {
    if !config.enabled {
        info!("Rate limiting disabled in configuration");
        return None;
    }
    
    info!(
        per_ip_rate = config.per_ip_rate,
        per_ip_concurrent = config.per_ip_concurrent,
        "Rate limiting enabled"
    );
    
    Some(RateLimitLayer::new(config.clone()))
}
