// src/server/security.rs

use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;
use axum::{Router, http::StatusCode, response::Response, extract::ConnectInfo};
use axum::body::Body;
use tokio::time;
use tracing::{info, warn};
use tower_governor::{
    governor::GovernorConfigBuilder,
    key_extractor::SmartIpKeyExtractor,
    GovernorLayer,
    errors::GovernorError,
};

use crate::server::config::RateLimitConfig;
use crate::server::metrics::METRICS;


// 返回应用了速率限制的路由
pub fn apply_rate_limiting(routes: Router, config: &RateLimitConfig) -> Router {
    if !config.enabled {
        return routes;
    }
    
    // 确保突发大小至少为 1
    let burst_size_nz = NonZeroU32::new(config.per_ip_concurrent.max(1)).unwrap_or_else(|| {
        warn!("per_ip_concurrent configuration resulted in zero burst size, defaulting to 1");
        NonZeroU32::new(1).unwrap()
    });
    let burst_size_u32 = burst_size_nz.get();
    
    info!(
        per_second = config.per_ip_rate,
        burst_size = burst_size_u32,
        key_extractor = "SmartIpKeyExtractor",
        "Rate limiting enabled"
    );
    
    // 构建 Governor 配置，添加错误处理程序
    let governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .key_extractor(SmartIpKeyExtractor)
            .per_second(config.per_ip_rate.into()) 
            .burst_size(burst_size_u32) 
            .error_handler(|err: &GovernorError| {
                // 获取客户端 IP 并记录指标
                if let GovernorError::TooManyRequests { key, .. } = err {
                    let client_ip = key.to_string();
                    // 记录速率限制指标
                    METRICS.with(|m| {
                        m.record_rate_limit(&client_ip);
                    });
                    
                    debug!("Rate limit exceeded for client: {}", client_ip);
                }
                
                // 返回 429 Too Many Requests 响应
                Response::builder()
                    .status(StatusCode::TOO_MANY_REQUESTS)
                    .header("Retry-After", "5")
                    .body(Body::from("Rate limit exceeded, please slow down and retry later."))
                    .unwrap()
            })
            .finish()
            .unwrap(),
    );
    
    // 启动后台清理任务
    let limiter = governor_conf.limiter().clone();
    tokio::spawn(async move {
        let interval = Duration::from_secs(60); // 每分钟清理一次
        let mut interval_timer = time::interval(interval);
        
        loop {
            interval_timer.tick().await;
            // 清理旧的限制器状态
            limiter.retain_recent();
            let size = limiter.len();
            info!("Cleaned up rate limiter state: current size {}", size);
        }
    });
    
    // 应用 GovernorLayer 到路由
    routes.layer(GovernorLayer { config: governor_conf })
} 