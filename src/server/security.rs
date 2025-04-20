// src/server/security.rs

use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::sync::Arc;
use tower_governor::{
    governor::GovernorConfigBuilder,
    key_extractor::PeerIpKeyExtractor,
    GovernorLayer,
};
use governor::middleware::NoOpMiddleware;
use tracing::{debug, warn};

use crate::server::config::RateLimitConfig;

/// 创建速率限制层
pub fn rate_limit_layer(config: &RateLimitConfig) -> Option<GovernorLayer<PeerIpKeyExtractor, NoOpMiddleware>> {
    if !config.enabled {
        return None;
    }
    
    let per_second = config.per_ip_rate as u64;
    let burst_size = config.per_ip_concurrent as u32;
    
    debug!(
        per_second,
        burst_size,
        "Creating rate limit layer"
    );
    
    // 创建 Governor 配置
    let governor_conf = GovernorConfigBuilder::default()
        .per_second(per_second)
        .burst_size(burst_size)
        .finish()
        .unwrap();
        
    // 将config用Arc包装并使用结构体字段初始化
    Some(GovernorLayer {
        config: Arc::new(governor_conf),
    })
}

/// 输入验证中间件
pub async fn validate_input(req: Request, next: Next) -> Response {
    // 检查请求体大小
    if let Some(content_length) = req.headers().get("content-length") {
        if let Ok(length) = content_length.to_str() {
            if let Ok(size) = length.parse::<usize>() {
                // 限制请求体大小为 4KB
                if size > 4096 {
                    warn!(size, "Request body too large");
                    return StatusCode::PAYLOAD_TOO_LARGE.into_response();
                }
            }
        }
    }
    
    next.run(req).await
} 
