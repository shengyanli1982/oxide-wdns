// src/server/security.rs

use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;
use axum::{Router, http::StatusCode, response::Response};
use axum::body::Body;
use tokio::time;
use tracing::{info, warn, debug};
use tower_governor::{
    governor::GovernorConfigBuilder,
    key_extractor::SmartIpKeyExtractor,
    GovernorLayer,
    errors::GovernorError,
};

use crate::server::config::RateLimitConfig;
use crate::common::consts::{MIN_PER_IP_RATE, MAX_PER_IP_RATE, MIN_PER_IP_CONCURRENT, MAX_PER_IP_CONCURRENT};
use crate::server::metrics::METRICS;


// 返回应用了速率限制的路由或者错误
pub fn apply_rate_limiting(routes: Router, config: &RateLimitConfig) -> Router {
    if !config.enabled {
        return routes;
    }
    
    // 确保突发大小在有效范围内
    let burst_size = config.per_ip_concurrent.clamp(MIN_PER_IP_CONCURRENT, MAX_PER_IP_CONCURRENT);
    let burst_size_nz = NonZeroU32::new(burst_size).unwrap_or_else(|| {
        warn!("per_ip_concurrent configuration resulted in zero burst size, defaulting to {}", MIN_PER_IP_CONCURRENT);
        NonZeroU32::new(MIN_PER_IP_CONCURRENT).unwrap()
    });
    let burst_size_u32 = burst_size_nz.get();
    
    // 确保速率在有效范围内
    let rate = config.per_ip_rate.clamp(MIN_PER_IP_RATE, MAX_PER_IP_RATE);
    
    // 计算令牌补充周期
    let period_duration = calculate_period_duration(rate);

    // 转换间隔为毫秒
    let interval_milliseconds = if let Some(duration) = period_duration {
        duration.as_millis() as u64
    } else {
        0
    };

    // 预先计算 Retry-After 值（向上取整的秒数，最小为5秒）
    let retry_seconds = if let Some(duration) = period_duration {
        let secs = (duration.as_secs_f64().ceil() as u64).max(5);
        secs.to_string()
    } else {
        "5".to_string()
    };
    
    info!(
        per_second = rate,
        burst_size = burst_size_u32,
        interval_milliseconds = interval_milliseconds,
        retry_after = retry_seconds,
        key_extractor = "SmartIpKeyExtractor",
        "Rate limiting enabled",
    );

    // 构建 Governor 配置，添加错误处理程序
    let governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .key_extractor(SmartIpKeyExtractor)
            .period(period_duration.unwrap()) // 在此处使用 unwrap()，实际的错误处理转移到了调用者
            .burst_size(burst_size_u32)
            .error_handler(move |err: GovernorError| {
                // 获取客户端 IP 并记录指标
                if let GovernorError::TooManyRequests { .. } = &err {
                    // 直接从请求上下文中获取客户端 IP (这里没有想好如何获取，先写死)
                    let client_ip = "unknown".to_string();

                    // 记录速率限制指标
                    METRICS.with(|m| {
                        m.rate_limit_rejected_total().with_label_values(&[&client_ip]).inc();
                    });
                    
                    // 使用毫秒更新日志消息
                    debug!(
                        client_ip = %client_ip,
                        "Rate limit exceeded by client. Too Many Requests! Wait for {}ms", 
                        interval_milliseconds
                    );
                }
                
                // 返回 429 Too Many Requests 响应
                Response::builder()
                    .status(StatusCode::TOO_MANY_REQUESTS)
                    .header("Retry-After", &retry_seconds.to_string()) // Ensure retry_seconds is converted to string
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

// 根据速率计算补充周期，返回 Option<Duration>
// 如果速率无效（<= 0），返回 None
pub fn calculate_period_duration(rate: u32) -> Option<Duration> {
    if !(MIN_PER_IP_RATE..=MAX_PER_IP_RATE).contains(&rate) {
        warn!("Invalid per_ip_rate configuration: {} (must be between {} and {})", 
             rate, MIN_PER_IP_RATE, MAX_PER_IP_RATE);
        return None;
    }
    
    // 1 秒 = 1,000,000,000 纳秒
    // 周期 = 1 / 速率 (秒/请求)
    // 周期 (纳秒) = 1,000,000,000 / 速率
    let period_nanos = 1000000000 / rate;
    Some(Duration::from_nanos(period_nanos.into()))
} 