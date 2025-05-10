// src/server/mod.rs

pub mod cache;
pub mod config;
pub mod doh_handler;
pub mod error;
pub mod health;
pub mod metrics;
pub mod routing;
pub mod security;
pub mod upstream;
pub mod args;
pub mod ecs;
pub mod scalar;

use std::sync::Arc;
use axum::Router as AxumRouter;
use reqwest::Client;
use tracing::info;

use crate::server::error::{Result, ServerError};
use crate::server::cache::DnsCache;
use crate::server::config::ServerConfig;
use crate::server::doh_handler::{doh_routes, ServerState};
use crate::server::health::health_routes;
use crate::server::metrics::metrics_routes;
use crate::server::routing::Router as DnsRouter;
use crate::server::security::{apply_rate_limiting, calculate_period_duration};
use crate::server::upstream::UpstreamManager;
use crate::common::consts::{MIN_PER_IP_RATE, MAX_PER_IP_RATE, MIN_PER_IP_CONCURRENT, MAX_PER_IP_CONCURRENT};

// 创建 HTTP 客户端的公共函数
pub fn create_http_client(config: &ServerConfig) -> Result<Client> {
    reqwest::ClientBuilder::new()
        .timeout(config.http_client_timeout())
        .pool_idle_timeout(config.http_client_pool_idle_timeout())
        .user_agent(&config.dns.http_client.request.user_agent)
        .pool_max_idle_per_host(config.dns.http_client.pool.max_idle_connections as usize)
        .build()
        .map_err(|e| error::ServerError::Http(format!("Failed to create HTTP client: {}", e)))
}

// DNS-over-HTTPS 服务器
pub struct DoHServer {
    // 配置
    config: ServerConfig,
    // 是否启用调试模式
    debug: bool,
}

impl DoHServer {
    // 创建新的 DoH 服务器
    pub fn new(config: ServerConfig, debug: bool) -> Self {
        Self { config, debug }
    }

    // 此方法构建 Axum 应用和相关资源，但不启动服务器。
    // 返回 Axum Router, DNS Cache, 和 cache metrics task handle.
    pub async fn build_application_components(
        &self,
    ) -> Result<(
        AxumRouter,
        Arc<DnsCache>,
    )> {
        let cache = Arc::new(DnsCache::new(self.config.dns.cache.clone()));
        let client = create_http_client(&self.config)?;
        let router_manager = Arc::new(DnsRouter::new(self.config.dns.routing.clone(), Some(client.clone())).await?);
        let upstream_manager = Arc::new(UpstreamManager::new(Arc::new(self.config.clone()), client.clone()).await?);

        let state = ServerState {
            config: self.config.clone(),
            upstream: upstream_manager,
            router: router_manager,
            cache: cache.clone(),
        };

        let mut doh_specific_routes = doh_routes(state);
        
        let rate_limit_config = &self.config.http.rate_limit;
        if rate_limit_config.enabled {
            let rate = rate_limit_config.per_ip_rate;
            let burst = rate_limit_config.per_ip_concurrent;
            
            // 仅计算期间持续时间并应用速率限制
            if calculate_period_duration(rate).is_none() {
                return Err(ServerError::Config(format!(
                    "Failed to calculate rate limit period for per_ip_rate: {}",
                    rate
                )));
            }
            doh_specific_routes = apply_rate_limiting(doh_specific_routes, rate_limit_config);
            info!("Rate limiting applied with per_ip_rate: {} and per_ip_concurrent: {}", rate, burst);
        } else {
            info!("Rate limiting is disabled");
        }

        // 创建 Axum Router
        let mut app = AxumRouter::new();
            
        // 在调试模式下启用 Swagger UI 和 RapiDoc（放在doh_specific_routes之前）
        if self.debug {
            // info!("Debug mode enabled: Swagger UI available at /swagger");
            // app = app.merge(swagger::create_swagger_routes());
            info!("Debug mode enabled: Scalar UI available at /scalar");
            app = app.merge(scalar::create_scalar_routes());
        }

        // 添加健康检查和指标路由
        // 放在doh_specific_routes之前，放置被限速
        app = app.merge(health_routes()).merge(metrics_routes());

        // 添加doh_specific_routes
        app = app.merge(doh_specific_routes);

        Ok((app, cache))
    }
}
