// src/server/mod.rs

pub mod cache;
pub mod config;
pub mod doh_handler;
pub mod health;
pub mod metrics;
pub mod security;
pub mod signal;
pub mod upstream;

use std::sync::Arc;
use std::time::Duration;
use axum::{middleware, Router};
use axum::http::StatusCode;
use tokio::net::TcpListener;
use tokio::signal::ctrl_c;
use tokio::sync::oneshot;
use tokio::time;
use tracing::{error, info};
use crate::common::error::Result;
use crate::server::cache::DnsCache;
use crate::server::config::ServerConfig;
use crate::server::doh_handler::{doh_routes, ServerState};
use crate::server::health::health_routes;
use crate::server::metrics::{metrics_routes, DnsMetrics};
use crate::server::security::{rate_limit_layer, validate_input};
use crate::server::upstream::UpstreamManager;

/// DNS-over-HTTPS 服务器
pub struct DoHServer {
    /// 配置
    config: ServerConfig,
    /// 关闭信号发送器
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl DoHServer {
    /// 创建新的 DoH 服务器
    pub fn new(config: ServerConfig) -> Self {
        Self {
            config,
            shutdown_tx: None,
        }
    }
    
    /// 启动服务器
    pub async fn start(&mut self) -> Result<()> {
        // 初始化缓存
        let cache = Arc::new(DnsCache::new(self.config.cache.clone()));
        
        // 初始化上游管理器
        let upstream = Arc::new(UpstreamManager::new(&self.config).await?);
        
        // 创建指标收集器
        let metrics = {
            let m = DnsMetrics::new();
            Arc::new(m)
        };
        
        // 创建服务器状态
        let state = ServerState {
            config: self.config.clone(),
            upstream,
            cache: cache.clone(),
            metrics: metrics.clone(),
        };
        
        // 创建 DoH 路由并应用相关中间件
        let mut doh_specific_routes = doh_routes(state);
            // .layer(middleware::from_fn(validate_input)); // 将 validate_input 应用于 DoH 路由

        // // 添加速率限制（如果启用）到 DoH 路由
        // if let Some(rate_limit) = rate_limit_layer(&self.config.rate_limit) {
        //     doh_specific_routes = doh_specific_routes.layer(rate_limit);
        // }
        
        // 创建主应用路由，合并所有路由
        let app = Router::new()
            .merge(health_routes()) // 添加健康检查路由 
            .merge(metrics_routes()) // 添加指标收集路由
            .merge(doh_specific_routes); // 合并已应用中间件的 DoH 路由
            
        // 创建 TCP 监听器
        let addr = self.config.listen_addr;
        let listener = TcpListener::bind(addr).await?;
        info!("DNS-over-HTTPS server is now active on: {}", addr);
        
        // 创建关闭信号
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        self.shutdown_tx = Some(shutdown_tx);
        
        // 启动缓存统计数据更新任务
        let cache_metrics_task = tokio::spawn(Self::update_cache_metrics(cache, metrics));
        
        // 启动服务器
        let server = axum::serve(listener, app)
            .with_graceful_shutdown(Self::shutdown_signal(shutdown_rx));
            
        // 等待服务器完成
        if let Err(e) = server.await {
            error!("HTTP server error: {}", e);
            return Err(e.into());
        }
        
        // 通知缓存指标任务停止
        cache_metrics_task.abort();
        
        info!("HTTP server has been successfully shutdown");
        Ok(())
    }
    
    /// 关闭服务器
    pub fn shutdown(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
            info!("Shutdown signal sent to HTTP server");
        }
    }
    
    /// 监听关闭信号
    async fn shutdown_signal(shutdown_rx: oneshot::Receiver<()>) {
        // 等待手动关闭信号或系统信号
        tokio::select! {
            // 手动关闭信号
            _ = shutdown_rx => {
                info!("Manual shutdown signal received");
            }
            // Ctrl+C 信号
            _ = ctrl_c() => {
                info!("Received Ctrl+C signal");
            }
        }
        
        info!("Initiating graceful shutdown sequence...");
    }
    
    /// 定期更新缓存指标
    async fn update_cache_metrics(
        cache: Arc<DnsCache>,
        metrics: Arc<DnsMetrics>,
    ) {
        let mut interval = time::interval(Duration::from_secs(15));
        
        loop {
            interval.tick().await;
            
            // 获取并更新缓存大小
            let cache_size = cache.len().await;
            metrics.record_cache_size(cache_size);
        }
    }
    
    /// 运行服务器
    pub async fn run(config: ServerConfig) -> Result<()> {
        let mut server = Self::new(config);
        server.start().await?;
        Ok(())
    }
} 
