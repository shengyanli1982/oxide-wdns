// src/server/mod.rs

pub mod cache;
pub mod config;
pub mod doh_handler;
pub mod error;
pub mod health;
pub mod metrics;
pub mod security;
pub mod signal;
pub mod upstream;
pub mod args;

use std::sync::Arc;
use std::time::Duration;
use axum::Router;
use tokio::net::TcpListener;
use tokio::signal::ctrl_c;
use tokio::sync::oneshot;
use tokio::time;
use tracing::{error, info};

use crate::server::error::Result;
use crate::server::cache::DnsCache;
use crate::server::config::ServerConfig;
use crate::server::doh_handler::{doh_routes, ServerState};
use crate::server::health::health_routes;
use crate::server::metrics::{metrics_routes, DnsMetrics};
use crate::server::security::apply_rate_limiting;
use crate::server::upstream::UpstreamManager;

// DNS-over-HTTPS 服务器
pub struct DoHServer {
    // 配置
    config: ServerConfig,
    // 关闭信号发送器
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl DoHServer {
    // 创建新的 DoH 服务器
    pub fn new(config: ServerConfig) -> Self {
        Self {
            config,
            shutdown_tx: None,
        }
    }
    
    // 启动服务器
    pub async fn start(&mut self) -> Result<()> {
        // 初始化缓存
        let cache = Arc::new(DnsCache::new(self.config.dns.cache.clone()));
        
        // 初始化上游管理器
        let upstream = Arc::new(UpstreamManager::new(&self.config).await?);
        
        // 创建指标收集器
        let metrics = Arc::new(DnsMetrics::new());
        
        // 创建服务器状态
        let state = ServerState {
            config: self.config.clone(),
            upstream,
            cache: cache.clone(),
            metrics: metrics.clone(),
        };
        
        // 创建 DoH 路由
        let mut doh_specific_routes = doh_routes(state);

        // 应用速率限制
        doh_specific_routes = apply_rate_limiting(doh_specific_routes, &self.config.http.rate_limit);
        
        // 创建主应用路由，合并所有路由
        let app = Router::new()
            .merge(health_routes()) // 添加健康检查路由 
            .merge(metrics_routes()) // 添加指标收集路由
            .merge(doh_specific_routes); // 合并已应用中间件的 DoH 路由
            
        // 创建 TCP 监听器
        let addr = self.config.http.listen_addr;
        let listener = TcpListener::bind(addr).await?;
        info!("DoH server is now active on: {}", addr);
        
        // 创建关闭信号
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        self.shutdown_tx = Some(shutdown_tx);
        
        // 启动缓存统计数据更新任务
        let cache_metrics_handle = tokio::spawn(Self::update_cache_metrics(cache, metrics));
        
        // 开始接收连接并处理请求
        info!("Starting to accept connections");
        let server = axum::serve(
            listener,
            // Ensure connect_info is provided for SmartIpKeyExtractor fallback
            app.into_make_service_with_connect_info::<std::net::SocketAddr>()
        )
        .with_graceful_shutdown(Self::shutdown_signal(shutdown_rx));
        
        // 运行服务器
        if let Err(e) = server.await {
            error!("HTTP server error: {}", e);
            // 确保取消缓存指标任务
            cache_metrics_handle.abort();
            return Err(e.into());
        }
        
        // 通知缓存指标任务停止
        cache_metrics_handle.abort();
        
        info!("HTTP server has been successfully shutdown");
        Ok(())
    }
    
    // 监听关闭信号
    async fn shutdown_signal(shutdown_rx: oneshot::Receiver<()>) {
        // 等待手动关闭信号或系统信号
        tokio::select! {
            // 手动关闭信号
            res = shutdown_rx => {
                match res {
                    Ok(_) => info!("Manual shutdown signal received"),
                    Err(e) => info!("Manual shutdown channel closed: {}", e),
                }
            }
            // Ctrl+C 信号
            _ = ctrl_c() => {
                info!("Received Ctrl+C signal");
            }
        }
        
        info!("Initiating graceful shutdown sequence...");
        // 给正在处理的请求留出一些时间完成
        // 使用 sleep_until 提高精确性
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        time::sleep_until(deadline).await;
    }
    
    // 更新缓存指标的任务
    async fn update_cache_metrics(
        cache: Arc<DnsCache>,
        metrics: Arc<DnsMetrics>,
    ) {
        // 使用 interval_at 确保固定间隔执行
        let start = tokio::time::Instant::now();
        let period = Duration::from_secs(15);
        let mut interval = time::interval_at(start, period);
        
        loop {
            interval.tick().await;
            
            // 获取并更新缓存大小 - 使用无需等待的 len 方法优化性能
            let cache_size = cache.len().await;
            metrics.record_cache_size(cache_size);
        }
    }
    
    // 关闭服务器
    pub fn shutdown(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
            info!("Shutdown signal sent to HTTP server");
        }
    }
    
    // 运行服务器
    pub async fn run(config: ServerConfig) -> Result<()> {
        let mut server = Self::new(config);
        server.start().await?;
        Ok(())
    }
} 
