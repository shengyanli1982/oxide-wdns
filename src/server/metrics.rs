// src/server/metrics.rs

use axum::{routing::get, Router};
use prometheus::{Registry};
use std::thread_local;

// 线程本地存储的指标实例
thread_local! {
    pub static METRICS: DnsMetrics = DnsMetrics::new();
}

// DNS 服务器性能指标
pub struct DnsMetrics {
    registry: Registry,
}

impl Default for DnsMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsMetrics {
    // 创建新的指标收集器
    pub fn new() -> Self {
        let registry = Registry::new();
    

        DnsMetrics {
            registry,

        }
    }
    
    // 获取 Prometheus 注册表
    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    // 导出当前指为字符串（用于测试）
    pub fn export_metrics(&self) -> String {
        let encoder = prometheus::TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = String::new();
        encoder.encode_utf8(&metric_families, &mut buffer).unwrap();
        buffer
    }
}

// 提供指标导出路由
pub fn metrics_routes() -> Router {
    Router::new().route(
        "/metrics",
        get(|| async {
            let encoder = prometheus::TextEncoder::new();
            
            // 线程安全地获取所有注册的指标
            let metric_families = METRICS.with(|m| m.registry().gather());
            
            // 编码为文本格式
            let mut buffer = String::new();
            encoder.encode_utf8(&metric_families, &mut buffer).unwrap();
            
            // 返回响应
            (
                axum::http::StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, prometheus::TEXT_FORMAT)],
                buffer
            )
        }),
    )
} 

