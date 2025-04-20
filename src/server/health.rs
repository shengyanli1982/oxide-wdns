// src/server/health.rs

use axum::{routing::get, Router};
use tracing::debug;

/// 创建健康检查路由
pub fn health_routes() -> Router {
    Router::new().route("/health", get(health_handler))
}

/// 健康检查处理函数
async fn health_handler() -> &'static str {
    "ok!!"
} 
