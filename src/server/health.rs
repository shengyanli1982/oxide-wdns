// src/server/health.rs

use axum::{routing::get, Router};

// 创建健康检查路由
pub fn health_routes() -> Router {
    Router::new()
        .route("/health", get(|| async { "ok!!" }))
} 
