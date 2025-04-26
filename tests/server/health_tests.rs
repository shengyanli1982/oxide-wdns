// tests/server/health_tests.rs

#[cfg(test)]
mod tests {
    use axum::Router;
    use reqwest::{Client, StatusCode};
    use tokio::net::TcpListener;
    use std::net::SocketAddr;
    use axum::routing::get;
    use std::sync::Arc;
    use tokio::sync::Mutex;
    
    // 定义一个辅助结构体来表示健康状态
    struct MockHealthState {
        is_healthy: bool,
    }
    
    // 定义一个辅助函数用于健康检查
    async fn health_handler(state: axum::extract::State<Arc<Mutex<MockHealthState>>>) -> impl axum::response::IntoResponse {
        let health_state = state.lock().await;
        if health_state.is_healthy {
            (StatusCode::OK, "ok!!")
        } else {
            (StatusCode::SERVICE_UNAVAILABLE, "service unhealthy")
        }
    }
    
    // 辅助函数：创建一个测试服务器
    async fn setup_test_server(is_healthy: bool) -> (SocketAddr, Arc<Mutex<MockHealthState>>) {
        // 创建健康状态
        let health_state = Arc::new(Mutex::new(MockHealthState { is_healthy }));
        
        // 创建路由
        let app = Router::new()
            .route("/health", get(health_handler))
            .with_state(health_state.clone());
            
        // 绑定到随机端口
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        
        // 启动服务器（后台运行）
        let server_state = health_state.clone();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        
        (addr, server_state)
    }

    #[tokio::test]
    async fn test_health_endpoint_returns_ok_when_healthy() {
        // 1. 设置服务为健康状态
        let (addr, _) = setup_test_server(true).await;
        
        // 2. 创建客户端
        let client = Client::new();
        
        // 3. 发送 GET 请求到 /health 端点
        let response = client.get(format!("http://{}/health", addr))
            .send()
            .await
            .unwrap();
            
        // 4. 断言响应状态码为 StatusCode::OK (200)
        assert_eq!(response.status(), StatusCode::OK);
        
        // 5. 断言响应体内容符合预期
        let body = response.text().await.unwrap();
        assert_eq!(body, "ok!!");
    }

    #[tokio::test]
    async fn test_health_endpoint_returns_error_when_unhealthy() {
        // 1. 设置服务为不健康状态
        let (addr, _) = setup_test_server(false).await;
        
        // 2. 创建客户端
        let client = Client::new();
        
        // 3. 发送 GET 请求到 /health 端点
        let response = client.get(format!("http://{}/health", addr))
            .send()
            .await
            .unwrap();
            
        // 4. 断言响应状态码为 StatusCode::SERVICE_UNAVAILABLE (503)
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        
        // 5. 断言响应体内容符合预期
        let body = response.text().await.unwrap();
        assert_eq!(body, "service unhealthy");
    }

    #[tokio::test]
    async fn test_health_check_upstream_dependency() {
        // 1. 初始设置上游服务为不可用状态
        let (addr, health_state) = setup_test_server(false).await;
        
        // 2. 创建客户端
        let client = Client::new();
        
        // 3. 验证健康检查结果为不健康
        let response = client.get(format!("http://{}/health", addr))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        
        // 4. 使上游服务恢复可用
        {
            let mut state = health_state.lock().await;
            state.is_healthy = true;
        }
        
        // 5. 再次调用健康检查逻辑
        let response = client.get(format!("http://{}/health", addr))
            .send()
            .await
            .unwrap();
            
        // 6. 断言健康检查结果为健康
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.text().await.unwrap();
        assert_eq!(body, "ok!!");
    }
} 