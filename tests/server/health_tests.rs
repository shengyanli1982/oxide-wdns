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
    use tracing::info;
    
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
        }
        
        (addr, server_state)
    }

    #[tokio::test]
    async fn test_health_endpoint_returns_ok_when_healthy() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_health_endpoint_returns_ok_when_healthy");

        // 1. 设置服务为健康状态
        info!("Setting up test server in healthy state...");
        let (addr, _) = setup_test_server(true).await;
        info!(server_addr = %addr, "Test server started.");

        // 2. 创建客户端
        let client = Client::new();
        info!("HTTP client created.");

        // 3. 发送 GET 请求到 /health 端点
        let health_url = format!("http://{}/health", addr);
        info!(url = %health_url, "Sending GET request to health endpoint...");
        let response = client.get(&health_url)
            .send()
            .await
            .unwrap();
        info!(status = %response.status(), "Received response from health endpoint.");

        // 4. 断言响应状态码为 StatusCode::OK (200)
        assert_eq!(response.status(), StatusCode::OK);
        info!("Validated response status is OK.");

        // 5. 断言响应体内容符合预期
        let body = response.text().await.unwrap();
        info!(response_body = %body, "Read response body.");
        assert_eq!(body, "ok!!");
        info!("Validated response body.");
        info!("Test completed: test_health_endpoint_returns_ok_when_healthy");
    }

    #[tokio::test]
    async fn test_health_endpoint_returns_error_when_unhealthy() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_health_endpoint_returns_error_when_unhealthy");

        // 1. 设置服务为不健康状态
        info!("Setting up test server in unhealthy state...");
        let (addr, _) = setup_test_server(false).await;
        info!(server_addr = %addr, "Test server started.");

        // 2. 创建客户端
        let client = Client::new();
        info!("HTTP client created.");

        // 3. 发送 GET 请求到 /health 端点
        let health_url = format!("http://{}/health", addr);
        info!(url = %health_url, "Sending GET request to health endpoint...");
        let response = client.get(&health_url)
            .send()
            .await
            .unwrap();
        info!(status = %response.status(), "Received response from health endpoint.");

        // 4. 断言响应状态码为 StatusCode::SERVICE_UNAVAILABLE (503)
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        info!("Validated response status is SERVICE_UNAVAILABLE.");

        // 5. 断言响应体内容符合预期
        let body = response.text().await.unwrap();
        info!(response_body = %body, "Read response body.");
        assert_eq!(body, "service unhealthy");
        info!("Validated response body.");
        info!("Test completed: test_health_endpoint_returns_error_when_unhealthy");
    }

    #[tokio::test]
    async fn test_health_check_upstream_dependency() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_health_check_upstream_dependency");

        // 1. 初始设置上游服务为不可用状态
        info!("Setting up test server initially in unhealthy state...");
        let (addr, health_state) = setup_test_server(false).await;
        info!(server_addr = %addr, "Test server started.");

        // 2. 创建客户端
        let client = Client::new();
        info!("HTTP client created.");

        // 3. 验证健康检查结果为不健康
        let health_url = format!("http://{}/health", addr);
        info!(url = %health_url, "Sending first GET request to health endpoint (expecting unhealthy)...");
        let response = client.get(&health_url)
            .send()
            .await
            .unwrap();
        info!(status = %response.status(), "Received first response.");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        info!("Validated initial response is SERVICE_UNAVAILABLE.");

        // 4. 使上游服务恢复可用
        info!("Updating server state to healthy...");
        {
            let mut state = health_state.lock().await;
            state.is_healthy = true;
            info!(new_state = state.is_healthy, "Server state updated.");
        }

        // 5. 再次调用健康检查逻辑
        info!(url = %health_url, "Sending second GET request to health endpoint (expecting healthy)...");
        let response = client.get(&health_url)
            .send()
            .await
            .unwrap();
        info!(status = %response.status(), "Received second response.");

        // 6. 断言健康检查结果为健康
        assert_eq!(response.status(), StatusCode::OK);
        info!("Validated second response status is OK.");
        let body = response.text().await.unwrap();
        info!(response_body = %body, "Read second response body.");
        assert_eq!(body, "ok!!");
        info!("Validated second response body.");
        info!("Test completed: test_health_check_upstream_dependency");
    }
} 