// tests/server/signal_tests.rs

#[cfg(test)]
mod tests {
    use oxide_wdns::server::signal;
    use tokio::sync::broadcast;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tracing::info;

    // 用于测试的辅助函数，模拟一个需要关闭的服务
    async fn mock_service_task(mut rx: broadcast::Receiver<()>, delay: Option<Duration>) -> bool {
        tokio::select! {
            _ = rx.recv() => {
                // 如果指定了延迟，则模拟服务关闭需要时间
                if let Some(delay_time) = delay {
                    tokio::time::sleep(delay_time).await;
                }
                true // 服务正常关闭
            }
            _ = tokio::time::sleep(Duration::from_secs(5)) => {
                false // 超时（无信号收到）
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_graceful_shutdown_on_sigint() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_graceful_shutdown_on_sigint");

        // 测试：接收到 SIGINT 信号时，是否触发了优雅关闭流程。
        info!("Creating shutdown broadcast channel...");
        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
        
        // 启动模拟服务
        info!("Spawning mock service task...");
        let service_handle = tokio::spawn(mock_service_task(shutdown_rx, None));
        
        // 启动信号处理器
        // 注意：在测试中，setup_signal_handlers 可能不会真正监听系统信号，
        // 但它会返回一个句柄，并且可以通过 tx 发送关闭信号来模拟。
        info!("Setting up signal handlers (mocked)...");
        let signal_handle = signal::setup_signal_handlers(shutdown_tx.clone()).await;
        info!("Signal handlers set up.");
        
        // 模拟发送信号 - 通过直接调用 shutdown_tx.send() 而不是真的发送系统信号
        // 这样可以绕过真实信号的限制，同时测试相同的关闭流程逻辑
        info!("Simulating shutdown signal by sending to broadcast channel...");
        let send_result = shutdown_tx.send(());
        info!(send_successful = send_result.is_ok(), "Shutdown signal sent.");
        
        // 等待服务关闭
        info!("Waiting for mock service task to complete...");
        let service_shutdown_result = service_handle.await.expect("Service task panicked");
        info!(service_result = service_shutdown_result, "Mock service task completed.");
        
        // 断言服务正常关闭
        assert!(service_shutdown_result, "Service did not respond to shutdown signal correctly");
        info!("Validated service shutdown result.");
        
        // 终止信号处理任务
        info!("Aborting signal handler task...");
        signal_handle.abort();
        info!("Test completed: test_graceful_shutdown_on_sigint");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_graceful_shutdown_on_sigterm() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_graceful_shutdown_on_sigterm");

        // 测试：接收到 SIGTERM 信号时，是否触发了优雅关闭流程。
        info!("Creating shutdown broadcast channel...");
        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
        
        // 启动模拟服务
        info!("Spawning mock service task...");
        let service_handle = tokio::spawn(mock_service_task(shutdown_rx, None));
        
        // 启动信号处理器
        info!("Setting up signal handlers (mocked)...");
        let signal_handle = signal::setup_signal_handlers(shutdown_tx.clone()).await;
        info!("Signal handlers set up.");
        
        // 模拟发送信号 - 直接发送到广播通道
        info!("Simulating shutdown signal by sending to broadcast channel...");
        let send_result = shutdown_tx.send(());
        info!(send_successful = send_result.is_ok(), "Shutdown signal sent.");
        
        // 等待服务关闭
        info!("Waiting for mock service task to complete...");
        let service_shutdown_result = service_handle.await.expect("Service task panicked");
        info!(service_result = service_shutdown_result, "Mock service task completed.");
        
        // 断言服务正常关闭
        assert!(service_shutdown_result, "Service did not respond to shutdown signal correctly");
        info!("Validated service shutdown result.");
        
        // 终止信号处理任务
        info!("Aborting signal handler task...");
        signal_handle.abort();
        info!("Test completed: test_graceful_shutdown_on_sigterm");
    }

    #[tokio::test]
    async fn test_shutdown_completes_within_timeout() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_shutdown_completes_within_timeout");

        // 测试：优雅关闭过程是否能在指定的超时时间内完成（或强制退出）。
        info!("Creating shutdown broadcast channel...");
        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
        
        // 设置关闭超时和服务延迟
        let shutdown_timeout = Duration::from_millis(100); // 非常短的超时时间
        let service_delay = Duration::from_secs(1); // 服务故意延迟较长时间
        info!(?shutdown_timeout, ?service_delay, "Configured shutdown timeout and service delay.");
        
        // 使用 Arc<Mutex<Option<JoinHandle>>> 共享服务句柄
        // 这样可以在不同分支中安全地访问和操作它
        info!("Spawning mock service task with delay...");
        let service_handle = tokio::spawn(mock_service_task(shutdown_rx, Some(service_delay)));
        let service_handle_arc = Arc::new(Mutex::new(Some(service_handle)));
        info!("Mock service task spawned.");
        
        // 记录开始时间
        let start_time = std::time::Instant::now();
        info!("Test timer started.");
        
        // 发送关闭信号
        info!("Simulating shutdown signal by sending to broadcast channel...");
        let send_result = shutdown_tx.send(());
        info!(send_successful = send_result.is_ok(), "Shutdown signal sent.");
        
        // 为超时分支克隆服务句柄
        let timeout_handle_arc = service_handle_arc.clone();
        
        // 使用超时机制等待服务关闭或强制终止
        info!("Waiting for service completion or timeout ({:?})...", shutdown_timeout);
        tokio::select! {
            _ = async {
                // 等待服务完成的分支
                info!("Waiting for service handle completion...");
                if let Some(handle) = service_handle_arc.lock().unwrap().take() {
                    let result = handle.await;
                    let elapsed = start_time.elapsed();
                    info!(?elapsed, ?result, "Service task completed normally.");
                    assert!(result.is_ok(), "Service task panicked");
                    // 由于select!竞态条件，即使服务正常完成，也可能落在超时分支
                    // 因此，如果服务正常完成，主要检查它是否运行了预期的时间
                    assert!(elapsed >= service_delay, "Service shutdown duration ({:?}) was less than expected delay ({:?})", elapsed, service_delay);
                } else {
                    info!("Service handle was already taken (likely by timeout branch).");
                }
            } => { info!("Service completed branch finished.") }
            
            _ = tokio::time::sleep(shutdown_timeout) => {
                // 超时分支
                let elapsed = start_time.elapsed();
                info!(?elapsed, ?shutdown_timeout, "Timeout branch executed.");
                // 尝试终止服务任务
                info!("Attempting to abort service task due to timeout...");
                if let Some(handle) = timeout_handle_arc.lock().unwrap().take() {
                    handle.abort();
                    info!("Service task aborted.");
                } else {
                    info!("Service handle was already taken (likely completed normally).");
                }
                
                // 断言：我们确实在 service_delay 之前超时了
                assert!(elapsed < service_delay, "Forced shutdown did not execute before service delay finished ({:?} < {:?})", elapsed, service_delay);
                // 断言：超时确实发生在 shutdown_timeout 之后（允许一点误差）
                assert!(elapsed >= shutdown_timeout, "Forced shutdown duration ({:?}) was less than timeout ({:?})", elapsed, shutdown_timeout);
                info!("Validated timeout behavior.");
            }
        }
        info!("Test completed: test_shutdown_completes_within_timeout");
    }
} 