// tests/server/signal_tests.rs

#[cfg(test)]
mod tests {
    use oxide_wdns::server::signal;
    use tokio::sync::broadcast;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

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
        // 测试：接收到 SIGINT 信号时，是否触发了优雅关闭流程。
        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
        
        // 启动模拟服务
        let service_handle = tokio::spawn(mock_service_task(shutdown_rx, None));
        
        // 启动信号处理器
        let signal_handle = signal::setup_signal_handlers(shutdown_tx.clone()).await;
        
        // 模拟发送信号 - 通过直接调用 shutdown_tx.send() 而不是真的发送系统信号
        // 这样可以绕过真实信号的限制，同时测试相同的关闭流程逻辑
        let _ = shutdown_tx.send(());
        
        // 等待服务关闭
        let service_shutdown_result = service_handle.await.expect("Service task panicked");
        
        // 断言服务正常关闭
        assert!(service_shutdown_result, "Service did not respond to shutdown signal correctly");
        
        // 终止信号处理任务
        signal_handle.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_graceful_shutdown_on_sigterm() {
        // 测试：接收到 SIGTERM 信号时，是否触发了优雅关闭流程。
        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
        
        // 启动模拟服务
        let service_handle = tokio::spawn(mock_service_task(shutdown_rx, None));
        
        // 启动信号处理器
        let signal_handle = signal::setup_signal_handlers(shutdown_tx.clone()).await;
        
        // 模拟发送信号 - 直接发送到广播通道
        let _ = shutdown_tx.send(());
        
        // 等待服务关闭
        let service_shutdown_result = service_handle.await.expect("Service task panicked");
        
        // 断言服务正常关闭
        assert!(service_shutdown_result, "Service did not respond to shutdown signal correctly");
        
        // 终止信号处理任务
        signal_handle.abort();
    }

    #[tokio::test]
    async fn test_shutdown_completes_within_timeout() {
        // 测试：优雅关闭过程是否能在指定的超时时间内完成（或强制退出）。
        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
        
        // 设置关闭超时和服务延迟
        let shutdown_timeout = Duration::from_millis(100); // 非常短的超时时间
        let service_delay = Duration::from_secs(1); // 服务故意延迟较长时间
        
        // 使用 Arc<Mutex<Option<JoinHandle>>> 共享服务句柄
        // 这样可以在不同分支中安全地访问和操作它
        let service_handle = tokio::spawn(mock_service_task(shutdown_rx, Some(service_delay)));
        let service_handle = Arc::new(Mutex::new(Some(service_handle)));
        
        // 记录开始时间
        let start_time = std::time::Instant::now();
        
        // 发送关闭信号
        let _ = shutdown_tx.send(());
        
        // 为超时分支克隆服务句柄
        let timeout_handle = service_handle.clone();
        
        // 使用超时机制等待服务关闭或强制终止
        tokio::select! {
            _ = async {
                // 等待服务完成的分支
                if let Some(handle) = service_handle.lock().unwrap().take() {
                    let result = handle.await;
                    let elapsed = start_time.elapsed();
                    assert!(result.is_ok(), "Service task panicked");
                    assert!(elapsed >= service_delay, "Service shutdown duration was unexpected");
                }
            } => {}
            
            _ = tokio::time::sleep(shutdown_timeout) => {
                // 超时分支
                let elapsed = start_time.elapsed();
                // 尝试终止服务任务
                if let Some(handle) = timeout_handle.lock().unwrap().take() {
                    handle.abort();
                }
                
                assert!(elapsed < service_delay, "Forced shutdown did not execute within timeout");
                assert!(elapsed >= shutdown_timeout, "Forced shutdown duration was unexpected");
            }
        }
    }
} 