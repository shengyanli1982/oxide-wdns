use tokio::sync::broadcast;
use tracing::{debug, error, info};

// Windows平台的信号处理设置
#[cfg(windows)]
pub async fn setup_signal_handlers(shutdown_tx: broadcast::Sender<()>) -> tokio::task::JoinHandle<()> {
    use tokio::signal::windows::{ctrl_c, ctrl_break};

    // 克隆发送者用于不同的信号处理
    let shutdown_tx_ctrl_c = shutdown_tx.clone();
    let shutdown_tx_ctrl_break = shutdown_tx;

    // 创建Ctrl+C信号处理器
    let mut ctrl_c = match ctrl_c() {
        Ok(handler) => handler,
        Err(err) => {
            error!("Failed to create Ctrl+C handler: {}", err);
            return tokio::spawn(async {});
        }
    };

    // 创建Ctrl+Break信号处理器
    let mut ctrl_break = match ctrl_break() {
        Ok(handler) => handler,
        Err(err) => {
            error!("Failed to create Ctrl+Break handler: {}", err);
            return tokio::spawn(async {});
        }
    };

    // 启动两个任务分别处理Ctrl+C和Ctrl+Break信号
    let ctrl_c_handle = tokio::spawn(async move {
        ctrl_c.recv().await;
        info!("Received Ctrl+C signal");
        let _ = shutdown_tx_ctrl_c.send(());
    });

    let ctrl_break_handle = tokio::spawn(async move {
        ctrl_break.recv().await;
        info!("Received Ctrl+Break signal");
        let _ = shutdown_tx_ctrl_break.send(());
    });

    // 返回等待任意一个信号处理完成的任务
    tokio::spawn(async move {
        tokio::select! {
            _ = ctrl_c_handle => {
                debug!("Ctrl+C handler completed");
            }
            _ = ctrl_break_handle => {
                debug!("Ctrl+Break handler completed");
            }
        }
    })
}

// Unix平台(Linux/macOS)的信号处理设置
#[cfg(unix)]
pub async fn setup_signal_handlers(shutdown_tx: broadcast::Sender<()>) -> tokio::task::JoinHandle<()> {
    use tokio::signal::unix::{signal, SignalKind};

    // 创建 SIGINT (Ctrl+C) 信号处理器
    let mut sigint = match signal(SignalKind::interrupt()) {
        Ok(handler) => handler,
        Err(err) => {
            error!("Failed to create SIGINT handler: {}", err);
            return tokio::spawn(async {});
        }
    };

    // 创建 SIGTERM 信号处理器
    let mut sigterm = match signal(SignalKind::terminate()) {
        Ok(handler) => handler,
        Err(err) => {
            error!("Failed to create SIGTERM handler: {}", err);
            return tokio::spawn(async {});
        }
    };

    // 创建 SIGHUP 信号处理器
    let mut sighup = match signal(SignalKind::hangup()) {
        Ok(handler) => handler,
        Err(err) => {
            error!("Failed to create SIGHUP handler: {}", err);
            return tokio::spawn(async {});
        }
    };

    // 克隆发送者用于不同的信号处理
    let shutdown_tx_sigint = shutdown_tx.clone();
    let shutdown_tx_sigterm = shutdown_tx.clone();
    let shutdown_tx_sighup = shutdown_tx;

    // 启动三个任务分别处理不同的信号
    let sigint_handle = tokio::spawn(async move {
        sigint.recv().await;
        info!("Received SIGINT signal");
        let _ = shutdown_tx_sigint.send(());
    });

    let sigterm_handle = tokio::spawn(async move {
        sigterm.recv().await;
        info!("Received SIGTERM signal");
        let _ = shutdown_tx_sigterm.send(());
    });

    let sighup_handle = tokio::spawn(async move {
        sighup.recv().await;
        info!("Received SIGHUP signal");
        let _ = shutdown_tx_sighup.send(());
    });

    // 返回等待任意一个信号处理完成的任务
    tokio::spawn(async move {
        tokio::select! {
            _ = sigint_handle => {
                debug!("SIGINT handler completed");
            }
            _ = sigterm_handle => {
                debug!("SIGTERM handler completed");
            }
            _ = sighup_handle => {
                debug!("SIGHUP handler completed");
            }
        }
    })
} 