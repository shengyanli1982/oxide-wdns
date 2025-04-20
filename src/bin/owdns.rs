// src/bin/owdns.rs

use clap::{Parser, ArgAction};
use mimalloc::MiMalloc;
use std::path::PathBuf;
use std::process::exit;
use tokio::sync::broadcast;
use tracing::{error, info};
use tracing_subscriber::{prelude::*, EnvFilter, fmt};
use oxide_wdns::server::config::ServerConfig;
use oxide_wdns::server::DoHServer;
use oxide_wdns::server::signal;

// 使用 mimalloc 作为全局内存分配器
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

/// 命令行参数
#[derive(Parser, Debug)]
#[command(author, version, about = "Oxide WDNS Server")]
struct CliArgs {
    /// 配置文件路径
    #[arg(short = 'c', long = "config", default_value = "config.yaml")]
    config: PathBuf,
    
    /// 测试配置文件有效性
    #[arg(short = 't', long = "test", action = ArgAction::SetTrue)]
    test_config: bool,
    
    /// 详细日志输出
    #[arg(short = 'd', long = "debug", action = ArgAction::SetTrue)]
    debug: bool,
}

/// 初始化日志系统
fn init_logging(args: &CliArgs) {
    // 从环境变量获取日志级别，如果没有则根据 debug 参数设置
    let filter = if let Ok(filter) = EnvFilter::try_from_default_env() {
        filter
    } else if args.debug {
        // 启用 debug 模式，显示更详细的日志
        EnvFilter::new("oxide_wdns=debug,tower_http=debug,info")
    } else {
        // 普通模式，只显示 info 及以上级别的日志
        EnvFilter::new("oxide_wdns=info")
    };
    
    // 创建日志格式化器
    let fmt_layer = fmt::layer()
        .with_target(true)
        .with_level(true)
        .with_thread_ids(args.debug) // debug 模式下显示线程 ID
        .with_thread_names(args.debug); // debug 模式下显示线程名称
        
    // 注册日志订阅者
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .init();
    
    // 如果启用了 debug 模式，输出调试信息
    if args.debug {
        tracing::debug!("Debug logging level enabled");
    }
} 

#[tokio::main]
async fn main() {
    // 解析命令行参数
    let args = CliArgs::parse();
    
    // 初始化日志
    init_logging(&args);
    
    // 加载配置
    let config = match ServerConfig::from_file(&args.config) {
        Ok(config) => {
            info!(
                config_path = ?args.config,
                dns_servers = config.upstream.resolvers.len(),
                listen_addr = %config.listen_addr,
                "Configuration loaded successfully"
            );
            config
        },
        Err(e) => {
            error!(
                config_path = ?args.config,
                error = %e,
                "Failed to load configuration file"
            );
            exit(1);
        }
    };
    
    // 如果只是测试配置
    if args.test_config {
        match config.test() {
            Ok(_) => {
                info!("Configuration test successful");
                exit(0);
            },
            Err(e) => {
                error!(error = %e, "Configuration test failed");
                exit(1);
            }
        }
    }
    
    // 创建关闭信号通道
    let (shutdown_tx, _) = broadcast::channel::<()>(1);
    
    // 设置信号处理
    let signal_handler = signal::setup_signal_handlers(shutdown_tx.clone()).await;
    
    // 启动服务器
    info!("Starting Oxide WDNS server...");
    let mut server = DoHServer::new(config);
    
    // 运行服务器，等待信号处理器或服务器完成
    tokio::select! {
        result = server.start() => {
            if let Err(e) = result {
                error!(error = %e, "Server failed to run");
                exit(1);
            }
        }
        _ = signal_handler => {
            info!("Received interrupt signal, shutting down server");
            server.shutdown();
        }
    }
    
    info!("Server shutdown completed successfully");
}

