// src/bin/owdns.rs

use std::process::exit;
use mimalloc::MiMalloc;
use tokio::sync::broadcast;
use tracing::{debug, error, info};
use tracing_subscriber::{prelude::*, EnvFilter, fmt};
use oxide_wdns::server::args::CliArgs;
use oxide_wdns::server::config::ServerConfig;
use oxide_wdns::server::DoHServer;
use oxide_wdns::server::signal;
use clap::Parser;

// 使用 mimalloc 作为全局内存分配器
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

// 初始化日志系统
fn init_logging(args: &CliArgs) {
    // 从环境变量获取日志级别，或根据调试参数设置
    let filter = if let Ok(filter) = EnvFilter::try_from_default_env() {
        filter
    } else if args.debug {
        // 启用调试模式，显示更详细的日志
        EnvFilter::new("oxide_wdns=debug,tower_http=debug,owdns=debug,info")
    } else {
        // 正常模式，仅显示 info 级别及以上
        EnvFilter::new("oxide_wdns=info,owdns=info")
    };
    
    // 创建日志格式化器
    let fmt_layer = fmt::layer()
        .with_target(true)
        .with_level(true)
        .with_ansi(false); // 关闭彩色输出
        
    // 注册日志订阅器
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .init();
    
    // 如果启用调试模式，输出调试信息
    if args.debug {
        debug!("Debug logging enabled - verbose output mode active");
    }
} 

// 使用 tokio::main 宏让tokio自动决定线程数量
#[tokio::main]
async fn main() {
    // 解析命令行参数
    let args = CliArgs::parse();
    
    // 验证命令行参数
    if let Err(e) = args.validate() {
        eprintln!("Parameter validation error: {}", e);
        exit(1);
    }
    
    // 初始化日志
    init_logging(&args);
    
    // 加载配置
    let config = match ServerConfig::from_file(&args.config) {
        Ok(config) => {
            info!(
                config_path = ?args.config,
                dns_servers = config.dns.upstream.resolvers.len(),
                listen_addr = %config.http.listen_addr,
                "Configuration loaded successfully,",
            );
            config
        },
        Err(e) => {
            error!(
                config_path = ?args.config,
                error = %e,
                "Failed to load configuration file,",
            );
            exit(1);
        }
    };
    
    // 如果仅测试配置
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
    
    // 设置信号处理程序
    let signal_handler = signal::setup_signal_handlers(shutdown_tx.clone()).await;
    
    // 启动服务器
    info!("Initializing Oxide WDNS server...");
    let mut server = DoHServer::new(config);
    
    // 运行服务器，等待信号处理程序或服务器完成
    tokio::select! {
        result = server.start() => {
            if let Err(e) = result {
                error!(error = %e, "Server failed to run");
                exit(1);
            }
        }
        _ = signal_handler => {
            info!("Interrupt signal received, initiating shutdown");
            server.shutdown();
        }
    }
    
    info!("Oxide WDNS shutdown completed");
}

