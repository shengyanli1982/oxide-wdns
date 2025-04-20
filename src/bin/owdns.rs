// src/bin/owdns.rs

use std::path::PathBuf;
use std::process::exit;
use anyhow::Result;
use clap::{Parser, ArgAction};
use mimalloc::MiMalloc;
use tokio::sync::broadcast;
use tracing::{debug, error, info};
use tracing_subscriber::{prelude::*, EnvFilter, fmt};
use oxide_wdns::common::consts::DEFAULT_CONFIG_PATH;
use oxide_wdns::server::config::ServerConfig;
use oxide_wdns::server::DoHServer;
use oxide_wdns::server::signal;

// 使用 mimalloc 作为全局内存分配器
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

/// Oxide WDNS 命令行参数
#[derive(Parser, Debug)]
#[command(
    name = "oxide-wdns",
    author,
    version,
    about = "High-performance DNS-over-HTTPS (DoH) server\n\n\
             Key Features:\n\
             - Standard DNS-over-HTTPS Wireformat support (RFC 8484)\n\
             - Google/Cloudflare DoH JSON format support\n\
             - DNSSEC validation\n\
             - Multiple upstream DNS protocols: UDP, TCP, DoT (DNS-over-TLS), DoH (DNS-over-HTTPS)\n\
             - Built-in LRU cache for performance optimization\n\
             - Prometheus metrics monitoring\n\
             - Kubernetes Health Probe\n\
             - Rate limiting and input validation for enhanced security"
)]
struct CliArgs {
    /// 配置文件路径
    #[arg(
        short = 'c',
        long = "config",
        default_value = DEFAULT_CONFIG_PATH,
        help = "Server configuration file path (YAML format)"
    )]
    config: PathBuf,
    
    /// 测试配置
    #[arg(
        short = 't', 
        long = "test", 
        action = ArgAction::SetTrue, 
        help = "Test configuration file for validity and exit"
    )]
    test_config: bool,
    
    /// 启用调试日志
    #[arg(
        short = 'd',
        long = "debug",
        action = ArgAction::SetTrue,
        help = "Enable debug level logging for detailed output"
    )]
    debug: bool,
}

impl CliArgs {
    /// 验证命令行参数
    pub fn validate(&self) -> Result<()> {
        // 配置文件路径必须存在
        if !self.config.exists() {
            return Err(anyhow::anyhow!(
                "Configuration file does not exist: {}",
                self.config.display()
            ));
        }
        
        Ok(())
    }
}

/// 初始化日志系统
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

