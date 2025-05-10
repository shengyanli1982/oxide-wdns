// src/bin/owdns.rs

use std::process::exit;
use std::time::Duration;
use mimalloc::MiMalloc;
use tokio::net::TcpListener;
use tracing::{debug, error, info};
use tracing_subscriber::{prelude::*, EnvFilter, fmt};
use oxide_wdns::server::args::CliArgs;
use oxide_wdns::server::config::ServerConfig;
use oxide_wdns::server::DoHServer;
use std::sync::Arc;
use clap::Parser;
use tokio_graceful_shutdown::{Toplevel, SubsystemHandle};

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
        EnvFilter::new("oxide_wdns=info,owdns=info,tokio_graceful_shutdown=info")
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

// 定义 owdns 服务子系统
async fn owdns_server_subsystem(
    subsys: SubsystemHandle,
    config: ServerConfig,
    doh_server: Arc<DoHServer>,
) -> Result<(), anyhow::Error> {
    let (app_router, dns_cache) =
        doh_server.build_application_components().await.map_err(|e| {
            error!("Failed to build application components: {}", e);
            anyhow::anyhow!("Failed to build application components: {}", e)
        })?;

    let addr = config.http.listen_addr;
    let listener = TcpListener::bind(addr).await.map_err(|e| {
        error!("Failed to bind to address {}: {}", addr, e);
        anyhow::anyhow!("Failed to bind to address {}: {}", addr, e)
    })?;
    info!("DoH server listening on: {}", addr);

    let server_future = axum::serve(
        listener,
        app_router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    );

    // 将 axum 服务器与子系统的关闭信号集成
    tokio::select! {
        result = server_future => {
            if let Err(e) = result {
                error!("Axum server error: {}", e);
                return Err(anyhow::anyhow!("Axum server error: {}", e));
            }
        }
        _ = subsys.on_shutdown_requested() => {
            info!("Shutdown requested, stopping server...");
        }
    };

    info!("HTTP server shutdown successfully.");
    
    // 关闭 DNS 缓存
    if let Err(e) = dns_cache.shutdown().await {
        error!("Failed to shutdown DNS cache: {}", e);
    } else {
        info!("DNS cache shutdown successfully.");
    }
    
    Ok(())
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

    info!("Initializing Oxide WDNS server...");
    
    // 创建 DoHServer 实例，传入debug参数
    let doh_server = Arc::new(DoHServer::new(config.clone(), args.debug));

    // 使用 tokio-graceful-shutdown 设置顶层关闭处理
    // 创建并运行顶层控制器
    if let Err(e) = Toplevel::new(move |subsys| {
            // 克隆 Arc<DoHServer> 和 config
            let server_clone = doh_server.clone();
            let config_clone = config.clone();
            async move {
                if let Err(e) = owdns_server_subsystem(subsys, config_clone, server_clone).await {
                    error!("Oxide WDNS server subsystem error: {:#}", e);
                }
            }
        })
        .catch_signals()
        .handle_shutdown_requests(Duration::from_secs(10))
        .await
    {
        error!("Oxide WDNS server shut down with error: {:#}", e);
        exit(1);
    }
    
    info!("Oxide WDNS shutdown successfully.");
    exit(0);
}

