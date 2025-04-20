// src/bin/owdns.rs

// 标准库导入
use std::path::PathBuf;
use std::process::exit;

// 第三方库导入
use anyhow::Result;
use clap::{Parser, ArgAction};
use mimalloc::MiMalloc;
use tokio::sync::broadcast;
use tracing::{debug, error, info};
use tracing_subscriber::{prelude::*, EnvFilter, fmt};

// 本地模块导入
use oxide_wdns::common::consts::DEFAULT_CONFIG_PATH;
use oxide_wdns::server::config::ServerConfig;
use oxide_wdns::server::DoHServer;
use oxide_wdns::server::signal;

// 使用 mimalloc 作为全局内存分配器
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

/// Oxide WDNS Command Line Arguments
#[derive(Parser, Debug)]
#[command(
    name = "oxide-wdns",
    author,
    version,
    about = "High-performance DNS-over-HTTPS (DoH) server\n\n\
             Key Features:\n\
             - Standard DNS-over-HTTPS protocol support (RFC 8484)\n\
             - DoH JSON format and Wireformat support\n\
             - GET and POST request methods\n\
             - HTTP/1.1 and HTTP/2.0 support\n\
             - DNSSEC validation\n\
             - Multiple upstream DNS protocols: UDP, TCP, DoT (DNS-over-TLS), DoH (DNS-over-HTTPS)\n\
             - Built-in LRU cache for performance optimization\n\
             - Prometheus metrics monitoring\n\
             - Rate limiting and input validation for enhanced security"
)]
struct CliArgs {
    /// Configuration file path
    #[arg(
        short = 'c',
        long = "config",
        default_value = DEFAULT_CONFIG_PATH,
        help = "Server configuration file path (YAML format)"
    )]
    config: PathBuf,
    
    /// Test configuration
    #[arg(
        short = 't', 
        long = "test", 
        action = ArgAction::SetTrue, 
        help = "Test configuration file for validity and exit"
    )]
    test_config: bool,
    
    /// Enable debug logging
    #[arg(
        short = 'd',
        long = "debug",
        action = ArgAction::SetTrue,
        help = "Enable debug level logging for detailed output"
    )]
    debug: bool,
}

impl CliArgs {
    /// Validate command line arguments
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

/// Initialize logging system
fn init_logging(args: &CliArgs) {
    // Get log level from environment variable, or set based on debug parameter
    let filter = if let Ok(filter) = EnvFilter::try_from_default_env() {
        filter
    } else if args.debug {
        // Enable debug mode, show more detailed logs
        EnvFilter::new("oxide_wdns=debug,tower_http=debug,info")
    } else {
        // Normal mode, only show info level and above
        EnvFilter::new("oxide_wdns=info")
    };
    
    // Create log formatter
    let fmt_layer = fmt::layer()
        .with_target(true)
        .with_level(true)
        .with_thread_ids(args.debug) // Show thread IDs in debug mode
        .with_thread_names(args.debug); // Show thread names in debug mode
        
    // Register log subscriber
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .init();
    
    // If debug mode is enabled, output debug info
    if args.debug {
        debug!("Debug logging level enabled");
    }
} 

// 使用 tokio::main 宏让tokio自动决定线程数量
#[tokio::main]
async fn main() {
    // Parse command line arguments
    let args = CliArgs::parse();
    
    // Validate command line arguments
    if let Err(e) = args.validate() {
        eprintln!("Parameter validation error: {}", e);
        exit(1);
    }
    
    // Initialize logging
    init_logging(&args);
    
    // Load configuration
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
    
    // If only testing configuration
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
    
    // Create shutdown signal channel
    let (shutdown_tx, _) = broadcast::channel::<()>(1);
    
    // Set up signal handlers
    let signal_handler = signal::setup_signal_handlers(shutdown_tx.clone()).await;
    
    // Start server
    info!("Starting Oxide WDNS server...");
    let mut server = DoHServer::new(config);
    
    // Run server, wait for signal handler or server completion
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
    
    info!("Server shutdown completed");
}

