// src/server/args.rs

use std::path::PathBuf;
use anyhow::Result;
use clap::{Parser, ArgAction};
use crate::common::consts::DEFAULT_CONFIG_PATH;

// Oxide WDNS 命令行参数
#[derive(Parser, Debug)]
#[command(
    name = "oxide-wdns",
    author,
    version,
    about = "High-performance Secure DNS via HTTP (DoH) Gateway\n\n\
             Key Features:\n\
             - Full RFC 8484 DoH compliance (Wireformat & JSON, GET/POST, HTTP/1.1 & HTTP/2)\n\
             - Advanced DNSSEC validation for response integrity\n\
             - Multi-protocol upstream support (UDP, TCP, DoT, DoH) with flexible selection strategies\n\
             - Powerful DNS routing: rule-based (Exact, Regex, Wildcard, File, URL), multiple upstream groups, loading remote rules\n\
             - Intelligent LRU caching: includes negative caching and persistent cache (disk load/save, periodic save)\n\
             - Flexible EDNS Client Subnet (ECS) handling: strip, forward, anonymize strategies; ECS-aware caching\n\
             - Robust security: built-in IP-based rate limiting and strict input validation\n\
             - Comprehensive observability: integrated Prometheus metrics, Kubernetes health probes, and structured logging (Tracing)\n\
             - Cloud-native friendly design with support for graceful shutdown\n\n\
             Author: shengyanli1982\n\
             Email: shengyanlee36@gmail.com\n\
             GitHub: https://github.com/shengyanli1982"
)]
pub struct CliArgs {
    // 配置文件路径
    #[arg(
        short = 'c',
        long = "config",
        default_value = DEFAULT_CONFIG_PATH,
        help = "Server configuration file path (YAML format)"
    )]
    pub config: PathBuf,
    
    // 测试配置
    #[arg(
        short = 't', 
        long = "test", 
        action = ArgAction::SetTrue, 
        help = "Test configuration file for validity and exit"
    )]
    pub test_config: bool,
    
    // 启用调试日志
    #[arg(
        short = 'd',
        long = "debug",
        action = ArgAction::SetTrue,
        help = "Enable debug level logging for detailed output"
    )]
    pub debug: bool,
}

impl CliArgs {
    // 验证命令行参数
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
