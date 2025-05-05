// src/bin/owdns_cli.rs

//! oxide-wdns DNS over HTTPS (DoH) 客户端命令行工具
//!
//! 这个工具用于测试和验证 DoH 服务器的功能、兼容性和性能。
//! 支持以下主要功能：
//! - 向 DoH 服务器发送 DNS 查询（GET 或 POST 方法）
//! - 支持 Wireformat 和 JSON 格式的请求和响应
//! - 可定制 DNS 查询参数（域名、记录类型、DNSSEC 等）
//! - 显示详细的请求和响应信息
//! - 支持通过条件验证响应内容

use mimalloc::MiMalloc;
use clap::Parser;
use oxide_wdns::client::{CliArgs, run_query, print_error};

// 使用 mimalloc 作为全局内存分配器
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[tokio::main]
async fn main() {
    // 解析命令行参数
    let args = CliArgs::parse();
    
    // 初始化全局颜色控制
    colored::control::set_override(!args.no_color);
    
    // 验证命令行参数
    if let Err(err) = args.validate() {
        eprintln!("Argument error: {}", err);
        std::process::exit(1);
    }
    
    // 执行 DNS 查询
    match run_query(args).await {
        Ok(_) => {}
        Err(err) => {
            // 错误处理
            print_error(&err);
            std::process::exit(1);
        }
    }
} 