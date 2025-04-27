// src/client/args.rs

/// 使用 clap 定义和解析命令行参数。
/// 该结构体将包含所有从命令行接收到的配置信息，
/// 例如服务器 URL、查询域名、记录类型、请求格式等。

use anyhow::Result;
use clap::{Parser, ValueEnum, ArgAction};
use std::fmt;

/// HTTP 格式支持的 DoH 请求
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum DohFormat {
    /// Wire 格式 (application/dns-message)
    Wire,
    /// JSON 格式 (application/dns-json)
    Json,
}

impl fmt::Display for DohFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DohFormat::Wire => write!(f, "wire"),
            DohFormat::Json => write!(f, "json"),
        }
    }
}

/// HTTP 请求方法支持的 DoH 请求
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq)]
pub enum HttpMethod {
    /// HTTP GET 方法
    Get,
    /// HTTP POST 方法
    Post,
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpMethod::Get => write!(f, "GET"),
            HttpMethod::Post => write!(f, "POST"),
        }
    }
}

/// HTTP 版本支持的 DoH 请求
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum HttpVersion {
    /// HTTP/1.1
    Http1,
    /// HTTP/2
    Http2,
}

impl fmt::Display for HttpVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpVersion::Http1 => write!(f, "1.1"),
            HttpVersion::Http2 => write!(f, "2"),
        }
    }
}

/// Oxide WDNS DoH 客户端命令行工具
#[derive(Parser, Debug)]
#[command(
    name = "oxide-wdns-client",
    author,
    version,
    about = "Secure DNS via HTTP (DoH) Client Tool\n\n\
             Key Features:\n\
             - RFC 8484 compliant binary DNS message format (wireformat)\n\
             - Google/Cloudflare compatible JSON query format\n\
             - DNSSEC validation requests\n\
             - Flexible HTTP method selection (GET/POST)\n\
             - Multi-protocol version support (HTTP/1.1, HTTP/2)\n\
             - Detailed response analysis and display\n\
             - Response validation capabilities\n\n\
             Author: shengyanli1982\n\
             Email: shengyanlee36@gmail.com\n\
             GitHub: https://github.com/shengyanli1982"
)]
pub struct CliArgs {
    /// DoH 服务器完整 URL
    /// 
    /// 完整的 DoH 服务器端点 URL，用于发送 DNS 查询
    /// 必须包含协议前缀 (https://) 和路径部分
    #[arg(required = true)]
    pub server_url: String,

    /// 要查询的域名
    ///
    /// 通过 DoH 服务器查询的域名
    #[arg(required = true)]
    pub domain: String,

    /// DNS 记录类型
    ///
    /// 指定要查询的 DNS 记录类型，常见类型包括:
    /// - A: IPv4 地址记录
    /// - AAAA: IPv6 地址记录
    /// - MX: 邮件交换记录
    /// - CNAME: 规范名称记录
    /// - TXT: 文本记录
    /// - SRV: 服务记录
    /// - NS: 域名服务器记录
    /// - SOA: 权威记录起始
    #[arg(
        short, 
        long, 
        default_value = "A", 
        help = "DNS record type to query (A, AAAA, MX, TXT, etc.)"
    )]
    pub record_type: String,

    /// DoH 请求格式 (json 或 wire)
    ///
    /// 指定 DNS 查询的编码格式:
    /// - wire: 二进制 DNS 消息格式 (application/dns-message)
    /// - json: JSON 格式 (application/dns-json)
    #[arg(
        long, 
        value_enum, 
        default_value_t = DohFormat::Wire,
        help = "DoH request format (json or wire)"
    )]
    pub format: DohFormat,

    /// HTTP 方法 (GET 或 POST)
    ///
    /// 强制使用指定的 HTTP 方法发送请求
    /// 若未指定，将根据查询大小和格式自动选择最合适的方法
    #[arg(
        short = 'X', 
        long, 
        value_enum,
        help = "HTTP method to use (GET or POST)"
    )]
    pub method: Option<HttpMethod>,

    /// 首选 HTTP 版本 (1.1 或 2)
    ///
    /// 指定与 DoH 服务器通信时使用的 HTTP 协议版本
    #[arg(
        long = "http", 
        value_enum,
        help = "Preferred HTTP version (1.1 or 2)"
    )]
    pub http_version: Option<HttpVersion>,

    /// 在 DNS 查询中设置 DNSSEC OK (DO) 位
    ///
    /// 通过在 DNS 查询中设置 DNSSEC OK 位启用 DNSSEC 验证，
    /// 请求服务器返回与 DNSSEC 相关的记录
    #[arg(
        long,
        action = ArgAction::SetTrue,
        help = "Set DNSSEC OK (DO) bit in the DNS query"
    )]
    pub dnssec: bool,

    /// 发送原始 DNS 查询载荷 (十六进制编码)
    ///
    /// 提供一个原始的、十六进制编码的 DNS 消息作为查询载荷
    /// 指定时，将覆盖域名和记录类型参数
    /// 用于高级或边缘情况测试
    #[arg(
        long,
        help = "Send a raw DNS query payload (hex-encoded)"
    )]
    pub payload: Option<String>,
    
    /// 根据指定条件验证响应
    ///
    /// 用于检查响应中的条件列表 (逗号分隔)
    /// 例如:
    /// - rcode=NOERROR: 检查响应代码是否为 NOERROR
    /// - has-ip=1.2.3.4: 检查响应中是否包含 IP 地址 1.2.3.4
    /// - min-ttl=300: 检查所有记录的 TTL 是否大于等于 300
    /// - min-answers=1: 检查至少有 1 条回答记录
    /// - has-type=A: 检查响应中是否包含 A 记录
    /// - contains=example: 检查某条记录数据是否包含 'example'
    /// - dnssec-validated: 检查 AD (认证数据) 位是否已设置
    #[arg(
        long,
        help = "Validate the response against specified conditions"
    )]
    pub validate: Option<String>,

    /// 跳过 TLS 证书验证
    ///
    /// 连接到服务器时禁用 TLS 证书验证
    /// 适用于使用自签名证书或本地开发服务器进行测试
    /// 警告: 这会降低安全性，仅在受控环境中使用
    #[arg(
        short = 'k', 
        long,
        action = ArgAction::SetTrue,
        help = "Skip TLS certificate validation"
    )]
    pub insecure: bool,

    /// 增加输出详细程度 (显示 HTTP 头，等)
    ///
    /// 控制输出中的详细程度:
    /// -v: 显示基本请求/响应详情
    /// -vv: 显示 HTTP 头和详细计时信息
    /// -vvv: 显示原始 DNS 消息负载 (十六进制和解码)
    #[arg(
        short, 
        long, 
        action = ArgAction::Count,
        help = "Increase output verbosity (display HTTP headers, etc.)"
    )]
    pub verbose: u8,
    
    /// 禁用终端中的彩色输出
    ///
    /// 关闭控制台输出中的所有彩色格式
    /// 适用于不支持 ANSI 颜色的环境
    /// 或将输出重定向到文件或其他工具时使用
    #[arg(
        long,
        action = ArgAction::SetTrue,
        help = "Disable colored output in terminal"
    )]
    pub no_color: bool,
}

impl CliArgs {
    /// 验证命令行参数
    pub fn validate(&self) -> Result<()> {
        // 验证服务器 URL
        if !self.server_url.starts_with("https://") {
            return Err(anyhow::anyhow!(
                "Server URL must start with https:// for security reasons"
            ));
        }

        // 如果提供了载荷，验证其是否为有效的十六进制字符串
        if let Some(payload) = &self.payload {
            if !payload.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(anyhow::anyhow!(
                    "Payload must be a valid hex-encoded string"
                ));
            }
        }

        // 验证记录类型
        if self.payload.is_none() {
            // 只有在未提供原始载荷时才验证记录类型
            match self.record_type.to_uppercase().as_str() {
                "A" | "AAAA" | "MX" | "CNAME" | "TXT" | "SRV" | "NS" | "SOA" | "PTR" => (),
                _ => {
                    // 尝试解析为数字记录类型
                    if self.record_type.parse::<u16>().is_err() {
                        return Err(anyhow::anyhow!(
                            "Invalid DNS record type: {}", self.record_type
                        ));
                    }
                }
            }
        }

        Ok(())
    }
} 