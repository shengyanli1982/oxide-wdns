// src/common/consts.rs
//
// 本文件包含项目中使用的所有全局常量

// 标准库导入
use std::net::SocketAddr;

//
// 通用常量
//

/// 默认配置文件路径
pub const DEFAULT_CONFIG_PATH: &str = "config.yaml";

//
// 服务器配置常量
//

/// 默认服务器监听地址
pub fn default_listen_addr() -> SocketAddr {
    "0.0.0.0:3053".parse().unwrap()
}

// 默认服务器连接超时
pub const DEFAULT_LISTEN_TIMEOUT: u64 = 120;

// 最大请求大小
pub const MAX_REQUEST_SIZE: usize = 16 * 1024; // 16KB

//
// DNS 常量
//

/// 默认记录类型 (A 记录)
pub const DNS_RECORD_TYPE_A: u16 = 1;

/// 默认 DNS 类 (IN 类)
pub const DNS_CLASS_IN: u16 = 1;

//
// 缓存常量
//

/// 默认是否启用缓存
pub const DEFAULT_CACHE_ENABLED: bool = true;

/// 默认缓存大小（条目数）
pub const DEFAULT_CACHE_SIZE: usize = 10000;

/// 默认最小 TTL（秒）
pub const DEFAULT_MIN_TTL: u32 = 60;

/// 默认最大 TTL（秒）
pub const DEFAULT_MAX_TTL: u32 = 86400; // 1 天

/// 默认负缓存 TTL（秒）
pub const DEFAULT_NEGATIVE_TTL: u32 = 300; // 5 分钟

//
// 速率限制常量
//

/// 默认每个 IP 每秒最大请求数
pub const DEFAULT_PER_IP_RATE: u32 = 100;

/// 默认单个 IP 的并发请求数限制
pub const DEFAULT_PER_IP_CONCURRENT: u32 = 10;

//
// 上游服务器常量
//

/// 默认查询超时时间（秒）
pub const DEFAULT_QUERY_TIMEOUT: u64 = 30;

//
// HTTP 相关常量
//

/// 默认 HTTP 客户端超时时间（秒）
pub const DEFAULT_HTTP_CLIENT_TIMEOUT: u64 = 120;

/// 默认 HTTP 客户端连接池空闲超时时间（秒）
pub const DEFAULT_HTTP_CLIENT_POOL_IDLE_TIMEOUT: u64 = 30;

/// 默认 HTTP 客户端连接池最大空闲连接数
pub const DEFAULT_HTTP_CLIENT_POOL_MAX_IDLE_CONNECTIONS: u32 = 10;

/// 默认 HTTP 客户端 Agent
pub const DEFAULT_HTTP_CLIENT_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36";

/// DoH JSON 内容类型
pub const CONTENT_TYPE_DNS_JSON: &str = "application/dns-json";

/// DoH 二进制消息内容类型
pub const CONTENT_TYPE_DNS_MESSAGE: &str = "application/dns-message";

/// IP 代理头字段名
pub const IP_HEADER_NAMES: [&str; 3] = [
    "X-Forwarded-For", 
    "X-Real-IP", 
    "CF-Connecting-IP"
]; 