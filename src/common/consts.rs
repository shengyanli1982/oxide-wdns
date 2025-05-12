// src/common/consts.rs
//
// 本文件包含项目中使用的所有全局常量

// 标准库导入
use std::net::SocketAddr;

//
// 通用常量
//

// 默认配置文件路径
pub const DEFAULT_CONFIG_PATH: &str = "config.yaml";

//
// 服务器配置常量
//

// 默认服务器监听地址
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

// 默认记录类型 (A 记录)
pub const DNS_RECORD_TYPE_A: u16 = 1;

// 默认 DNS 类 (IN 类)
pub const DNS_CLASS_IN: u16 = 1;

// DNS 分流特殊上游组名称 - 黑洞（阻止）
pub const BLACKHOLE_UPSTREAM_GROUP_NAME: &str = "__blackhole__";

//
// EDNS 客户端子网 (ECS) 常量
//

// EDNS 客户端子网 Option Code（RFC 7871）
pub const EDNS_CLIENT_SUBNET_OPTION_CODE: u16 = 8;

// ECS 策略：剥离
pub const ECS_POLICY_STRIP: &str = "strip";

// ECS 策略：转发
pub const ECS_POLICY_FORWARD: &str = "forward";

// ECS 策略：匿名化
pub const ECS_POLICY_ANONYMIZE: &str = "anonymize";

// 默认 IPv4 匿名化前缀长度
pub const DEFAULT_IPV4_PREFIX_LENGTH: u8 = 24;

// 默认 IPv6 匿名化前缀长度
pub const DEFAULT_IPV6_PREFIX_LENGTH: u8 = 48;

// ECS 最大 IPv4 前缀长度
pub const MAX_IPV4_PREFIX_LENGTH: u8 = 32;

// ECS 最大 IPv6 前缀长度
pub const MAX_IPV6_PREFIX_LENGTH: u8 = 128;

//
// 缓存常量
//

// 默认缓存大小（条目数）
pub const DEFAULT_CACHE_SIZE: usize = 10000;

// 默认最小 TTL（秒）
pub const DEFAULT_MIN_TTL: u32 = 60;

// 默认最大 TTL（秒）
pub const DEFAULT_MAX_TTL: u32 = 86400; // 1 天

// 默认负缓存 TTL（秒）
pub const DEFAULT_NEGATIVE_TTL: u32 = 300; // 5 分钟

// 缓存文件魔数，用于识别缓存文件
pub const CACHE_FILE_MAGIC: &str = "OXIDEWDNS_CACHE";

// 缓存文件版本号
pub const CACHE_FILE_VERSION: u64 = 1;

//
// 速率限制常量
//

// 默认每个 IP 每秒最大请求数
pub const DEFAULT_PER_IP_RATE: u32 = 100;

// 每个 IP 每秒最大请求数的最小值
pub const MIN_PER_IP_RATE: u32 = 1;

// 每个 IP 每秒最大请求数的最大值
pub const MAX_PER_IP_RATE: u32 = 1000000; // 100万

// 默认单个 IP 的并发请求数限制
pub const DEFAULT_PER_IP_CONCURRENT: u32 = 10;

// 单个 IP 的并发请求数限制的最小值
pub const MIN_PER_IP_CONCURRENT: u32 = 1;

// 单个 IP 的并发请求数限制的最大值
pub const MAX_PER_IP_CONCURRENT: u32 = 65535; 

//
// 上游服务器常量
//

// 默认查询超时时间（秒）
pub const DEFAULT_QUERY_TIMEOUT: u64 = 30;

//
// HTTP 相关常量
//

// 默认 HTTP 客户端超时时间（秒）
pub const DEFAULT_HTTP_CLIENT_TIMEOUT: u64 = 120;

// 默认 HTTP 客户端连接池空闲超时时间（秒）
pub const DEFAULT_HTTP_CLIENT_POOL_IDLE_TIMEOUT: u64 = 30;

// 默认 HTTP 客户端连接池最大空闲连接数
pub const DEFAULT_HTTP_CLIENT_POOL_MAX_IDLE_CONNECTIONS: u32 = 10;

// 默认 HTTP 客户端 Agent
pub const DEFAULT_HTTP_CLIENT_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36";

// 默认 JSON 内容类型
pub const CONTENT_TYPE_JSON: &str = "application/json";

// DoH JSON 内容类型
pub const CONTENT_TYPE_DNS_JSON: &str = "application/dns-json";

// DoH 二进制消息内容类型
pub const CONTENT_TYPE_DNS_MESSAGE: &str = "application/dns-message";

// IP 代理头字段名
pub const IP_HEADER_NAMES: [&str; 3] = [
    "X-Forwarded-For", 
    "X-Real-IP", 
    "CF-Connecting-IP"
]; 

//
// DoH 路由和格式常量
//

// DoH JSON API 路径
pub const DOH_JSON_API_PATH: &str = "/resolve";

// DoH 标准请求路径 (RFC 8484)
pub const DOH_STANDARD_PATH: &str = "/dns-query";

// DoH JSON格式标识
pub const DOH_FORMAT_JSON: &str = "json";

// DoH 二进制格式标识
pub const DOH_FORMAT_WIRE: &str = "wire"; 

//
// URL规则周期性更新常量
//

// 默认URL规则更新间隔（秒）
pub const DEFAULT_URL_RULE_UPDATE_INTERVAL_SECS: u64 = 3600; // 1小时

// URL规则更新间隔的最小值（秒）
pub const MIN_URL_RULE_UPDATE_INTERVAL_SECS: u64 = 30; // 30秒

// URL规则更新间隔的最大值（秒）
pub const MAX_URL_RULE_UPDATE_INTERVAL_SECS: u64 = 86400 * 7; // 7天
