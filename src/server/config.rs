// src/server/config.rs

use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;
use serde::{Deserialize, Serialize};
use crate::common::error::{AppError, Result};
use crate::common::consts::{
    // 服务器配置相关常量
    default_listen_addr, DEFAULT_LISTEN_TIMEOUT,
    // 上游服务器相关常量
    DEFAULT_QUERY_TIMEOUT,
    // 缓存相关常量
    DEFAULT_CACHE_ENABLED, DEFAULT_CACHE_SIZE, DEFAULT_MIN_TTL, 
    DEFAULT_MAX_TTL, DEFAULT_NEGATIVE_TTL,
    // 速率限制相关常量
    DEFAULT_PER_IP_RATE, DEFAULT_PER_IP_CONCURRENT,
    // HTTP 客户端相关常量
    DEFAULT_HTTP_CLIENT_TIMEOUT, DEFAULT_HTTP_CLIENT_POOL_IDLE_TIMEOUT,
    DEFAULT_HTTP_CLIENT_POOL_MAX_IDLE_CONNECTIONS, DEFAULT_HTTP_CLIENT_AGENT
};

// 服务器配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    // HTTP 服务器配置
    #[serde(rename = "http_server")]
    pub http: HttpServerConfig,
    
    // DNS 解析器配置
    #[serde(rename = "dns_resolver")]
    pub dns: DnsResolverConfig,
}

// HTTP 服务器配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpServerConfig {
    // 服务器监听地址
    #[serde(default = "default_listen_addr")]
    pub listen_addr: SocketAddr,
    
    // 服务器连接超时（秒）
    #[serde(default = "default_listen_timeout")]
    pub timeout: u64,
    
    // 速率限制配置
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
}

// DNS 解析器配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsResolverConfig {
    // 上游 DNS 服务器配置
    pub upstream: UpstreamConfig,
    
    // HTTP 客户端配置
    #[serde(default)]
    pub http_client: HttpClientConfig,
    
    // 缓存配置
    #[serde(default)]
    pub cache: CacheConfig,
}

// 上游 DNS 服务器配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamConfig {
    // 上游 DNS 服务器列表
    pub resolvers: Vec<ResolverConfig>,
    
    // 是否启用 DNSSEC
    #[serde(default)]
    pub enable_dnssec: bool,
    
    // 查询超时时间（秒）
    #[serde(default = "default_query_timeout")]
    pub query_timeout: u64,
}

// DNS 解析器配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolverConfig {
    // 解析器地址（IP:端口 或 URL）
    pub address: String,
    
    // 解析器协议类型
    #[serde(default = "default_resolver_protocol")]
    pub protocol: ResolverProtocol,
}

// DNS 解析器协议类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ResolverProtocol {
    // UDP 协议
    Udp,
    // TCP 协议
    Tcp,
    // DNS-over-TLS
    Dot,
    // DNS-over-HTTPS
    Doh,
}

// 缓存配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    // 是否启用缓存
    #[serde(default = "default_cache_enabled")]
    pub enabled: bool,
    
    // 缓存大小（条目数）
    #[serde(default = "default_cache_size")]
    pub size: usize,
    
    // TTL 配置
    #[serde(default)]
    pub ttl: TtlConfig,
}

// TTL 配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtlConfig {
    // 最小 TTL（秒）
    #[serde(default = "default_min_ttl")]
    pub min: u32,
    
    // 最大 TTL（秒）
    #[serde(default = "default_max_ttl")]
    pub max: u32,
    
    // 负缓存 TTL（秒）
    #[serde(default = "default_negative_ttl")]
    pub negative: u32,
}

// 速率限制配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    // 是否启用速率限制
    #[serde(default)]
    pub enabled: bool,
    
    // 每个 IP 每秒最大请求数
    #[serde(default = "default_per_ip_rate")]
    pub per_ip_rate: u32,
    
    // 单个 IP 的并发请求数限制
    #[serde(default = "default_per_ip_concurrent")]
    pub per_ip_concurrent: u32,
}

// HTTP 客户端配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpClientConfig {
    // HTTP 客户端超时时间（秒）
    #[serde(default = "default_http_client_timeout")]
    pub timeout: u64,
    
    // 连接池配置
    #[serde(default)]
    pub pool: PoolConfig,
    
    // HTTP 请求相关配置
    #[serde(default)]
    pub request: RequestConfig,
}

// 连接池配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolConfig {
    // 连接池空闲超时时间（秒）
    #[serde(default = "default_http_client_pool_idle_timeout")]
    pub idle_timeout: u64,
    
    // 连接池最大空闲连接数
    #[serde(default = "default_http_client_pool_max_idle_connections")]
    pub max_idle_connections: u32,
}

// HTTP 请求配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestConfig {
    // HTTP 客户端 User-Agent
    #[serde(default = "default_http_client_agent")]
    pub user_agent: String,
    
    // 使用的 IP 代理头字段名列表
    #[serde(default = "default_ip_header_names")]
    pub ip_header_names: Vec<String>,
}

// 默认值函数 - 使用 consts 中定义的常量
fn default_resolver_protocol() -> ResolverProtocol {
    ResolverProtocol::Udp
}

fn default_query_timeout() -> u64 {
    DEFAULT_QUERY_TIMEOUT
}

fn default_cache_enabled() -> bool {
    DEFAULT_CACHE_ENABLED
}

fn default_cache_size() -> usize {
    DEFAULT_CACHE_SIZE
}

fn default_min_ttl() -> u32 {
    DEFAULT_MIN_TTL
}

fn default_max_ttl() -> u32 {
    DEFAULT_MAX_TTL
}

fn default_negative_ttl() -> u32 {
    DEFAULT_NEGATIVE_TTL
}

fn default_per_ip_rate() -> u32 {
    DEFAULT_PER_IP_RATE
}

fn default_per_ip_concurrent() -> u32 {
    DEFAULT_PER_IP_CONCURRENT
}

fn default_listen_timeout() -> u64 {
    DEFAULT_LISTEN_TIMEOUT
}

fn default_http_client_timeout() -> u64 {
    DEFAULT_HTTP_CLIENT_TIMEOUT
}

fn default_http_client_pool_idle_timeout() -> u64 {
    DEFAULT_HTTP_CLIENT_POOL_IDLE_TIMEOUT
}

fn default_http_client_pool_max_idle_connections() -> u32 {
    DEFAULT_HTTP_CLIENT_POOL_MAX_IDLE_CONNECTIONS
}

fn default_http_client_agent() -> String {
    DEFAULT_HTTP_CLIENT_AGENT.to_string()
}

fn default_ip_header_names() -> Vec<String> {
    crate::common::consts::IP_HEADER_NAMES.iter().map(|&s| s.to_string()).collect()
}

impl ServerConfig {
    // 从配置文件加载配置
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let contents = fs::read_to_string(path)
            .map_err(|e| AppError::Config(format!("Failed to read config file: {}", e)))?;
        
        let config: ServerConfig = serde_yaml::from_str(&contents)
            .map_err(|e| AppError::Config(format!("Invalid config file format: {}", e)))?;
        
        Ok(config)
    }
    
    // 获取服务器监听超时时间
    pub fn listen_timeout(&self) -> Duration {
        Duration::from_secs(self.http.timeout)
    }
    
    // 获取上游查询超时时间
    pub fn query_timeout(&self) -> Duration {
        Duration::from_secs(self.dns.upstream.query_timeout)
    }
    
    // 获取 HTTP 客户端超时时间
    pub fn http_client_timeout(&self) -> Duration {
        Duration::from_secs(self.dns.http_client.timeout)
    }
    
    // 获取 HTTP 客户端连接池空闲超时时间
    pub fn http_client_pool_idle_timeout(&self) -> Duration {
        Duration::from_secs(self.dns.http_client.pool.idle_timeout)
    }
    
    // 测试配置的有效性
    pub fn test(&self) -> Result<()> {
        // 检查上游解析器列表
        if self.dns.upstream.resolvers.is_empty() {
            return Err(AppError::Config("No upstream DNS resolvers defined".to_string()));
        }
        
        // 检查上游解析器地址
        for resolver in &self.dns.upstream.resolvers {
            if resolver.address.is_empty() {
                return Err(AppError::Config("Empty resolver address".to_string()));
            }
            
            // 检查 DoH 地址格式
            if resolver.protocol == ResolverProtocol::Doh && !resolver.address.starts_with("https://") {
                return Err(AppError::Config(format!(
                    "DoH resolver address must start with 'https://': {}",
                    resolver.address
                )));
            }
        }
        
        Ok(())
    }
}

impl Default for TtlConfig {
    fn default() -> Self {
        Self {
            min: DEFAULT_MIN_TTL,
            max: DEFAULT_MAX_TTL,
            negative: DEFAULT_NEGATIVE_TTL,
        }
    }
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: DEFAULT_CACHE_ENABLED,
            size: DEFAULT_CACHE_SIZE,
            ttl: TtlConfig::default(),
        }
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            per_ip_rate: DEFAULT_PER_IP_RATE,
            per_ip_concurrent: DEFAULT_PER_IP_CONCURRENT,
        }
    }
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            idle_timeout: DEFAULT_HTTP_CLIENT_POOL_IDLE_TIMEOUT,
            max_idle_connections: DEFAULT_HTTP_CLIENT_POOL_MAX_IDLE_CONNECTIONS,
        }
    }
}

impl Default for RequestConfig {
    fn default() -> Self {
        Self {
            user_agent: DEFAULT_HTTP_CLIENT_AGENT.to_string(),
            ip_header_names: default_ip_header_names(),
        }
    }
}

impl Default for HttpClientConfig {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_HTTP_CLIENT_TIMEOUT,
            pool: PoolConfig::default(),
            request: RequestConfig::default(),
        }
    }
}

impl Default for HttpServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_listen_addr(),
            timeout: DEFAULT_LISTEN_TIMEOUT,
            rate_limit: RateLimitConfig::default(),
        }
    }
}

impl Default for DnsResolverConfig {
    fn default() -> Self {
        Self {
            upstream: UpstreamConfig {
                resolvers: Vec::new(),
                enable_dnssec: false,
                query_timeout: DEFAULT_QUERY_TIMEOUT,
            },
            http_client: HttpClientConfig::default(),
            cache: CacheConfig::default(),
        }
    }
}
