// src/server/config.rs

use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;
use serde::{Deserialize, Serialize};
use crate::server::error::{ServerError, Result};
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
    DEFAULT_HTTP_CLIENT_POOL_MAX_IDLE_CONNECTIONS, DEFAULT_HTTP_CLIENT_AGENT,
    // 分流相关常量
    BLACKHOLE_UPSTREAM_GROUP_NAME,
    // 添加新常量
    MIN_PER_IP_RATE,
    MAX_PER_IP_RATE,
    MIN_PER_IP_CONCURRENT,
    MAX_PER_IP_CONCURRENT,
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
    // 上游 DNS 服务器配置（全局/默认）
    pub upstream: UpstreamConfig,
    
    // HTTP 客户端配置
    #[serde(default)]
    pub http_client: HttpClientConfig,
    
    // 缓存配置
    #[serde(default)]
    pub cache: CacheConfig,
    
    // 路由配置（DNS分流）
    #[serde(default)]
    pub routing: RoutingConfig,
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

// 路由配置（DNS分流）
#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Default)]
pub struct RoutingConfig {
    // 是否启用DNS分流
    #[serde(default)]
    pub enabled: bool,
    
    // 上游DNS服务器组
    #[serde(default)]
    pub upstream_groups: Vec<UpstreamGroup>,
    
    // 分流规则
    #[serde(default)]
    pub rules: Vec<Rule>,
    
    // 默认上游组名称（如果未匹配任何规则）
    #[serde(default)]
    pub default_upstream_group: Option<String>,
}

// 上游DNS服务器组
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamGroup {
    // 组名称
    pub name: String,
    
    // 是否启用DNSSEC（覆盖全局设置）
    pub enable_dnssec: Option<bool>,
    
    // 查询超时时间（覆盖全局设置）
    pub query_timeout: Option<u64>,
    
    // 解析器列表
    pub resolvers: Vec<ResolverConfig>,
}

// 分流规则
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    // 匹配条件
    #[serde(rename = "match")]
    pub match_: MatchCondition,
    
    // 目标上游组名称
    pub upstream_group: String,
}

// 匹配条件
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchCondition {
    // 匹配类型
    #[serde(rename = "type")]
    pub type_: MatchType,
    
    // 匹配值（根据类型可能是域名列表、路径或URL）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
    
    // 文件路径（用于file类型）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    
    // URL（用于url类型）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

// 匹配类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum MatchType {
    // 精确匹配
    #[default]
    Exact,
    // 正则表达式匹配
    Regex,
    // 通配符匹配
    Wildcard,
    // 文件匹配
    File,
    // URL匹配
    Url,
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
        let config_str = fs::read_to_string(path)
            .map_err(|e| ServerError::Config(format!("Failed to read config file: {}", e)))?;
            
        let config: ServerConfig = serde_yaml::from_str(&config_str)
            .map_err(|e| ServerError::Config(format!("Failed to parse config: {}", e)))?;
            
        // 验证配置
        config.test()?;
        
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
    
    // 获取上游组的有效配置（包含继承和覆盖）
    pub fn get_effective_upstream_config(&self, group_name: &str) -> Result<UpstreamConfig> {
        // 如果是黑洞，返回错误，因为黑洞不应该被用于实际查询
        if group_name == BLACKHOLE_UPSTREAM_GROUP_NAME {
            return Err(ServerError::UpstreamGroupNotFound(format!(
                "Cannot get effective config for blackhole group: {}", 
                BLACKHOLE_UPSTREAM_GROUP_NAME
            )));
        }
        
        // 查找指定的上游组
        if let Some(group) = self.dns.routing.upstream_groups.iter().find(|g| g.name == group_name) {
            // 创建新的配置，继承全局配置并应用组特定的覆盖
            let mut config = self.dns.upstream.clone();
            
            // 覆盖解析器列表
            config.resolvers = group.resolvers.clone();
            
            // 可选地覆盖其他设置
            if let Some(enable_dnssec) = group.enable_dnssec {
                config.enable_dnssec = enable_dnssec;
            }
            
            if let Some(query_timeout) = group.query_timeout {
                config.query_timeout = query_timeout;
            }
            
            Ok(config)
        } else {
            Err(ServerError::UpstreamGroupNotFound(format!(
                "Upstream group not found: {}", 
                group_name
            )))
        }
    }
    
    pub fn test(&self) -> Result<()> {
        // 验证速率限制配置
        if self.http.rate_limit.enabled {
            // 验证每个 IP 每秒最大请求数
            if self.http.rate_limit.per_ip_rate < MIN_PER_IP_RATE || self.http.rate_limit.per_ip_rate > MAX_PER_IP_RATE {
                return Err(ServerError::Config(format!(
                    "Invalid per_ip_rate: {} (must be between {} and {})",
                    self.http.rate_limit.per_ip_rate, MIN_PER_IP_RATE, MAX_PER_IP_RATE
                )));
            }
            
            // 验证单个 IP 的并发请求数限制
            if self.http.rate_limit.per_ip_concurrent < MIN_PER_IP_CONCURRENT || self.http.rate_limit.per_ip_concurrent > MAX_PER_IP_CONCURRENT {
                return Err(ServerError::Config(format!(
                    "Invalid per_ip_concurrent: {} (must be between {} and {})",
                    self.http.rate_limit.per_ip_concurrent, MIN_PER_IP_CONCURRENT, MAX_PER_IP_CONCURRENT
                )));
            }
        }
        
        // 验证解析器地址
        for resolver in &self.dns.upstream.resolvers {
            match resolver.protocol {
                ResolverProtocol::Doh => {
                    // 验证 DoH 地址是有效的 URL
                    if !resolver.address.starts_with("https://") {
                        return Err(ServerError::Config(format!(
                            "DoH resolver address must start with 'https://': {}", 
                            resolver.address
                        )));
                    }
                },
                ResolverProtocol::Dot => {
                    // 验证 DoT 地址格式 (域名@IP:端口)
                    if !resolver.address.contains('@') || !resolver.address.contains(':') {
                        return Err(ServerError::Config(format!(
                            "DoT resolver address must be in format 'domain@ip:port': {}", 
                            resolver.address
                        )));
                    }
                },
                _ => {
                    // 验证 UDP/TCP 地址格式 (IP:端口)
                    if !resolver.address.contains(':') {
                        return Err(ServerError::Config(format!(
                            "Resolver address must be in format 'ip:port': {}", 
                            resolver.address
                        )));
                    }
                }
            }
        }
        
        // 如果启用了路由功能，验证路由配置
        if self.dns.routing.enabled {
            // 创建上游组名称集合，用于后续验证
            let mut group_names = std::collections::HashSet::new();
            for group in &self.dns.routing.upstream_groups {
                // 检查组名不为空
                if group.name.is_empty() {
                    return Err(ServerError::Config("Upstream group name cannot be empty".to_string()));
                }
                
                // 检查组名不重复
                if !group_names.insert(group.name.clone()) {
                    return Err(ServerError::Config(format!(
                        "Duplicate upstream group name: {}", 
                        group.name
                    )));
                }
                
                // 检查组中至少有一个解析器
                if group.resolvers.is_empty() {
                    return Err(ServerError::Config(format!(
                        "Upstream group '{}' must have at least one resolver", 
                        group.name
                    )));
                }
                
                // 验证解析器配置
                for resolver in &group.resolvers {
                    match resolver.protocol {
                        ResolverProtocol::Doh => {
                            // 验证 DoH 地址是有效的 URL
                            if !resolver.address.starts_with("https://") {
                                return Err(ServerError::Config(format!(
                                    "DoH resolver address must start with 'https://': {}", 
                                    resolver.address
                                )));
                            }
                        },
                        ResolverProtocol::Dot => {
                            // 验证 DoT 地址格式 (域名@IP:端口)
                            if !resolver.address.contains('@') || !resolver.address.contains(':') {
                                return Err(ServerError::Config(format!(
                                    "DoT resolver address must be in format 'domain@ip:port': {}", 
                                    resolver.address
                                )));
                            }
                        },
                        _ => {
                            // 验证 UDP/TCP 地址格式 (IP:端口)
                            if !resolver.address.contains(':') {
                                return Err(ServerError::Config(format!(
                                    "Resolver address must be in format 'ip:port': {}", 
                                    resolver.address
                                )));
                            }
                        }
                    }
                }
            }
            
            // 验证规则配置
            for (i, rule) in self.dns.routing.rules.iter().enumerate() {
                // 获取规则索引（从1开始，用于错误消息）
                let rule_index = i + 1;
                
                // 验证上游组名称存在于上游组列表中或为黑洞特殊值
                if rule.upstream_group != BLACKHOLE_UPSTREAM_GROUP_NAME && !group_names.contains(&rule.upstream_group) {
                    return Err(ServerError::Config(format!(
                        "Rule #{} references unknown upstream group: {}", 
                        rule_index,
                        rule.upstream_group
                    )));
                }
                
                // 验证匹配条件基于类型
                match rule.match_.type_ {
                    MatchType::Exact | MatchType::Regex | MatchType::Wildcard => {
                        // 这些类型需要 values 字段
                        if rule.match_.values.is_none() || rule.match_.values.as_ref().unwrap().is_empty() {
                            return Err(ServerError::Config(format!(
                                "Rule #{} with type {:?} must have non-empty 'values' list", 
                                rule_index,
                                rule.match_.type_
                            )));
                        }
                        
                        // 对于正则表达式类型，验证每个正则表达式的有效性
                        if rule.match_.type_ == MatchType::Regex {
                            for (j, pattern) in rule.match_.values.as_ref().unwrap().iter().enumerate() {
                                match regex::Regex::new(pattern) {
                                    Ok(_) => {}, // 正则表达式有效
                                    Err(e) => {
                                        return Err(ServerError::Config(format!(
                                            "Rule #{} has invalid regex at index {}: '{}' - Error: {}", 
                                            rule_index, j, pattern, e
                                        )));
                                    }
                                }
                            }
                        }
                    },
                    MatchType::File => {
                        // File 类型需要 path 字段
                        if rule.match_.path.is_none() || rule.match_.path.as_ref().unwrap().is_empty() {
                            return Err(ServerError::Config(format!(
                                "Rule #{} with type File must have non-empty 'path' value", 
                                rule_index
                            )));
                        }
                    },
                    MatchType::Url => {
                        // Url 类型需要 url 字段，且必须是有效的URL
                        if rule.match_.url.is_none() || rule.match_.url.as_ref().unwrap().is_empty() {
                            return Err(ServerError::Config(format!(
                                "Rule #{} with type Url must have non-empty 'url' value", 
                                rule_index
                            )));
                        }
                        
                        // 验证URL格式
                        let url_str = rule.match_.url.as_ref().unwrap();
                        if !url_str.starts_with("http://") && !url_str.starts_with("https://") {
                            return Err(ServerError::Config(format!(
                                "Rule #{} has invalid URL format (must start with http:// or https://): {}", 
                                rule_index,
                                url_str
                            )));
                        }
                    },
                }
            }
            
            // 验证默认上游组（如果设置）存在于上游组列表中
            if let Some(default_group) = &self.dns.routing.default_upstream_group {
                if !group_names.contains(default_group) {
                    return Err(ServerError::Config(format!(
                        "Default upstream group does not exist: {}", 
                        default_group
                    )));
                }
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
            routing: RoutingConfig::default(),
        }
    }
}

