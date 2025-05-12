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
    DEFAULT_CACHE_SIZE, DEFAULT_MIN_TTL, 
    DEFAULT_MAX_TTL, DEFAULT_NEGATIVE_TTL,
    // 速率限制相关常量
    DEFAULT_PER_IP_RATE, DEFAULT_PER_IP_CONCURRENT,
    // HTTP 客户端相关常量
    DEFAULT_HTTP_CLIENT_TIMEOUT, DEFAULT_HTTP_CLIENT_POOL_IDLE_TIMEOUT,
    DEFAULT_HTTP_CLIENT_POOL_MAX_IDLE_CONNECTIONS, DEFAULT_HTTP_CLIENT_AGENT,
    // 分流相关常量
    BLACKHOLE_UPSTREAM_GROUP_NAME,
    // ECS 相关常量
    ECS_POLICY_STRIP, ECS_POLICY_FORWARD, ECS_POLICY_ANONYMIZE,
    DEFAULT_IPV4_PREFIX_LENGTH, DEFAULT_IPV6_PREFIX_LENGTH,
    MAX_IPV4_PREFIX_LENGTH, MAX_IPV6_PREFIX_LENGTH,
    // 添加新常量
    MIN_PER_IP_RATE,
    MAX_PER_IP_RATE,
    MIN_PER_IP_CONCURRENT,
    MAX_PER_IP_CONCURRENT,
    // URL规则周期性更新相关常量
    DEFAULT_URL_RULE_UPDATE_INTERVAL_SECS,
    MIN_URL_RULE_UPDATE_INTERVAL_SECS,
    MAX_URL_RULE_UPDATE_INTERVAL_SECS,
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
    
    // EDNS 客户端子网配置
    #[serde(default)]
    pub ecs_policy: EcsPolicyConfig,
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
    #[serde(default = "default_disable")]
    pub enabled: bool,
    
    // 缓存大小（条目数）
    #[serde(default = "default_cache_size")]
    pub size: usize,
    
    // TTL 配置
    #[serde(default)]
    pub ttl: TtlConfig,

    // 持久化缓存配置
    #[serde(default)]
    pub persistence: PersistenceCacheConfig,
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
    #[serde(default = "default_disable")]
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
    #[serde(default = "default_disable")]
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
    
    // 上游组级别的 ECS 策略配置（覆盖全局设置）
    #[serde(default)]
    pub ecs_policy: Option<EcsPolicyConfig>,
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
    
    // 周期性更新配置（用于url类型）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub periodic: Option<PeriodicUpdateConfig>,
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

// 持久化缓存配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceCacheConfig {
    // 是否启用缓存持久化功能
    #[serde(default = "default_disable")]
    pub enabled: bool,
    
    // 缓存文件的存储路径
    #[serde(default = "default_cache_persistence_path")]
    pub path: String,
    
    // 服务启动时是否自动加载缓存
    #[serde(default = "default_cache_load_on_startup")]
    pub load_on_startup: bool,
    
    // 保存到磁盘的最大缓存条目数
    #[serde(default)]
    pub max_items_to_save: usize,
    
    // 加载时是否跳过已过期条目
    #[serde(default = "default_cache_skip_expired_on_load")]
    pub skip_expired_on_load: bool,
    
    // 关机时保存缓存的超时时间（秒）
    #[serde(default = "default_cache_shutdown_save_timeout")]
    pub shutdown_save_timeout_secs: u64,
    
    // 周期性保存配置
    #[serde(default)]
    pub periodic: PeriodicSaveConfig,
}

// 周期性保存配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeriodicSaveConfig {
    // 是否启用周期性保存
    #[serde(default = "default_disable")]
    pub enabled: bool,
    
    // 保存间隔（秒）
    #[serde(default = "default_cache_periodic_interval_secs")]
    pub interval_secs: u64,
}

// EDNS 客户端子网策略配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcsPolicyConfig {
    // 是否启用 ECS 处理策略
    #[serde(default = "default_disable")]
    pub enabled: bool,
    
    // 全局 ECS 处理策略
    #[serde(default = "default_ecs_strategy")]
    pub strategy: String,
    
    // 匿名化配置
    #[serde(default)]
    pub anonymization: EcsAnonymizationConfig,
}

// EDNS 客户端子网匿名化配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcsAnonymizationConfig {
    // IPv4 地址匿名化保留前缀长度
    #[serde(default = "default_ipv4_prefix_length")]
    pub ipv4_prefix_length: u8,
    
    // IPv6 地址匿名化保留前缀长度
    #[serde(default = "default_ipv6_prefix_length")]
    pub ipv6_prefix_length: u8,
}

// URL规则周期性更新配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeriodicUpdateConfig {
    // 是否启用周期性更新
    #[serde(default)]
    pub enabled: bool,
    
    // 更新间隔（秒）
    #[serde(default = "default_url_rule_update_interval")]
    pub interval_secs: u64,
}

// 默认值函数 - 使用 consts 中定义的常量
fn default_resolver_protocol() -> ResolverProtocol {
    ResolverProtocol::Udp
}

fn default_query_timeout() -> u64 {
    DEFAULT_QUERY_TIMEOUT
}

fn default_disable() -> bool {
    false
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

// 默认缓存持久化路径
fn default_cache_persistence_path() -> String {
    "./cache.dat".to_string()
}

// 默认启动时加载缓存
fn default_cache_load_on_startup() -> bool {
    true
}

// 默认加载时跳过已过期条目
fn default_cache_skip_expired_on_load() -> bool {
    true
}

// 默认周期性保存间隔
fn default_cache_periodic_interval_secs() -> u64 {
    3600  // 1小时
}

// 默认关机保存超时
fn default_cache_shutdown_save_timeout() -> u64 {
    30  // 30秒
}

// 默认 ECS 策略为剥离
fn default_ecs_strategy() -> String {
    ECS_POLICY_STRIP.to_string()
}

// 默认 IPv4 匿名化前缀长度
fn default_ipv4_prefix_length() -> u8 {
    DEFAULT_IPV4_PREFIX_LENGTH
}

// 默认 IPv6 匿名化前缀长度
fn default_ipv6_prefix_length() -> u8 {
    DEFAULT_IPV6_PREFIX_LENGTH
}

// 默认URL规则更新间隔
fn default_url_rule_update_interval() -> u64 {
    DEFAULT_URL_RULE_UPDATE_INTERVAL_SECS
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
    
    // 获取特定上游组的有效 ECS 策略配置
    pub fn get_effective_ecs_policy(&self, group_name: &str) -> Result<EcsPolicyConfig> {
        // 如果指定了组名，尝试查找该组
        if !group_name.is_empty() && group_name != BLACKHOLE_UPSTREAM_GROUP_NAME {
            if let Some(group) = self.dns.routing.upstream_groups
                .iter()
                .find(|g| g.name == group_name) {
                // 如果组存在且指定了 ECS 策略，则使用组策略
                if let Some(ecs_policy) = &group.ecs_policy {
                    return Ok(ecs_policy.clone());
                }
            }
        }
        
        // 否则使用全局 ECS 策略
        Ok(self.dns.ecs_policy.clone())
    }
    
    // 验证配置有效性
    pub fn test(&self) -> Result<()> {
        // 验证速率限制配置
        self.validate_rate_limit()?;
        
        // 验证缓存持久化依赖链
        self.validate_cache_dependencies()?;
        
        // 验证全局解析器地址
        self.validate_resolvers(&self.dns.upstream.resolvers)?;
        
        // 验证上游组 ECS 策略与路由功能的依赖关系
        self.validate_routing_ecs_dependencies()?;
        
        // 验证路由配置
        self.validate_routing()?;
        
        // 验证 ECS 策略配置
        self.validate_ecs_policy()?;
        
        Ok(())
    }
    
    // 验证速率限制配置
    fn validate_rate_limit(&self) -> Result<()> {
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
        Ok(())
    }
    
    // 验证缓存持久化依赖链
    fn validate_cache_dependencies(&self) -> Result<()> {
        // 验证持久化缓存依赖于缓存本身
        if self.dns.cache.persistence.enabled && !self.dns.cache.enabled {
            return Err(ServerError::Config(
                "Cache persistence is enabled but cache itself is disabled. Enable cache first.".to_string()
            ));
        }
        
        // 验证周期性保存依赖于持久化缓存
        if self.dns.cache.persistence.periodic.enabled && !self.dns.cache.persistence.enabled {
            return Err(ServerError::Config(
                "Periodic cache persistence is enabled but persistence itself is disabled. Enable persistence first.".to_string()
            ));
        }
        
        Ok(())
    }
    
    // 验证解析器地址配置
    fn validate_resolvers(&self, resolvers: &[ResolverConfig]) -> Result<()> {
        for resolver in resolvers {
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
        Ok(())
    }
    
    // 验证上游组 ECS 策略与路由功能的依赖关系
    fn validate_routing_ecs_dependencies(&self) -> Result<()> {
        let mut has_enabled_group_ecs_policy = false;
        for group in &self.dns.routing.upstream_groups {
            if let Some(ecs_policy) = &group.ecs_policy {
                if ecs_policy.enabled {
                    has_enabled_group_ecs_policy = true;
                    break;
                }
            }
        }
        
        if has_enabled_group_ecs_policy && !self.dns.routing.enabled {
            return Err(ServerError::Config(
                "One or more upstream groups have ECS policy enabled, but routing is disabled. Enable routing first.".to_string()
            ));
        }
        
        Ok(())
    }
    
    // 验证路由配置
    fn validate_routing(&self) -> Result<()> {
        // 如果路由功能未启用，则直接返回
        if !self.dns.routing.enabled {
            return Ok(());
        }
        
        // 验证上游组配置
        let group_names = self.validate_upstream_groups()?;
        
        // 验证规则配置
        self.validate_routing_rules(&group_names)?;
        
        // 验证默认上游组
        self.validate_default_upstream_group(&group_names)?;
        
        Ok(())
    }
    
    // 验证上游组配置
    fn validate_upstream_groups(&self) -> Result<std::collections::HashSet<String>> {
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
            self.validate_resolvers(&group.resolvers)?;
        }
        
        Ok(group_names)
    }
    
    // 验证路由规则配置
    fn validate_routing_rules(&self, group_names: &std::collections::HashSet<String>) -> Result<()> {
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
            
            // 验证匹配条件
            self.validate_match_condition(&rule.match_, rule_index)?;
        }
        
        Ok(())
    }
    
    // 验证匹配条件
    fn validate_match_condition(&self, match_: &MatchCondition, rule_index: usize) -> Result<()> {
        match match_.type_ {
            MatchType::Exact => {
                if match_.values.is_none() {
                    return Err(ServerError::Config(format!(
                        "规则[{}]：Exact 类型的匹配条件需要提供 'values' 数组",
                        rule_index
                    )));
                }
            }
            MatchType::Regex => {
                if match_.values.is_none() {
                    return Err(ServerError::Config(format!(
                        "规则[{}]：Regex 类型的匹配条件需要提供 'values' 数组",
                        rule_index
                    )));
                }
                // 尝试编译正则表达式，验证其有效性
                if let Some(ref values) = match_.values {
                    for (i, pattern) in values.iter().enumerate() {
                        if let Err(e) = regex::Regex::new(pattern) {
                            return Err(ServerError::Config(format!(
                                "规则[{}]：Regex 模式 [{}] '{}' 无效：{}",
                                rule_index, i, pattern, e
                            )));
                        }
                    }
                }
            }
            MatchType::Wildcard => {
                if match_.values.is_none() {
                    return Err(ServerError::Config(format!(
                        "规则[{}]：Wildcard 类型的匹配条件需要提供 'values' 数组",
                        rule_index
                    )));
                }
            }
            MatchType::File => {
                if match_.path.is_none() {
                    return Err(ServerError::Config(format!(
                        "规则[{}]：File 类型的匹配条件需要提供 'path' 文件路径",
                        rule_index
                    )));
                }
                // 检查文件是否存在且可读
                if let Some(ref path) = match_.path {
                    let path = Path::new(path);
                    if !path.exists() {
                        return Err(ServerError::Config(format!(
                            "规则[{}]：File 类型的路径 '{}' 不存在",
                            rule_index, path.display()
                        )));
                    }
                    if !path.is_file() {
                        return Err(ServerError::Config(format!(
                            "规则[{}]：File 类型的路径 '{}' 不是一个文件",
                            rule_index, path.display()
                        )));
                    }
                    // 尝试读取文件，验证其可访问性
                    if let Err(e) = fs::read_to_string(path) {
                        return Err(ServerError::Config(format!(
                            "规则[{}]：无法读取 File 类型的文件 '{}': {}",
                            rule_index, path.display(), e
                        )));
                    }
                }
            }
            MatchType::Url => {
                if match_.url.is_none() {
                    return Err(ServerError::Config(format!(
                        "规则[{}]：Url 类型的匹配条件需要提供 'url' 地址",
                        rule_index
                    )));
                }
                // 检查 URL 是否有效
                if let Some(ref url) = match_.url {
                    if let Err(e) = url::Url::parse(url) {
                        return Err(ServerError::Config(format!(
                            "规则[{}]：Url 类型的 URL '{}' 无效：{}",
                            rule_index, url, e
                        )));
                    }
                }
                
                // 验证周期性更新配置（如果存在）
                if let Some(ref periodic) = match_.periodic {
                    if periodic.enabled {
                        // 验证更新间隔是否在合理范围内
                        if periodic.interval_secs < MIN_URL_RULE_UPDATE_INTERVAL_SECS {
                            return Err(ServerError::Config(format!(
                                "规则[{}]：Url 类型的周期性更新间隔 {} 秒小于最小允许值 {} 秒",
                                rule_index, periodic.interval_secs, MIN_URL_RULE_UPDATE_INTERVAL_SECS
                            )));
                        }
                        if periodic.interval_secs > MAX_URL_RULE_UPDATE_INTERVAL_SECS {
                            return Err(ServerError::Config(format!(
                                "规则[{}]：Url 类型的周期性更新间隔 {} 秒大于最大允许值 {} 秒",
                                rule_index, periodic.interval_secs, MAX_URL_RULE_UPDATE_INTERVAL_SECS
                            )));
                        }
                    }
                }
            }
        }
        
        Ok(())
    }
    
    // 验证默认上游组配置
    fn validate_default_upstream_group(&self, group_names: &std::collections::HashSet<String>) -> Result<()> {
        if let Some(default_group) = &self.dns.routing.default_upstream_group {
            if !group_names.contains(default_group) {
                return Err(ServerError::Config(format!(
                    "Default upstream group does not exist: {}", 
                    default_group
                )));
            }
        }
        
        Ok(())
    }
    
    // 验证 ECS 策略配置有效性
    pub fn validate_ecs_policy(&self) -> Result<()> {
        // 验证全局 ECS 策略
        self.validate_single_ecs_policy(&self.dns.ecs_policy)?;
        
        // 验证每个上游组的 ECS 策略
        for group in &self.dns.routing.upstream_groups {
            if let Some(ecs_policy) = &group.ecs_policy {
                self.validate_single_ecs_policy(ecs_policy)?;
            }
        }
        
        Ok(())
    }
    
    // 验证单个 ECS 策略配置
    fn validate_single_ecs_policy(&self, policy: &EcsPolicyConfig) -> Result<()> {
        // 如果 ECS 策略未启用，则不需要验证其他参数
        if !policy.enabled {
            return Ok(());
        }
        
        // 验证策略类型
        match policy.strategy.as_str() {
            ECS_POLICY_STRIP | ECS_POLICY_FORWARD | ECS_POLICY_ANONYMIZE => {}
            strategy => return Err(ServerError::Config(format!(
                "Invalid ECS policy type: {}, supported values are: {}, {}, {}",
                strategy, ECS_POLICY_STRIP, ECS_POLICY_FORWARD, ECS_POLICY_ANONYMIZE
            ))),
        }
        
        // 验证 IPv4 前缀长度
        if policy.anonymization.ipv4_prefix_length == 0 || policy.anonymization.ipv4_prefix_length > MAX_IPV4_PREFIX_LENGTH {
            return Err(ServerError::Config(format!(
                "Invalid IPv4 prefix length: {}, valid range: 1-{}",
                policy.anonymization.ipv4_prefix_length, MAX_IPV4_PREFIX_LENGTH
            )));
        }
        
        // 验证 IPv6 前缀长度
        if policy.anonymization.ipv6_prefix_length == 0 || policy.anonymization.ipv6_prefix_length > MAX_IPV6_PREFIX_LENGTH {
            return Err(ServerError::Config(format!(
                "Invalid IPv6 prefix length: {}, valid range: 1-{}",
                policy.anonymization.ipv6_prefix_length, MAX_IPV6_PREFIX_LENGTH
            )));
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
            enabled: false,
            size: DEFAULT_CACHE_SIZE,
            ttl: TtlConfig::default(),
            persistence: PersistenceCacheConfig::default(),
        }
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: false,
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
            ecs_policy: EcsPolicyConfig::default(),
        }
    }
}

impl Default for PersistenceCacheConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: default_cache_persistence_path(),
            load_on_startup: default_cache_load_on_startup(),
            max_items_to_save: 0,
            skip_expired_on_load: default_cache_skip_expired_on_load(),
            shutdown_save_timeout_secs: default_cache_shutdown_save_timeout(),
            periodic: PeriodicSaveConfig::default(),
        }
    }
}

impl Default for PeriodicSaveConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: default_cache_periodic_interval_secs(),
        }
    }
}

impl Default for EcsAnonymizationConfig {
    fn default() -> Self {
        Self {
            ipv4_prefix_length: DEFAULT_IPV4_PREFIX_LENGTH,
            ipv6_prefix_length: DEFAULT_IPV6_PREFIX_LENGTH,
        }
    }
}

impl Default for EcsPolicyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            strategy: ECS_POLICY_STRIP.to_string(),
            anonymization: EcsAnonymizationConfig::default(),
        }
    }
}

impl Default for PeriodicUpdateConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: DEFAULT_URL_RULE_UPDATE_INTERVAL_SECS,
        }
    }
}

