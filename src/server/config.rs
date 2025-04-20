// src/server/config.rs

use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;
use serde::{Deserialize, Serialize};
use crate::common::error::{AppError, Result};
use crate::common::consts::{
    // 服务器配置相关常量
    default_listen_addr, MIN_THREADS, MAX_THREADS, DEFAULT_THREADS, 
    // 上游服务器相关常量
    DEFAULT_QUERY_TIMEOUT,
    // 缓存相关常量
    DEFAULT_CACHE_ENABLED, DEFAULT_CACHE_SIZE, DEFAULT_MIN_TTL, 
    DEFAULT_MAX_TTL, DEFAULT_NEGATIVE_TTL,
    // 速率限制相关常量
    DEFAULT_PER_IP_RATE, DEFAULT_PER_IP_CONCURRENT
};

/// 服务器配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// 服务器监听地址
    #[serde(default = "default_listen_addr")]
    pub listen_addr: SocketAddr,
    
    /// 工作线程数
    #[serde(default = "default_threads")]
    pub threads: usize,
    
    /// 上游 DNS 服务器配置
    pub upstream: UpstreamConfig,
    
    /// 缓存配置
    #[serde(default)]
    pub cache: CacheConfig,
    
    /// 速率限制配置
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
}

/// 上游 DNS 服务器配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamConfig {
    /// 上游 DNS 服务器列表
    pub resolvers: Vec<ResolverConfig>,
    
    /// 是否启用 DNSSEC
    #[serde(default)]
    pub enable_dnssec: bool,
    
    /// 查询超时时间（秒）
    #[serde(default = "default_query_timeout")]
    pub query_timeout: u64,
}

/// DNS 解析器配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolverConfig {
    /// 解析器地址（IP:端口 或 URL）
    pub address: String,
    
    /// 解析器协议类型
    #[serde(default = "default_resolver_protocol")]
    pub protocol: ResolverProtocol,
}

/// DNS 解析器协议类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ResolverProtocol {
    /// UDP 协议
    Udp,
    /// TCP 协议
    Tcp,
    /// DNS-over-TLS
    Dot,
    /// DNS-over-HTTPS
    Doh,
}

/// 缓存配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    /// 是否启用缓存
    #[serde(default = "default_cache_enabled")]
    pub enabled: bool,
    
    /// 缓存大小（条目数）
    #[serde(default = "default_cache_size")]
    pub size: usize,
    
    /// 最小 TTL（秒）
    #[serde(default = "default_min_ttl")]
    pub min_ttl: u32,
    
    /// 最大 TTL（秒）
    #[serde(default = "default_max_ttl")]
    pub max_ttl: u32,
    
    /// 负缓存 TTL（秒）
    #[serde(default = "default_negative_ttl")]
    pub negative_ttl: u32,
}

/// 速率限制配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// 是否启用速率限制
    #[serde(default)]
    pub enabled: bool,
    
    /// 每个 IP 每秒最大请求数
    #[serde(default = "default_per_ip_rate")]
    pub per_ip_rate: u32,
    
    /// 单个 IP 的并发请求数限制
    #[serde(default = "default_per_ip_concurrent")]
    pub per_ip_concurrent: u32,
}

// 默认值函数 - 使用 consts 中定义的常量
fn default_threads() -> usize {
    DEFAULT_THREADS
}

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

impl ServerConfig {
    /// 从配置文件加载配置
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let contents = fs::read_to_string(path)
            .map_err(|e| AppError::Config(format!("Failed to read config file: {}", e)))?;
        
        let config: ServerConfig = serde_yaml::from_str(&contents)
            .map_err(|e| AppError::Config(format!("Invalid config file format: {}", e)))?;
        
        Ok(config)
    }
    
    /// 获取上游查询超时时间
    pub fn query_timeout(&self) -> Duration {
        Duration::from_secs(self.upstream.query_timeout)
    }
    
    /// 测试配置的有效性
    pub fn test(&self) -> Result<()> {
        // 验证线程数范围
        if self.threads < MIN_THREADS || self.threads > MAX_THREADS {
            return Err(AppError::Config(format!(
                "Thread count must be between {}-{}, current value: {}", 
                MIN_THREADS, MAX_THREADS, self.threads
            )));
        }
        
        // 检查上游解析器列表
        if self.upstream.resolvers.is_empty() {
            return Err(AppError::Config("Upstream resolver list cannot be empty".to_string()));
        }
        
        // 验证上游解析器配置
        for (idx, resolver) in self.upstream.resolvers.iter().enumerate() {
            match resolver.protocol {
                ResolverProtocol::Udp | ResolverProtocol::Tcp => {
                    // 验证地址格式
                    if let Err(e) = resolver.address.parse::<SocketAddr>() {
                        return Err(AppError::Config(format!(
                            "Upstream resolver #{} has invalid address ({}): {}",
                            idx + 1, resolver.address, e
                        )));
                    }
                },
                ResolverProtocol::Dot => {
                    // 验证 DoT 格式 (域名@IP:端口)
                    let parts: Vec<&str> = resolver.address.split('@').collect();
                    if parts.len() != 2 {
                        return Err(AppError::Config(format!(
                            "Upstream resolver #{} DoT address format error, should be 'domain@IP:port': {}",
                            idx + 1, resolver.address
                        )));
                    }
                    
                    if let Err(e) = parts[1].parse::<SocketAddr>() {
                        return Err(AppError::Config(format!(
                            "Upstream resolver #{} DoT has invalid address ({}): {}",
                            idx + 1, parts[1], e
                        )));
                    }
                },
                ResolverProtocol::Doh => {
                    // 验证 DoH URL 格式
                    if !resolver.address.starts_with("https://") {
                        return Err(AppError::Config(format!(
                            "Upstream resolver #{} DoH address must start with https://: {}",
                            idx + 1, resolver.address
                        )));
                    }
                },
            }
        }
        
        // 验证缓存配置
        if self.cache.enabled {
            if self.cache.size == 0 {
                return Err(AppError::Config("Cache size cannot be zero".to_string()));
            }
            
            if self.cache.min_ttl > self.cache.max_ttl {
                return Err(AppError::Config(format!(
                    "Cache min TTL ({}) cannot be greater than max TTL ({})",
                    self.cache.min_ttl, self.cache.max_ttl
                )));
            }
        }
        
        // 验证速率限制
        if self.rate_limit.enabled {
            if self.rate_limit.per_ip_rate == 0 {
                return Err(AppError::Config("Per-IP rate limit cannot be zero".to_string()));
            }
            
            if self.rate_limit.per_ip_concurrent == 0 {
                return Err(AppError::Config("Per-IP concurrent requests limit cannot be zero".to_string()));
            }
        }
        
        Ok(())
    }
}

impl Default for CacheConfig {
    fn default() -> Self {
        CacheConfig {
            enabled: default_cache_enabled(),
            size: default_cache_size(),
            min_ttl: default_min_ttl(),
            max_ttl: default_max_ttl(),
            negative_ttl: default_negative_ttl(),
        }
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        RateLimitConfig {
            enabled: false,
            per_ip_rate: default_per_ip_rate(),
            per_ip_concurrent: default_per_ip_concurrent(),
        }
    }
}
