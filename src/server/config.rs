// src/server/config.rs

use serde::{Deserialize, Serialize};
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use crate::common::error::{AppError, Result};

/// 服务器配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// 服务器监听地址
    #[serde(default = "default_listen_addr")]
    pub listen_addr: SocketAddr,
    
    /// TLS 配置
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    
    /// 日志配置
    #[serde(default)]
    pub log: LogConfig,
    
    /// 上游 DNS 服务器配置
    pub upstream: UpstreamConfig,
    
    /// 缓存配置
    #[serde(default)]
    pub cache: CacheConfig,
    
    /// 速率限制配置
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
}

/// TLS 配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// 证书文件路径
    pub cert_path: String,
    
    /// 密钥文件路径
    pub key_path: String,
}

/// 日志配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    /// 日志级别
    #[serde(default = "default_log_level")]
    pub level: String,
    
    /// 是否以 JSON 格式输出
    #[serde(default)]
    pub json: bool,
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

// 默认值函数
fn default_listen_addr() -> SocketAddr {
    "127.0.0.1:3053".parse().unwrap()
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_resolver_protocol() -> ResolverProtocol {
    ResolverProtocol::Udp
}

fn default_query_timeout() -> u64 {
    5
}

fn default_cache_enabled() -> bool {
    true
}

fn default_cache_size() -> usize {
    10000
}

fn default_min_ttl() -> u32 {
    60
}

fn default_max_ttl() -> u32 {
    86400 // 1 day
}

fn default_negative_ttl() -> u32 {
    300 // 5 minutes
}

fn default_per_ip_rate() -> u32 {
    100
}

fn default_per_ip_concurrent() -> u32 {
    10
}

impl ServerConfig {
    /// 从配置文件加载配置
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let contents = fs::read_to_string(path)
            .map_err(|e| AppError::Config(format!("无法读取配置文件: {}", e)))?;
        
        let config: ServerConfig = serde_yaml::from_str(&contents)
            .map_err(|e| AppError::Config(format!("配置文件格式错误: {}", e)))?;
        
        Ok(config)
    }
    
    /// 获取上游查询超时时间
    pub fn query_timeout(&self) -> Duration {
        Duration::from_secs(self.upstream.query_timeout)
    }
    
    /// 测试配置的有效性
    pub fn test(&self) -> Result<()> {
        // 检查上游解析器列表
        if self.upstream.resolvers.is_empty() {
            return Err(AppError::Config("上游解析器列表不能为空".to_string()));
        }
        
        // 验证上游解析器配置
        for (idx, resolver) in self.upstream.resolvers.iter().enumerate() {
            match resolver.protocol {
                ResolverProtocol::Udp | ResolverProtocol::Tcp => {
                    // 验证地址格式
                    if let Err(e) = resolver.address.parse::<SocketAddr>() {
                        return Err(AppError::Config(format!(
                            "上游解析器 #{} 地址无效 ({}): {}",
                            idx + 1, resolver.address, e
                        )));
                    }
                },
                ResolverProtocol::Dot => {
                    // 验证 DoT 格式 (域名@IP:端口)
                    let parts: Vec<&str> = resolver.address.split('@').collect();
                    if parts.len() != 2 {
                        return Err(AppError::Config(format!(
                            "上游解析器 #{} DoT 地址格式错误，应为 '域名@IP:端口': {}",
                            idx + 1, resolver.address
                        )));
                    }
                    
                    if let Err(e) = parts[1].parse::<SocketAddr>() {
                        return Err(AppError::Config(format!(
                            "上游解析器 #{} DoT 地址无效 ({}): {}",
                            idx + 1, parts[1], e
                        )));
                    }
                },
                ResolverProtocol::Doh => {
                    // 验证 DoH URL 格式
                    if !resolver.address.starts_with("https://") {
                        return Err(AppError::Config(format!(
                            "上游解析器 #{} DoH 地址必须以 https:// 开头: {}",
                            idx + 1, resolver.address
                        )));
                    }
                },
            }
        }
        
        // 验证缓存配置
        if self.cache.enabled {
            if self.cache.size == 0 {
                return Err(AppError::Config("缓存大小不能为0".to_string()));
            }
            
            if self.cache.min_ttl > self.cache.max_ttl {
                return Err(AppError::Config(format!(
                    "缓存最小 TTL ({}) 不能大于最大 TTL ({})",
                    self.cache.min_ttl, self.cache.max_ttl
                )));
            }
        }
        
        // 验证速率限制
        if self.rate_limit.enabled {
            if self.rate_limit.per_ip_rate == 0 {
                return Err(AppError::Config("每 IP 速率限制不能为0".to_string()));
            }
            
            if self.rate_limit.per_ip_concurrent == 0 {
                return Err(AppError::Config("每 IP 并发请求数限制不能为0".to_string()));
            }
        }
        
        Ok(())
    }
}

impl Default for LogConfig {
    fn default() -> Self {
        LogConfig {
            level: default_log_level(),
            json: false,
        }
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

// TODO: Implement configuration loading (YAML, Serde)
// TODO: Implement clap for config testing (`-t`) 