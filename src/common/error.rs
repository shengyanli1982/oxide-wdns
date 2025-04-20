// src/common/error.rs

// 标准库导入
use std::io;
use std::result;

// 第三方库导入
use thiserror::Error;
use trust_dns_proto::error::ProtoError;
use trust_dns_resolver::error::ResolveError;

/// 应用程序错误类型
#[derive(Debug, Error)]
pub enum AppError {
    /// IO 错误
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// 配置错误
    #[error("Config error: {0}")]
    Config(String),

    /// DNS 解析错误
    #[error("DNS resolve error: {0}")]
    DnsResolve(#[from] ResolveError),
    
    /// DNS 协议错误
    #[error("DNS protocol error: {0}")]
    DnsProto(#[from] ProtoError),
    
    /// 序列化/反序列化错误
    #[error("Serialization error: {0}")]
    Serde(#[from] serde_yaml::Error),
    
    /// HTTP 错误
    #[error("HTTP error: {0}")]
    Http(String),
    
    /// 上游服务器错误
    #[error("Upstream server error: {0}")]
    Upstream(String),
    
    /// 缓存错误
    #[error("Cache error: {0}")]
    Cache(String),
    
    /// 其他错误
    #[error("Other error: {0}")]
    Other(String),
}

/// 结果类型别名
pub type Result<T> = result::Result<T, AppError>; 