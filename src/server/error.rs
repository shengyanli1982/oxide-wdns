// src/server/error.rs

use std::io;
use std::result;
use thiserror::Error;
use hickory_proto::error::ProtoError;
use hickory_resolver::error::ResolveError;

// 服务器错误类型
#[derive(Debug, Error)]
pub enum ServerError {
    // IO 错误
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    // 配置错误
    #[error("Config error: {0}")]
    Config(String),

    // DNS 解析错误
    #[error("DNS resolve error: {0}")]
    DnsResolve(#[from] ResolveError),
    
    // DNS 协议错误
    #[error("DNS protocol error: {0}")]
    DnsProto(#[from] ProtoError),
    
    // 序列化/反序列化错误
    #[error("Serialization error: {0}")]
    Serde(#[from] serde_yaml::Error),
    
    // HTTP 错误
    #[error("HTTP error: {0}")]
    Http(String),
    
    // 上游服务器错误
    #[error("Upstream server error: {0}")]
    Upstream(String),
    
    // 缓存错误
    #[error("Cache error: {0}")]
    Cache(String),
    
    // 规则加载错误
    #[error("Rule load error: {0}")]
    RuleLoad(String),
    
    // 规则获取错误
    #[error("Rule fetch error: {0}")]
    RuleFetch(String),
    
    // 无效规则格式
    #[error("Invalid rule format: {0}")]
    InvalidRuleFormat(String),
    
    // 正则表达式编译错误
    #[error("Regex compilation error: {0}")]
    RegexCompilation(String),
    
    // 上游组未找到
    #[error("Upstream group not found: {0}")]
    UpstreamGroupNotFound(String),
    
    // 无效查询
    #[error("Invalid query: {0}")]
    InvalidQuery(String),
    
    // 其他错误
    #[error("Other error: {0}")]
    Other(String),
}

// 结果类型别名
pub type Result<T> = result::Result<T, ServerError>;