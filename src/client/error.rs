// src/client/error.rs

// 使用 thiserror 来定义客户端特定的错误类型
use thiserror::Error;
use std::cmp::PartialEq;
use std::fmt::Debug;

// 客户端操作中可能出现的错误。
#[derive(Error, Debug)]
pub enum ClientError {
    // HTTP 请求错误 (例如，网络问题，服务器错误)
    #[error("HTTP request failed: {0}")]
    ReqwestError(#[from] reqwest::Error), // 使用 #[from] 自动转换 reqwest::Error

    // HTTP 客户端创建错误
    #[error("Failed to create HTTP client: {0}")]
    HttpClientError(String),
    
    // HTTP 服务器错误
    #[error("HTTP error {0}: {1}")]
    HttpError(u16, String),

    // DNS 协议解析/构建错误
    #[error("DNS protocol error: {0}")]
    DnsProtoError(#[from] trust_dns_proto::error::ProtoError),

    // JSON 序列化/反序列化错误
    #[error("JSON processing error: {0}")]
    JsonError(#[from] serde_json::Error),

    // 无效的命令行参数
    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    // 无效的 URL
    #[error("Invalid URL: {0}")]
    UrlError(#[from] url::ParseError),

    // 无效的十六进制格式
    #[error("Invalid hex data: {0}")]
    HexError(#[from] hex::FromHexError),

    // 无效的 DNS 记录类型
    #[error("Invalid DNS record type: {0}")]
    InvalidRecordType(String),
    
    // Base64 编解码错误
    #[error("Base64 error: {0}")]
    Base64Error(#[from] base64::DecodeError),

    // IO 错误 (虽然在这个客户端中可能不太常见，但可以包含)
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    // 验证失败错误
    #[error("DNS response validation failed: {0}")]
    ValidationFailed(String),

    // 其他未分类错误
    #[error("An unexpected error occurred: {0}")]
    Other(String),
}

// 手动实现 PartialEq
// 因为存在多种错误类型，不支持 PartialEq 的自动实现
impl PartialEq for ClientError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::HttpClientError(a), Self::HttpClientError(b)) => a == b,
            (Self::HttpError(code_a, msg_a), Self::HttpError(code_b, msg_b)) => code_a == code_b && msg_a == msg_b,
            (Self::InvalidArgument(a), Self::InvalidArgument(b)) => a == b,
            (Self::UrlError(a), Self::UrlError(b)) => a == b,
            (Self::HexError(a), Self::HexError(b)) => a.to_string() == b.to_string(),
            (Self::InvalidRecordType(a), Self::InvalidRecordType(b)) => a == b,
            (Self::Base64Error(a), Self::Base64Error(b)) => a.to_string() == b.to_string(),
            (Self::ValidationFailed(a), Self::ValidationFailed(b)) => a == b,
            (Self::Other(a), Self::Other(b)) => a == b,
            // 对于不支持 PartialEq 的错误类型，我们通过转换为字符串进行比较
            (Self::ReqwestError(a), Self::ReqwestError(b)) => a.to_string() == b.to_string(),
            (Self::DnsProtoError(a), Self::DnsProtoError(b)) => a.to_string() == b.to_string(),
            (Self::JsonError(a), Self::JsonError(b)) => a.to_string() == b.to_string(),
            (Self::IoError(a), Self::IoError(b)) => a.kind() == b.kind(),
            _ => false,
        }
    }
}

// 手动实现 Clone
// 因为存在多种错误类型，不支持 Clone 的自动实现
impl Clone for ClientError {
    fn clone(&self) -> Self {
        match self {
            Self::HttpClientError(s) => Self::HttpClientError(s.clone()),
            Self::HttpError(code, msg) => Self::HttpError(*code, msg.clone()),
            Self::InvalidArgument(s) => Self::InvalidArgument(s.clone()),
            Self::InvalidRecordType(s) => Self::InvalidRecordType(s.clone()),
            Self::ValidationFailed(s) => Self::ValidationFailed(s.clone()),
            Self::Other(s) => Self::Other(s.clone()),
            // 对于不支持 Clone 的错误类型，我们创建新的类似错误
            Self::ReqwestError(e) => Self::Other(format!("HTTP request failed: {}", e)),
            Self::DnsProtoError(e) => Self::Other(format!("DNS protocol error: {}", e)),
            Self::JsonError(e) => Self::Other(format!("JSON processing error: {}", e)),
            Self::UrlError(e) => Self::Other(format!("Invalid URL: {}", e)),
            Self::HexError(e) => Self::Other(format!("Invalid hex data: {}", e)),
            Self::Base64Error(e) => Self::Other(format!("Base64 error: {}", e)),
            Self::IoError(e) => Self::Other(format!("IO error: {}", e)),
        }
    }
}

// 定义一个 Result 类型别名，方便使用
pub type ClientResult<T> = Result<T, ClientError>; 