// src/client/error.rs

// 使用 thiserror 来定义客户端特定的错误类型
use thiserror::Error;

/// 客户端操作中可能出现的错误。
#[derive(Error, Debug)]
pub enum ClientError {
    /// HTTP 请求错误 (例如，网络问题，服务器错误)
    #[error("HTTP request failed: {0}")]
    ReqwestError(#[from] reqwest::Error), // 使用 #[from] 自动转换 reqwest::Error

    /// HTTP 客户端创建错误
    #[error("Failed to create HTTP client: {0}")]
    HttpClientError(String),
    
    /// HTTP 服务器错误
    #[error("HTTP error {0}: {1}")]
    HttpError(u16, String),

    /// DNS 协议解析/构建错误
    #[error("DNS protocol error: {0}")]
    DnsProtoError(#[from] trust_dns_proto::error::ProtoError),

    /// JSON 序列化/反序列化错误
    #[error("JSON processing error: {0}")]
    JsonError(#[from] serde_json::Error),

    /// 无效的命令行参数
    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    /// 无效的 URL
    #[error("Invalid URL: {0}")]
    UrlError(#[from] url::ParseError),

    /// 无效的十六进制格式
    #[error("Invalid hex data: {0}")]
    HexError(#[from] hex::FromHexError),

    /// 无效的 DNS 记录类型
    #[error("Invalid DNS record type: {0}")]
    InvalidRecordType(String),
    
    /// Base64 编解码错误
    #[error("Base64 error: {0}")]
    Base64Error(#[from] base64::DecodeError),

    /// IO 错误 (虽然在这个客户端中可能不太常见，但可以包含)
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// 其他未分类错误
    #[error("An unexpected error occurred: {0}")]
    Other(String),
}

// 定义一个 Result 类型别名，方便使用
pub type ClientResult<T> = Result<T, ClientError>; 