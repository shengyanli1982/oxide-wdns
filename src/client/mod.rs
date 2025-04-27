// src/client/mod.rs

/// 声明客户端库的公共模块。
pub mod args;
pub mod error;
pub mod request;
pub mod response;
pub mod core;

// 可以考虑 re-export 关键类型，方便外部使用
// pub use args::CliArgs;
// pub use error::{ClientError, ClientResult};
// pub use core::run_query; 