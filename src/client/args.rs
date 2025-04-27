// src/client/args.rs

/// 使用 clap 定义和解析命令行参数。
/// 该结构体将包含所有从命令行接收到的配置信息，
/// 例如服务器 URL、查询域名、记录类型、请求格式等。

// 依赖: clap = { version = "4", features = ["derive"] }

// use clap::Parser;

// /// DoH 客户端命令行接口
// #[derive(Parser, Debug)]
// #[clap(author, version, about, long_about = None)]
// pub struct CliArgs {
//     /// DoH 服务器的完整 URL (例如: https://localhost:8080/dns-query)
//     #[clap(required = true)]
//     pub server_url: String,
//
//     /// 要查询的域名
//     #[clap(required = true)]
//     pub domain: String,
//
//     /// 指定 DNS 查询类型 (默认: A)
//     #[clap(short, long, value_parser, default_value = "A")]
//     pub record_type: String, // 可以考虑使用枚举 trust_dns_proto::rr::RecordType
//
//     /// 指定 DoH 请求格式 (`json` 或 `wire`)
//     #[clap(long, value_parser, default_value = "wire")]
//     pub format: String, // 可以考虑使用枚举
//
//     /// 指定 HTTP 方法 (`GET` 或 `POST`). 默认会自动选择。
//     #[clap(short = 'X', long, value_parser)]
//     pub method: Option<String>, // 可以考虑使用枚举
//
//     /// 指定首选的 HTTP 版本 (`1.1` 或 `2`)
//     #[clap(long = "http", value_parser)]
//     pub http_version: Option<String>, // 可以考虑使用枚举
//
//     /// 在 DNS 查询中设置 DNSSEC OK (DO) 位
//     #[clap(long)]
//     pub dnssec: bool,
//
//     /// 发送原始 DNS 查询报文 (十六进制编码)。覆盖 <DOMAIN> 和 -t, --type 参数。
//     #[clap(long, value_parser)]
//     pub payload: Option<String>,
//
//     /// 跳过 TLS 证书验证
//     #[clap(short = 'k', long)]
//     pub insecure: bool,
//
//     /// 显示详细的请求和响应信息 (包括 HTTP 头)。多次使用增加详细程度。
//     #[clap(short, long, action = clap::ArgAction::Count)]
//     pub verbose: u8,
// } 