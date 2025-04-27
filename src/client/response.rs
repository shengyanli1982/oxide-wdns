// src/client/response.rs

/// 该模块负责处理来自 DoH 服务器的响应。
///
/// 主要职责:
/// 1. 从 `reqwest::Response` 中提取响应体。
/// 2. 检查 HTTP 状态码和 `Content-Type` Header，判断响应是否成功以及格式 (Wireformat/JSON)。
/// 3. 根据 `Content-Type` 解析响应体：
///    - Wireformat (`application/dns-message`): 使用 `trust-dns-proto` 解析为 `Message`。
///    - JSON (`application/dns-json`): 使用 `serde_json` 解析为相应的结构体 (可能需要定义，或者直接用 `trust-dns-proto` 的 JSON 支持)。
/// 4. 将解析后的 DNS 响应 (`Message` 或等效结构) 以用户友好的格式打印到控制台。
///    - 显示查询耗时。
///    - 显示响应状态码 (RCODE)。
///    - 列出 Answer, Authority, Additional sections 中的记录。
///    - 如果设置了 verbose 标志 (`args.verbose > 0`)，则显示更详细的信息，例如：
///        - 完整的 HTTP 响应头。
///        - 原始的 DNS 响应报文 (十六进制或 Base64)。
/// 5. 清晰地报告解析或处理过程中的任何错误。

// 依赖: reqwest, trust-dns-proto, serde_json (如果支持 JSON), tokio (用于 async read)

// use crate::client::error::{ClientError, ClientResult};
// use std::time::Duration;
// use trust_dns_proto::op::Message;
//
// /// 解析 DoH 响应
// pub async fn parse_doh_response(response: reqwest::Response) -> ClientResult<Message> {
//     // 1. 检查状态码和 Content-Type
//     // let status = response.status();
//     // let content_type = response.headers().get(reqwest::header::CONTENT_TYPE).map(|v| v.to_str().unwrap_or(""));
//     //
//     // if !status.is_success() {
//     //     // 处理 HTTP 错误
//     // }
//
//     // 2. 读取响应体
//     // let body = response.bytes().await?;
//
//     // 3. 根据 Content-Type 解析
//     // match content_type {
//     //     Some("application/dns-message") => {
//     //         // 解析 Wireformat
//     //         // Message::from_vec(&body).map_err(ClientError::DnsProtoError)
//     //     }
//     //     Some("application/dns-json") => {
//     //         // 解析 JSON
//     //         // 需要 trust_dns_proto 的 JSON 支持或自定义结构
//     //         unimplemented!("JSON response parsing not yet implemented")
//     //     }
//     //     _ => {
//     //         // 返回错误，未知的 Content-Type
//     //         Err(ClientError::Other(format!("Unexpected Content-Type: {:?}", content_type)))
//     //     }
//     // }
//     unimplemented!()
// }
//
// /// 显示 DNS 响应结果
// pub fn display_response(response_message: &Message, duration: Duration, verbose_level: u8) {
//     // 打印耗时
//     println!(";; Query time: {:?}", duration);
//
//     // 打印响应状态
//     println!(";; Got answer:");
//     println!(";; ->>HEADER<<- opcode: {}, status: {}, id: {}", response_message.op_code(), response_message.response_code(), response_message.id());
//     println!(";; flags: {}; QUERY: {}, ANSWER: {}, AUTHORITY: {}, ADDITIONAL: {}",
//              response_message.flags(),
//              response_message.queries().len(),
//              response_message.answers().len(),
//              response_message.name_servers().len(),
//              response_message.additionals().len());
//
//     // 打印 Question Section (如果需要)
//     // ...
//
//     // 打印 Answer Section
//     if !response_message.answers().is_empty() {
//         println!("
;; ANSWER SECTION:");
//         for record in response_message.answers() {
//             println!("{}", record);
//         }
//     }
//
//     // 打印 Authority Section
//     if !response_message.name_servers().is_empty() {
//         println!("
;; AUTHORITY SECTION:");
//         for record in response_message.name_servers() {
//             println!("{}", record);
//         }
//     }
//
//     // 打印 Additional Section
//     if !response_message.additionals().is_empty() {
//         println!("
;; ADDITIONAL SECTION:");
//         for record in response_message.additionals() {
//             println!("{}", record);
//         }
//     }
//
//     if verbose_level > 0 {
//         // 打印更详细的信息，例如原始报文等
//         println!("
;; --- Verbose Output (Level {}) ---", verbose_level);
//         // println!(";; Raw Message (Debug): {:?}", response_message);
//     }
//
// } 