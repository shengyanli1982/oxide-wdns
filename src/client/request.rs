// src/client/request.rs

/// 该模块负责构建 DoH (DNS over HTTPS) 请求。
///
/// 主要职责:
/// 1. 根据命令行参数 (`args::CliArgs`) 创建 DNS 查询消息 (`trust_dns_proto::op::Message`)。
///    - 设置查询的域名、记录类型。
///    - 根据 `--dnssec` 参数设置 DNSSEC OK (DO) 位。
///    - 如果提供了 `--payload`，则直接使用提供的十六进制编码报文，跳过域名/类型参数。
/// 2. 将 DNS 消息编码为指定的格式：
///    - Wireformat (`application/dns-message`)。
///    - JSON (`application/dns-json`)，如果服务器支持 (需要确认实现细节或添加对 JSON 的支持)。
/// 3. 确定 HTTP 方法 (GET 或 POST)：
///    - GET 通常用于较小的 Wireformat 请求，将 DNS 报文进行 Base64URL 编码后作为 `?dns=` 查询参数。
///    - POST 用于较大的请求或 JSON 格式，将 DNS 报文放在请求体中。
///    - 允许用户通过 `--method` 强制指定。
/// 4. 构建 HTTP 请求 (`reqwest::Request`)：
///    - 设置目标 URL (来自 `args.server_url`)。
///    - 设置正确的 HTTP 方法。
///    - 设置必要的 HTTP Headers:
///      - `Accept`: `application/dns-message` 或 `application/dns-json`。
///      - `Content-Type`: `application/dns-message` 或 `application/dns-json` (主要用于 POST)。
///    - 设置 HTTP 版本偏好 (来自 `args.http_version`)。
///    - 附加请求体 (对于 POST)。

// 依赖: reqwest, trust-dns-proto, base64, serde_json (如果支持 JSON)

// use crate::client::args::CliArgs;
// use crate::client::error::{ClientError, ClientResult};
// use trust_dns_proto::op::Message;
// use trust_dns_proto::rr::{Name, RecordType};
// use trust_dns_proto::serialize::binary::BinEncoder;
// use std::str::FromStr;
//
// /// 构建最终要发送的 HTTP 请求
// pub async fn build_doh_request(args: &CliArgs) -> ClientResult<reqwest::Request> {
//     // 1. 创建或解析 DNS 消息
//     // let dns_message = create_dns_query(args)?;
//
//     // 2. 编码 DNS 消息 (Wireformat / JSON)
//     // let (content_type, body_or_query_param) = encode_dns_message(&dns_message, args.format.as_str())?;
//
//     // 3. 确定 HTTP 方法和 URL
//     // let method = determine_http_method(args, body_or_query_param.len());
//     // let url = build_url(args.server_url.as_str(), method, &body_or_query_param)?;
//
//     // 4. 构建 reqwest 请求
//     // let client = reqwest::Client::new(); // 临时的，实际客户端应在 runner 中创建
//     // let mut request_builder = client.request(method, url);
//     // request_builder = request_builder.header(reqwest::header::ACCEPT, content_type);
//     // if method == reqwest::Method::POST {
//     //     request_builder = request_builder
//     //         .header(reqwest::header::CONTENT_TYPE, content_type)
//     //         .body(body_or_query_param);
//     // }
//     // ... 设置其他 Headers 和版本 ...
//
//     // Ok(request_builder.build()?)
//     unimplemented!()
// }
//
// /// 创建 DNS 查询消息
// fn create_dns_query(args: &CliArgs) -> ClientResult<Message> {
//     // ... 实现逻辑 ...
//     unimplemented!()
// }
//
// /// 编码 DNS 消息
// fn encode_dns_message(message: &Message, format: &str) -> ClientResult<(String, Vec<u8>)> { // 返回 (Content-Type, 编码后的数据)
//     // ... 实现 Wireformat 和 JSON 编码 ...
//     unimplemented!()
// }
//
// /// 确定 HTTP 方法
// fn determine_http_method(args: &CliArgs, encoded_len: usize) -> reqwest::Method {
//     // ... 根据用户指定或请求大小决定 GET/POST ...
//     unimplemented!()
// }
//
// /// 构建最终请求的 URL (包含 GET 参数，如果需要)
// fn build_url(base_url: &str, method: reqwest::Method, data: &[u8]) -> ClientResult<reqwest::Url> {
//     // ... 如果是 GET，添加 ?dns=... 参数 ...
//     unimplemented!()
// } 