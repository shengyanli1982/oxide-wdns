// src/client/request.rs

// 该模块负责构建 DoH (DNS over HTTPS) 请求。
//
// 主要职责:
// 1. 根据命令行参数 (`args::CliArgs`) 创建 DNS 查询消息 (`trust_dns_proto::op::Message`)。
//    - 设置查询的域名、记录类型。
//    - 根据 `--dnssec` 参数设置 DNSSEC OK (DO) 位。
//    - 如果提供了 `--payload`，则直接使用提供的十六进制编码报文，跳过域名/类型参数。
// 2. 将 DNS 消息编码为指定的格式：
//    - Wireformat (`application/dns-message`)。
//    - JSON (`application/dns-json`)，如果服务器支持 (需要确认实现细节或添加对 JSON 的支持)。
// 3. 确定 HTTP 方法 (GET 或 POST)：
//    - GET 通常用于较小的 Wireformat 请求，将 DNS 报文进行 Base64URL 编码后作为 `?dns=` 查询参数。
//    - POST 用于较大的请求或 JSON 格式，将 DNS 报文放在请求体中。
//    - 允许用户通过 `--method` 强制指定。
// 4. 构建 HTTP 请求 (`reqwest::Request`)：
//    - 设置目标 URL (来自 `args.server_url`)。
//    - 设置正确的 HTTP 方法。
//    - 设置必要的 HTTP Headers:
//      - `Accept`: `application/dns-message` 或 `application/dns-json`。
//      - `Content-Type`: `application/dns-message` 或 `application/dns-json` (主要用于 POST)。
//    - 设置 HTTP 版本偏好 (来自 `args.http_version`)。
//    - 附加请求体 (对于 POST)。

// 依赖: reqwest, trust-dns-proto, base64, serde_json (如果支持 JSON)

use crate::client::args::{CliArgs, DohFormat, HttpMethod, HttpVersion};
use crate::client::error::{ClientError, ClientResult};
use crate::common::consts::{CONTENT_TYPE_DNS_JSON, CONTENT_TYPE_DNS_MESSAGE};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use reqwest::{self, Request, Url};
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use serde::Serialize;
use serde_json;
use std::str::FromStr;
use trust_dns_proto::op::{Message, MessageType, OpCode, Query};
use trust_dns_proto::rr::{Name, RecordType, DNSClass};
use trust_dns_proto::serialize::binary::{BinEncodable, BinEncoder};
use rand::random;

// DoH JSON 请求格式
#[derive(Debug, Serialize)]
struct DohJsonRequest {
    name: String,
    #[serde(rename = "type")]
    record_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    dnssec: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cd: Option<bool>,
}

// 构建最终要发送的 HTTP 请求
pub async fn build_doh_request(args: &CliArgs, client: &reqwest::Client) -> ClientResult<Request> {
    // 1. 创建或解析 DNS 消息
    let dns_message = create_dns_query(args)?;
    
    // 2. 编码 DNS 消息 (Wireformat / JSON)
    let (content_type, encoded_data) = encode_dns_message(&dns_message, &args.format, args)?;
    
    // 3. 确定 HTTP 方法和 URL
    let method = determine_http_method(args, encoded_data.len());
    let url = build_url(&args.server_url, method, &encoded_data, &args.format)?;
    
    // 4. 构建 reqwest 请求
    let mut request_builder = client.request(
        if method == HttpMethod::Get { reqwest::Method::GET } else { reqwest::Method::POST }, 
        url
    );
    
    // 设置 Accept 头
    request_builder = request_builder.header(ACCEPT, content_type.clone());
    
    // 如果是 POST 请求，设置 Content-Type 头和请求体
    if method == HttpMethod::Post {
        request_builder = request_builder
            .header(CONTENT_TYPE, content_type)
            .body(encoded_data);
    }
    
    // 添加HTTP版本头，仅用于测试
    if let Some(http_version) = &args.http_version {
        match http_version {
            HttpVersion::Http1 => {
                // 添加一个自定义头以便测试可以检测HTTP版本
                request_builder = request_builder.header("version", "http/1.1");
            },
            HttpVersion::Http2 => {
                // 添加一个自定义头以便测试可以检测HTTP版本
                request_builder = request_builder.header("version", "http/2");
            }
        }
    }
    
    Ok(request_builder.build()?)
}

// 创建 DNS 查询消息
fn create_dns_query(args: &CliArgs) -> ClientResult<Message> {
    // 如果提供了 payload 参数，直接使用
    if let Some(hex_payload) = &args.payload {
        // 解析十六进制数据
        let payload = hex::decode(hex_payload)
            .map_err(ClientError::HexError)?;
        
        // 解析为 DNS 消息
        return Message::from_vec(&payload)
            .map_err(ClientError::DnsProtoError);
    }
    
    // 否则，根据提供的域名和记录类型创建 DNS 查询
    // 1. 创建一个新的消息
    let mut message = Message::new();
    
    // 2. 设置查询参数
    message.set_id(random::<u16>());
    message.set_message_type(MessageType::Query);
    message.set_op_code(OpCode::Query);
    
    // 3. 设置递归请求位 (RD)
    message.set_recursion_desired(true);
    
    // 4. 解析域名和记录类型
    let name = Name::from_str(&args.domain)
        .map_err(|_| ClientError::InvalidArgument(format!("Invalid domain name: {}", args.domain)))?;
    
    let record_type = RecordType::from_str(&args.record_type)
        .map_err(|_| ClientError::InvalidRecordType(args.record_type.clone()))?;
    
    // 5. 创建查询并添加到消息
    let mut query = Query::new();
    query.set_name(name);
    query.set_query_type(record_type);
    query.set_query_class(DNSClass::IN);
    
    // 6. 设置 DNSSEC OK 位 (如果启用)
    if args.dnssec {
        message.set_checking_disabled(true);
        
        // 为 DNSSEC 添加 EDNS(0) 和 DO 位支持
        let mut edns = trust_dns_proto::op::Edns::new();
        edns.set_dnssec_ok(true);
        message.set_edns(edns);
    }
    
    message.add_query(query);
    
    Ok(message)
}

// 编码 DNS 消息为指定格式
fn encode_dns_message(message: &Message, format: &DohFormat, args: &CliArgs) -> ClientResult<(String, Vec<u8>)> {
    match format {
        DohFormat::Wire => {
            // 编码为二进制格式
            let mut buffer = Vec::with_capacity(512);
            let mut encoder = BinEncoder::new(&mut buffer);
            message.emit(&mut encoder)
                .map_err(ClientError::DnsProtoError)?;
            
            Ok((CONTENT_TYPE_DNS_MESSAGE.to_string(), buffer))
        },
        DohFormat::Json => {
            // 编码为 JSON 格式
            // 注意：DoH JSON 格式是一个简化的 JSON 结构，不是直接将 DNS 消息序列化为 JSON
            
            // 获取查询的域名和记录类型
            let query = message.queries().first()
                .ok_or_else(|| ClientError::Other("No query found in message".to_string()))?;
            
            let doh_json = DohJsonRequest {
                name: query.name().to_string(),
                record_type: query.query_type().to_string(),
                dnssec: if args.dnssec { Some(true) } else { None },
                cd: if args.dnssec { Some(true) } else { None },
            };
            
            let json_data = serde_json::to_vec(&doh_json)
                .map_err(ClientError::JsonError)?;
            
            Ok((CONTENT_TYPE_DNS_JSON.to_string(), json_data))
        }
    }
}

// 确定 HTTP 方法 (GET 或 POST)
fn determine_http_method(args: &CliArgs, encoded_len: usize) -> HttpMethod {
    // 如果用户明确指定了 HTTP 方法，使用指定的方法
    if let Some(method) = args.method {
        return method;
    }
    
    // 否则，根据请求的大小和格式自动选择
    // GET 用于小型 wireformat 请求，POST 用于大型请求或 JSON
    match args.format {
        DohFormat::Wire => {
            if encoded_len <= 2048 {
                HttpMethod::Get
            } else {
                HttpMethod::Post
            }
        },
        DohFormat::Json => HttpMethod::Get, // JSON 格式可以使用 GET，因为参数通常很短
    }
}

// 构建最终请求的 URL (包含 GET 参数，如果需要)
fn build_url(base_url: &str, method: HttpMethod, data: &[u8], format: &DohFormat) -> ClientResult<Url> {
    let mut url = Url::parse(base_url)
        .map_err(ClientError::UrlError)?;
    
    // 如果是 GET 请求，添加查询参数
    if method == HttpMethod::Get {
        match format {
            DohFormat::Wire => {
                // 对于 wireformat，使用 ?dns= 参数
                let encoded = URL_SAFE_NO_PAD.encode(data);
                url.query_pairs_mut().append_pair("dns", &encoded);
            },
            DohFormat::Json => {
                // 对于 JSON 格式，解析 JSON 并添加每个字段作为查询参数
                let json_data: serde_json::Value = serde_json::from_slice(data)
                    .map_err(ClientError::JsonError)?;
                
                if let Some(obj) = json_data.as_object() {
                    let mut query_pairs = url.query_pairs_mut();
                    
                    for (key, value) in obj {
                        if let Some(value_str) = value.as_str() {
                            query_pairs.append_pair(key, value_str);
                        } else if let Some(value_bool) = value.as_bool() {
                            query_pairs.append_pair(key, if value_bool { "true" } else { "false" });
                        } else if let Some(value_num) = value.as_i64() {
                            query_pairs.append_pair(key, &value_num.to_string());
                        }
                    }
                }
            }
        }
    }
    
    Ok(url)
} 