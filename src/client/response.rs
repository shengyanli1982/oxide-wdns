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

use crate::client::error::{ClientError, ClientResult};
use crate::common::consts::{CONTENT_TYPE_DNS_JSON, CONTENT_TYPE_DNS_MESSAGE};
use colored::Colorize;
use hex;
use serde::{Deserialize, Serialize};
use serde_json;
use std::fmt::Write as FmtWrite;
use std::time::Duration;
use trust_dns_proto::op::{Message, MessageType, Query, ResponseCode};
use trust_dns_proto::rr::{DNSClass, Name, Record, RecordType, RData};
use trust_dns_proto::serialize::binary::BinDecodable;

/// DoH JSON 响应
#[derive(Debug, Deserialize)]
struct DohJsonResponse {
    /// 应答状态
    #[serde(default)]
    Status: u16,
    /// 是否截断
    #[serde(default)]
    TC: bool,
    /// 是否递归可用
    #[serde(default)]
    RD: bool,
    /// 是否递归查询
    #[serde(default)]
    RA: bool,
    /// 是否通过验证
    #[serde(default)]
    AD: bool,
    /// 是否禁用验证
    #[serde(default)]
    CD: bool,
    /// 响应的问题
    Question: Vec<DohJsonQuestion>,
    /// 响应的答案
    #[serde(default)]
    Answer: Vec<DohJsonAnswer>,
    /// 权威信息
    #[serde(default)]
    Authority: Vec<DohJsonAnswer>,
    /// 附加信息
    #[serde(default)]
    Additional: Vec<DohJsonAnswer>,
    /// 注释
    #[serde(default)]
    Comment: Option<String>,
}

/// DoH JSON 问题
#[derive(Debug, Deserialize)]
struct DohJsonQuestion {
    name: String,
    #[serde(rename = "type")]
    record_type: u16,
}

/// DoH JSON 应答
#[derive(Debug, Deserialize)]
struct DohJsonAnswer {
    name: String,
    #[serde(rename = "type")]
    record_type: u16,
    TTL: u32,
    data: String,
}

/// DoH 响应结果
pub struct DohResponse {
    /// 解析后的 DNS 消息
    pub message: Message,
    /// HTTP 状态码
    pub status: reqwest::StatusCode,
    /// HTTP 响应头
    pub headers: reqwest::header::HeaderMap,
    /// 原始响应体
    pub raw_body: Vec<u8>,
    /// 查询耗时
    pub duration: Duration,
    /// 是否为 JSON 格式响应
    pub is_json: bool,
    /// 原始 JSON 结构（如果是 JSON 响应）
    pub json_response: Option<DohJsonResponse>,
}

/// 解析 DoH 响应
pub async fn parse_doh_response(response: reqwest::Response) -> ClientResult<DohResponse> {
    // 获取 HTTP 状态码和响应头
    let status = response.status();
    let headers = response.headers().clone();
    
    // 检查状态码是否成功
    if !status.is_success() {
        return Err(ClientError::Other(format!(
            "HTTP request failed with status code: {}", status
        )));
    }
    
    // 获取 Content-Type 头
    let content_type = headers
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    
    // 读取响应体
    let body = response.bytes().await?;
    let raw_body = body.to_vec();
    
    // 根据 Content-Type 解析响应体
    let (message, is_json, json_response) = match content_type {
        ct if ct.contains(CONTENT_TYPE_DNS_MESSAGE) => {
            // 解析 Wireformat
            let message = Message::from_vec(&raw_body)
                .map_err(ClientError::DnsProtoError)?;
            (message, false, None)
        }
        ct if ct.contains(CONTENT_TYPE_DNS_JSON) || ct.contains("application/json") => {
            // 解析 JSON 格式
            let json_response: DohJsonResponse = serde_json::from_slice(&raw_body)
                .map_err(ClientError::JsonError)?;
            
            // 将 JSON 转换为 Message
            let message = json_to_message(&json_response)?;
            
            (message, true, Some(json_response))
        }
        _ => {
            // 未知的 Content-Type，尝试当作 Wireformat 解析
            let message = Message::from_vec(&raw_body)
                .map_err(|_| {
                    // 如果作为 Wireformat 解析失败，尝试作为 JSON 解析
                    match serde_json::from_slice::<DohJsonResponse>(&raw_body) {
                        Ok(json_response) => {
                            match json_to_message(&json_response) {
                                Ok(message) => {
                                    // 解析为 JSON 成功
                                    return ClientError::Other(format!(
                                        "Unexpected Content-Type: {}, but successfully parsed as JSON", content_type
                                    ));
                                }
                                Err(_) => {}
                            }
                        }
                        Err(_) => {}
                    }
                    
                    ClientError::Other(format!(
                        "Unexpected Content-Type: {}, and failed to parse as DNS message or JSON", content_type
                    ))
                })?;
            
            (message, false, None)
        }
    };
    
    // 构建响应结果
    Ok(DohResponse {
        message,
        status,
        headers,
        raw_body,
        duration: Duration::default(), // 初始值，调用者应该设置正确的耗时
        is_json,
        json_response,
    })
}

/// 将 JSON 响应转换为 Message
fn json_to_message(json: &DohJsonResponse) -> ClientResult<Message> {
    let mut message = Message::new();
    
    // 设置消息头部信息
    message.set_message_type(MessageType::Response);
    message.set_recursion_desired(json.RD);
    message.set_recursion_available(json.RA);
    message.set_authentic_data(json.AD);
    message.set_checking_disabled(json.CD);
    message.set_truncated(json.TC);
    
    // 设置响应码
    if let Some(response_code) = ResponseCode::from_u16(json.Status) {
        message.set_response_code(response_code);
    }
    
    // 添加问题部分
    for q in &json.Question {
        if let Ok(name) = Name::from_ascii(&q.name) {
            if let Some(query_type) = RecordType::from_u16(q.record_type) {
                let mut query = Query::new();
                query.set_name(name);
                query.set_query_type(query_type);
                query.set_query_class(DNSClass::IN);
                message.add_query(query);
            }
        }
    }
    
    // 添加答案部分
    for ans in &json.Answer {
        if let Ok(name) = Name::from_ascii(&ans.name) {
            if let Some(record_type) = RecordType::from_u16(ans.record_type) {
                // 解析记录数据
                if let Ok(rdata) = parse_json_rdata(record_type, &ans.data) {
                    let mut record = Record::new();
                    record.set_name(name);
                    record.set_ttl(ans.TTL);
                    record.set_record_type(record_type);
                    record.set_data(Some(rdata));
                    message.add_answer(record);
                }
            }
        }
    }
    
    // 添加权威部分
    for auth in &json.Authority {
        if let Ok(name) = Name::from_ascii(&auth.name) {
            if let Some(record_type) = RecordType::from_u16(auth.record_type) {
                // 解析记录数据
                if let Ok(rdata) = parse_json_rdata(record_type, &auth.data) {
                    let mut record = Record::new();
                    record.set_name(name);
                    record.set_ttl(auth.TTL);
                    record.set_record_type(record_type);
                    record.set_data(Some(rdata));
                    message.add_name_server(record);
                }
            }
        }
    }
    
    // 添加附加部分
    for add in &json.Additional {
        if let Ok(name) = Name::from_ascii(&add.name) {
            if let Some(record_type) = RecordType::from_u16(add.record_type) {
                // 解析记录数据
                if let Ok(rdata) = parse_json_rdata(record_type, &add.data) {
                    let mut record = Record::new();
                    record.set_name(name);
                    record.set_ttl(add.TTL);
                    record.set_record_type(record_type);
                    record.set_data(Some(rdata));
                    message.add_additional(record);
                }
            }
        }
    }
    
    Ok(message)
}

/// 解析 JSON 记录数据为 RData
fn parse_json_rdata(record_type: RecordType, data: &str) -> ClientResult<RData> {
    match record_type {
        RecordType::A => {
            // IPv4 地址
            if let Ok(addr) = data.parse() {
                Ok(RData::A(addr))
            } else {
                Err(ClientError::Other(format!("Invalid A record data: {}", data)))
            }
        },
        RecordType::AAAA => {
            // IPv6 地址
            if let Ok(addr) = data.parse() {
                Ok(RData::AAAA(addr))
            } else {
                Err(ClientError::Other(format!("Invalid AAAA record data: {}", data)))
            }
        },
        RecordType::NS => {
            // 名称服务器
            if let Ok(name) = Name::from_ascii(data) {
                Ok(RData::NS(name))
            } else {
                Err(ClientError::Other(format!("Invalid NS record data: {}", data)))
            }
        },
        RecordType::CNAME => {
            // 别名
            if let Ok(name) = Name::from_ascii(data) {
                Ok(RData::CNAME(name))
            } else {
                Err(ClientError::Other(format!("Invalid CNAME record data: {}", data)))
            }
        },
        RecordType::TXT => {
            // 文本记录
            Ok(RData::TXT(vec![data.as_bytes().to_vec()]))
        },
        // 其他记录类型可以根据需要添加
        _ => {
            // 对于不支持的记录类型，返回 NULL 类型
            Ok(RData::NULL(data.as_bytes().to_vec()))
        }
    }
}

/// 显示格式化的 DNS 响应
pub fn display_response(response: &DohResponse, verbose_level: u8) {
    let message = &response.message;
    
    // 打印查询耗时
    println!("{} {:?}", ";; Query time:".bold(), response.duration);
    
    // 打印 HTTP 状态
    println!("{} {}", ";; HTTP Status:".bold(), response.status);
    
    // 打印响应格式
    if response.is_json {
        println!("{} {}", ";; Response Format:".bold(), "JSON (application/dns-json)".green());
    } else {
        println!("{} {}", ";; Response Format:".bold(), "Wire Format (application/dns-message)".green());
    }
    
    // 打印响应状态
    println!("\n{}", ";; Got answer:".bold());
    println!("{} opcode: {}, status: {}, id: {}", 
             ";; ->>HEADER<<-".bold(), 
             message.op_code(), 
             message.response_code(), 
             message.id());
    
    println!("{} {}; QUERY: {}, ANSWER: {}, AUTHORITY: {}, ADDITIONAL: {}",
             ";; flags:".bold(),
             get_flags_description(message),
             message.queries().len(),
             message.answers().len(),
             message.name_servers().len(),
             message.additionals().len());
    
    // 打印 Question Section
    if !message.queries().is_empty() {
        println!("\n{}", ";; QUESTION SECTION:".bold());
        for query in message.queries() {
            println!("{}. \t {} \t {}", 
                     query.name(), 
                     query.query_class(),
                     query.query_type());
        }
    }
    
    // 打印 Answer Section
    if !message.answers().is_empty() {
        println!("\n{}", ";; ANSWER SECTION:".bold());
        for record in message.answers() {
            println!("{}. \t {} \t {} \t {}", 
                     record.name(), 
                     record.ttl(),
                     record.record_class(),
                     record.record_type());
            
            // 打印记录数据
            println!("\t\t{}", record.rdata());
        }
    }
    
    // 打印 Authority Section
    if !message.name_servers().is_empty() {
        println!("\n{}", ";; AUTHORITY SECTION:".bold());
        for record in message.name_servers() {
            println!("{}. \t {} \t {} \t {}", 
                     record.name(), 
                     record.ttl(),
                     record.record_class(),
                     record.record_type());
            
            // 打印记录数据
            println!("\t\t{}", record.rdata());
        }
    }
    
    // 打印 Additional Section
    if !message.additionals().is_empty() {
        println!("\n{}", ";; ADDITIONAL SECTION:".bold());
        for record in message.additionals() {
            println!("{}. \t {} \t {} \t {}", 
                     record.name(), 
                     record.ttl(),
                     record.record_class(),
                     record.record_type());
            
            // 打印记录数据
            println!("\t\t{}", record.rdata());
        }
    }
    
    // 根据详细程度打印更多信息
    if verbose_level > 0 {
        println!("\n{} (Level {})", ";; --- Verbose Output ---".bold(), verbose_level);
        
        // 打印 HTTP 响应头
        if verbose_level >= 1 {
            println!("\n{}", ";; HTTP Response Headers:".bold());
            for (name, value) in response.headers.iter() {
                println!("{}: {}", name, value.to_str().unwrap_or("<binary>"));
            }
        }
        
        // 打印原始消息
        if verbose_level >= 2 {
            println!("\n{}", ";; Raw DNS Message (Hex):".bold());
            print_hex_dump(&response.raw_body);
            
            // 如果是 JSON 响应，打印原始 JSON
            if response.is_json && verbose_level >= 2 {
                println!("\n{}", ";; Raw JSON Response:".bold());
                match String::from_utf8(response.raw_body.clone()) {
                    Ok(json_str) => {
                        // 尝试格式化 JSON
                        match serde_json::from_str::<serde_json::Value>(&json_str) {
                            Ok(json_value) => {
                                if let Ok(pretty_json) = serde_json::to_string_pretty(&json_value) {
                                    println!("{}", pretty_json);
                                } else {
                                    println!("{}", json_str);
                                }
                            },
                            Err(_) => println!("{}", json_str),
                        }
                    },
                    Err(_) => println!("<invalid UTF-8>"),
                }
            }
        }
        
        // 打印更详细的消息调试信息
        if verbose_level >= 3 {
            println!("\n{}", ";; DNS Message Debug:".bold());
            println!("{:#?}", message);
        }
    }
}

/// 获取消息标志的描述
fn get_flags_description(message: &Message) -> String {
    let mut flags = Vec::new();
    
    if message.response() { flags.push("qr"); }
    if message.authoritative() { flags.push("aa"); }
    if message.truncated() { flags.push("tc"); }
    if message.recursion_desired() { flags.push("rd"); }
    if message.recursion_available() { flags.push("ra"); }
    if message.authentic_data() { flags.push("ad"); }
    if message.checking_disabled() { flags.push("cd"); }
    
    flags.join(" ")
}

/// 打印十六进制转储
fn print_hex_dump(data: &[u8]) {
    for (i, chunk) in data.chunks(16).enumerate() {
        let mut hex_line = String::new();
        let mut ascii_line = String::new();
        
        for b in chunk {
            write!(&mut hex_line, "{:02x} ", b).unwrap();
            
            // ASCII 部分只显示可打印字符，其他用点代替
            if *b >= 32 && *b <= 126 {
                ascii_line.push(*b as char);
            } else {
                ascii_line.push('.');
            }
        }
        
        // 对齐短行
        for _ in chunk.len()..16 {
            hex_line.push_str("   ");
        }
        
        println!("{:08x}:  {}  |{}|", i * 16, hex_line, ascii_line);
    }
} 