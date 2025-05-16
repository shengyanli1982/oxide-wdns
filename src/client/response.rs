// src/client/response.rs

// 该模块负责解析和处理 DoH (DNS over HTTPS) 响应。
//
// 主要职责:
// 1. 接收并解析 HTTP 响应 (`reqwest::Response`)。
// 2. 根据响应内容类型确定解析策略:
//    - `application/dns-message`: 解析为二进制 DNS 报文。
//    - `application/dns-json`: 解析为 JSON 格式的 DNS 数据。
// 3. 将解析后的数据转换为统一的 DNS 消息 (`trust_dns_proto::op::Message`)。
// 4. 提供格式化输出功能，根据用户的详细程度设置显示数据。
//    - 基本输出: 显示查询详情、响应状态和记录值。
//    - 详细输出: 增加显示 HTTP 头、原始数据等。

// 依赖: reqwest, trust-dns-proto, serde_json, colored (终端颜色支持)

use crate::client::error::{ClientError, ClientResult};
use crate::common::consts::{CONTENT_TYPE_DNS_JSON, CONTENT_TYPE_DNS_MESSAGE};
use colored::Colorize;
use reqwest;
use serde::Deserialize;
use serde_json;
use std::fmt::Write;
use std::time::Duration;
use hickory_proto::op::{Message, MessageType, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};

// DoH JSON 响应格式
#[derive(Debug, Deserialize)]
pub struct DohJsonResponse {
    // 应答状态
    #[serde(default)]
    #[serde(rename = "Status")]
    pub status: u16,
    // 是否截断
    #[serde(default)]
    #[serde(rename = "TC")]
    pub tc: bool,
    // 是否递归可用
    #[serde(default)]
    #[serde(rename = "RD")]
    pub rd: bool,
    // 是否递归查询
    #[serde(default)]
    #[serde(rename = "RA")]
    pub ra: bool,
    // 是否通过验证
    #[serde(default)]
    #[serde(rename = "AD")]
    pub ad: bool,
    // 是否禁用验证
    #[serde(default)]
    #[serde(rename = "CD")]
    pub cd: bool,
    // 响应的问题
    #[serde(rename = "Question")]
    pub question: Vec<DohJsonQuestion>,
    // 响应的答案
    #[serde(default)]
    #[serde(rename = "Answer")]
    pub answer: Vec<DohJsonAnswer>,
    // 权威信息
    #[serde(default)]
    #[serde(rename = "Authority")]
    pub authority: Vec<DohJsonAnswer>,
    // 附加信息
    #[serde(default)]
    #[serde(rename = "Additional")]
    pub additional: Vec<DohJsonAnswer>,
    // 注释
    #[serde(default)]
    #[serde(rename = "Comment")]
    pub comment: Option<String>,
}

// DoH JSON 问题
#[derive(Debug, Deserialize)]
pub struct DohJsonQuestion {
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: u16,
}

// DoH JSON 答案
#[derive(Debug, Deserialize)]
pub struct DohJsonAnswer {
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: u16,
    #[serde(rename = "TTL")]
    pub ttl: u32,
    pub data: String,
}

// DoH 响应结构
#[derive(Debug)]
pub struct DohResponse {
    // 解析后的 DNS 消息
    pub message: Message,
    // HTTP 状态码
    pub status: reqwest::StatusCode,
    // HTTP 响应头
    pub headers: reqwest::header::HeaderMap,
    // 原始响应体
    pub raw_body: Vec<u8>,
    // 查询耗时
    pub duration: Duration,
    // 是否为 JSON 格式响应
    pub is_json: bool,
    // 原始 JSON 结构（如果是 JSON 响应）
    pub json_response: Option<DohJsonResponse>,
}

// 解析 DoH 响应
pub async fn parse_doh_response(response: reqwest::Response) -> ClientResult<DohResponse> {
    // 记录响应状态和头部
    let status = response.status();
    let headers = response.headers().clone();
    
    // 检查响应状态
    if !status.is_success() {
        // 对于5xx服务器错误，返回ReqwestError类型错误
        if status.is_server_error() {
            // 创建一个reqwest::Error类似的错误作为包装
            let error_msg = format!("HTTP server error: {} {}", 
                status.as_u16(), 
                status.canonical_reason().unwrap_or("Unknown error"));
            return Err(ClientError::Other(error_msg));
        } else {
            return Err(ClientError::HttpError(status.as_u16(), 
                status.canonical_reason().unwrap_or("Unknown error").to_string()));
        }
    }
    
    // 获取内容类型和原始响应体
    let content_type = headers.get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    
    let raw_body = response.bytes().await.map_err(ClientError::ReqwestError)?.to_vec();
    
    // 根据内容类型选择解析策略
    let (message, is_json, json_response) = match content_type {
        ct if ct.starts_with(CONTENT_TYPE_DNS_MESSAGE) => {
            // 解析二进制 DNS 消息
            let message = Message::from_vec(&raw_body)
                .map_err(ClientError::DnsProtoError)?;
            (message, false, None)
        },
        ct if ct.starts_with(CONTENT_TYPE_DNS_JSON) => {
            // 解析 JSON 格式的 DNS 消息
            let json: DohJsonResponse = serde_json::from_slice(&raw_body)
                .map_err(ClientError::JsonError)?;
            
            let message = json_to_message(&json)?;
            (message, true, Some(json))
        },
        // 对于其他格式，尝试作为二进制 DNS 消息解析
        _ => {
            match Message::from_vec(&raw_body) {
                Ok(message) => (message, false, None),
                Err(_) => {
                    // 尝试作为 JSON 解析
                    match serde_json::from_slice::<DohJsonResponse>(&raw_body) {
                        Ok(json) => {
                            let message = json_to_message(&json)?;
                            (message, true, Some(json))
                        },
                        Err(e) => return Err(ClientError::Other(format!(
                            "Unsupported response content type: {}. Parse error: {}", content_type, e
                        ))),
                    }
                }
            }
        }
    };
    
    // 创建并返回 DohResponse
    Ok(DohResponse {
        message,
        status,
        headers,
        raw_body,
        duration: Duration::default(), // 将在调用方填充
        is_json,
        json_response,
    })
}

// 将 JSON 格式的 DNS 数据转换为 DNS 消息
fn json_to_message(json: &DohJsonResponse) -> ClientResult<Message> {
    let mut message = Message::new();
    
    // 设置消息头部信息
    message.set_message_type(MessageType::Response);
    message.set_recursion_desired(json.rd);
    message.set_recursion_available(json.ra);
    message.set_authentic_data(json.ad);
    message.set_checking_disabled(json.cd);
    message.set_truncated(json.tc);
    
    // 设置响应码
    // 使用 from_low 方法替代 from_u16
    message.set_response_code(ResponseCode::from_low(json.status as u8));
    
    // 添加问题部分
    for q in &json.question {
        if let Ok(name) = Name::from_ascii(&q.name) {
            // 使用 RecordType::from(u16) 获取记录类型
            let query_type = RecordType::from(q.record_type);
            {
                let mut query = Query::new();
                query.set_name(name);
                query.set_query_type(query_type);
                query.set_query_class(DNSClass::IN);
                message.add_query(query);
            }
        }
    }
    
    // 添加答案部分
    for ans in &json.answer {
        if let Ok(name) = Name::from_ascii(&ans.name) {
            // 使用 RecordType::from(u16) 获取记录类型
            let record_type = RecordType::from(ans.record_type);
            
            // 解析记录数据
            if let Ok(rdata) = parse_json_rdata(record_type, &ans.data) {
                let mut record = Record::new();
                record.set_name(name);
                record.set_ttl(ans.ttl);
                record.set_record_type(record_type);
                record.set_data(Some(rdata));
                message.add_answer(record);
            }
        }
    }
    
    // 添加权威部分
    for auth in &json.authority {
        if let Ok(name) = Name::from_ascii(&auth.name) {
            // 使用 RecordType::from(u16) 获取记录类型
            let record_type = RecordType::from(auth.record_type);
            
            // 解析记录数据
            if let Ok(rdata) = parse_json_rdata(record_type, &auth.data) {
                let mut record = Record::new();
                record.set_name(name);
                record.set_ttl(auth.ttl);
                record.set_record_type(record_type);
                record.set_data(Some(rdata));
                message.add_name_server(record);
            }
        }
    }
    
    // 添加附加部分
    for add in &json.additional {
        if let Ok(name) = Name::from_ascii(&add.name) {
            // 使用 RecordType::from(u16) 获取记录类型
            let record_type = RecordType::from(add.record_type);
            
            // 解析记录数据
            if let Ok(rdata) = parse_json_rdata(record_type, &add.data) {
                let mut record = Record::new();
                record.set_name(name);
                record.set_ttl(add.ttl);
                record.set_record_type(record_type);
                record.set_data(Some(rdata));
                message.add_additional(record);
            }
        }
    }
    
    Ok(message)
}

// 解析 JSON 记录数据为 RData
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
                let ns = hickory_proto::rr::rdata::NS(name);
                Ok(RData::NS(ns))
            } else {
                Err(ClientError::Other(format!("Invalid NS record data: {}", data)))
            }
        },
        RecordType::CNAME => {
            // 别名
            if let Ok(name) = Name::from_ascii(data) {
                let cname = hickory_proto::rr::rdata::CNAME(name);
                Ok(RData::CNAME(cname))
            } else {
                Err(ClientError::Other(format!("Invalid CNAME record data: {}", data)))
            }
        },
        RecordType::TXT => {
            // 文本记录
            // 创建 TXT 记录，使用字符串向量而不是字节向量
            let data_strings = vec![String::from(data)];
            let txt = hickory_proto::rr::rdata::TXT::new(data_strings); 
            Ok(RData::TXT(txt))
        },
        // 其他记录类型可以根据需要添加
        _ => {
            // 对于不支持的记录类型，使用 NULL 记录
            let null = hickory_proto::rr::rdata::NULL::new();
            Ok(RData::NULL(null))
        }
    }
}

// 显示格式化的 DNS 响应
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
            println!("{} \t {} \t {}", 
                     query.name(), 
                     query.query_class(),
                     query.query_type());
        }
    }
    
    // 打印 Answer Section
    if !message.answers().is_empty() {
        println!("\n{}", ";; ANSWER SECTION:".bold());
        for record in message.answers() {
            if let Some(data) = record.data() {
                println!("{}\t{}\t{}\t{}\t{}", 
                     record.name(), 
                     record.ttl(),
                     record.dns_class(),
                     record.record_type(),
                     data);
            } else {
                println!("{}\t{}\t{}\t{}", 
                     record.name(), 
                     record.ttl(),
                     record.dns_class(),
                     record.record_type());
            }
        }
    }
    
    // 打印 Authority Section
    if !message.name_servers().is_empty() {
        println!("\n{}", ";; AUTHORITY SECTION:".bold());
        for record in message.name_servers() {
            if let Some(data) = record.data() {
                println!("{}\t{}\t{}\t{}\t{}", 
                     record.name(), 
                     record.ttl(),
                     record.dns_class(),
                     record.record_type(),
                     data);
            } else {
                println!("{}\t{}\t{}\t{}", 
                     record.name(), 
                     record.ttl(),
                     record.dns_class(),
                     record.record_type());
            }
        }
    }
    
    // 打印 Additional Section
    if !message.additionals().is_empty() {
        println!("\n{}", ";; ADDITIONAL SECTION:".bold());
        for record in message.additionals() {
            if let Some(data) = record.data() {
                println!("{}\t{}\t{}\t{}\t{}", 
                     record.name(), 
                     record.ttl(),
                     record.dns_class(),
                     record.record_type(),
                     data);
            } else {
                println!("{}\t{}\t{}\t{}", 
                     record.name(), 
                     record.ttl(),
                     record.dns_class(),
                     record.record_type());
            }
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
                // 使用 from_utf8_lossy 避免在UTF-8有效时克隆 raw_body
                // 它返回 Cow<str>，如果需要分配，它会这样做
                let json_str_cow = String::from_utf8_lossy(&response.raw_body);
                match json_str_cow {
                    std::borrow::Cow::Borrowed(json_str) => {
                        // 尝试格式化 JSON
                        match serde_json::from_str::<serde_json::Value>(json_str) {
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
                    std::borrow::Cow::Owned(json_str) => {
                        // 如果是 Owned，说明发生了替换，可以直接打印
                        // （虽然理论上 lossy 替换后可能不是有效的 JSON，但我们仍然尝试解析）
                        match serde_json::from_str::<serde_json::Value>(&json_str) {
                            Ok(json_value) => {
                                if let Ok(pretty_json) = serde_json::to_string_pretty(&json_value) {
                                    println!("{}", pretty_json);
                                } else {
                                    println!("{}", json_str); // 格式化失败，打印原始（可能已替换的）字符串
                                }
                            },
                            Err(_) => println!("{}\n;; Note: Original data contained invalid UTF-8 sequences.", json_str),
                        }
                    }
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

// 获取消息标志的描述
fn get_flags_description(message: &Message) -> String {
    let mut flags = Vec::new();
    
    // 修复 message.response() 不存在的问题
    if message.header().message_type() == MessageType::Response { flags.push("qr"); }
    if message.authoritative() { flags.push("aa"); }
    if message.truncated() { flags.push("tc"); }
    if message.recursion_desired() { flags.push("rd"); }
    if message.recursion_available() { flags.push("ra"); }
    if message.authentic_data() { flags.push("ad"); }
    if message.checking_disabled() { flags.push("cd"); }
    
    flags.join(" ")
}

// 打印十六进制转储
fn print_hex_dump(data: &[u8]) {
    // 预先计算一行的容量：8位地址 + ":" + 空格 + 空格 + 48字符(16字节×3) + 空格 + "|" + 16字符 + "|"
    const LINE_CAPACITY: usize = 8 + 1 + 1 + 1 + 48 + 1 + 1 + 16 + 1;
    
    for (i, chunk) in data.chunks(16).enumerate() {
        // 使用预分配容量减少重新分配
        let mut line = String::with_capacity(LINE_CAPACITY);
        
        // 添加地址部分
        write!(&mut line, "{:08x}:  ", i * 16).unwrap();
        
        // 十六进制部分
        for &b in chunk.iter() {
            write!(&mut line, "{:02x} ", b).unwrap();
        }
        
        // 对齐短行 - 计算剩余空间
        for _ in chunk.len()..16 {
            line.push_str("   ");
        }
        
        // 添加分隔符
        line.push_str(" |");
        
        // ASCII 部分
        for &b in chunk {
            // 优化：避免使用 if 判断，使用条件表达式
            line.push(if (32..=126).contains(&b) { b as char } else { '.' });
        }
        
        // 完成行
        line.push('|');
        
        // 一次性打印整行
        println!("{}", line);
    }
} 