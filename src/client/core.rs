// src/client/runner.rs

// 该模块包含执行 DoH 查询的核心业务逻辑。
// 它将协调 `args`, `request`, `response` 等模块的功能。
//
// 主要流程：
// 1. 接收解析后的命令行参数 (`args::CliArgs`)。
// 2. 初始化 HTTP 客户端 (`reqwest::Client`)，可能需要根据参数配置 (例如 `--insecure`)。
// 3. 调用 `request::build_doh_request` 构建 HTTP 请求。
// 4. 使用 HTTP 客户端发送请求到 DoH 服务器。
// 5. 记录请求耗时。
// 6. 调用 `response::parse_doh_response` 解析收到的 HTTP 响应。
// 7. 调用 `response::display_response` 或类似函数来格式化并打印结果或错误信息。
// 8. 处理整个流程中可能出现的 `error::ClientError`。

use crate::client::args::CliArgs;
use crate::client::error::{ClientError, ClientResult};
use crate::client::{request, response};
use crate::client::response::DohResponse;
use crate::common::consts::DEFAULT_HTTP_CLIENT_TIMEOUT;
use colored::Colorize;
use regex::Regex;
use reqwest::Client;
use std::str::FromStr;
use std::time::{Duration, Instant};
use trust_dns_proto::op::ResponseCode;
use trust_dns_proto::rr::RecordType;

// 解析 ResponseCode 的方式
fn parse_response_code(code: &str) -> Result<ResponseCode, ClientError> {
    // 直接匹配常见的响应码
    match code.to_uppercase().as_str() {
        "NOERROR" => Ok(ResponseCode::NoError),
        "FORMERR" => Ok(ResponseCode::FormErr),
        "SERVFAIL" => Ok(ResponseCode::ServFail),
        "NXDOMAIN" => Ok(ResponseCode::NXDomain),
        "NOTIMP" => Ok(ResponseCode::NotImp),
        "REFUSED" => Ok(ResponseCode::Refused),
        "YXDOMAIN" => Ok(ResponseCode::YXDomain),
        "YXRRSET" => Ok(ResponseCode::YXRRSet),
        "NXRRSET" => Ok(ResponseCode::NXRRSet),
        "NOTAUTH" => Ok(ResponseCode::NotAuth),
        "NOTZONE" => Ok(ResponseCode::NotZone),
        "BADVERS" => Ok(ResponseCode::BADVERS),
        "BADSIG" => Ok(ResponseCode::BADSIG),
        "BADKEY" => Ok(ResponseCode::BADKEY),
        "BADTIME" => Ok(ResponseCode::BADTIME),
        _ => Err(ClientError::InvalidArgument(format!("Unknown response code: {}", code))),
    }
}

// 验证条件类型
#[derive(Debug, Clone, PartialEq)]
pub enum ValidationCondition {
    // 期望的响应码
    ResponseCode(ResponseCode),
    // 期望包含的 IP 地址
    ContainsIP(String),
    // 期望最小的 TTL 值
    MinTTL(u32),
    // 期望至少有多少条回答记录
    MinAnswers(usize),
    // 期望响应中包含特定记录类型
    HasRecordType(RecordType),
    // 期望记录中包含特定的文本
    ContainsText(String),
    // 期望 DNSSEC 验证通过 (AD 位设置)
    DnssecValidated,
}

impl FromStr for ValidationCondition {
    type Err = ClientError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // 解析验证条件字符串
        // 格式: rcode=NOERROR, has-ip=1.2.3.4, min-ttl=300, min-answers=1, has-type=A, contains=example, dnssec-validated
        
        let s = s.trim();
        
        if let Some(code) = s.strip_prefix("rcode=") {
            // 响应码
            return parse_response_code(code).map(ValidationCondition::ResponseCode);
        }
        
        if let Some(ip) = s.strip_prefix("has-ip=") {
            // IP 地址
            return Ok(ValidationCondition::ContainsIP(ip.to_string()));
        }
        
        if let Some(ttl_str) = s.strip_prefix("min-ttl=") {
            // TTL 值
            match ttl_str.parse::<u32>() {
                Ok(ttl) => return Ok(ValidationCondition::MinTTL(ttl)),
                Err(_) => return Err(ClientError::InvalidArgument(format!("Invalid TTL value: {}", ttl_str))),
            }
        }
        
        if let Some(count_str) = s.strip_prefix("min-answers=") {
            // 回答记录数
            match count_str.parse::<usize>() {
                Ok(count) => return Ok(ValidationCondition::MinAnswers(count)),
                Err(_) => return Err(ClientError::InvalidArgument(format!("Invalid answer count: {}", count_str))),
            }
        }
        
        if let Some(type_str) = s.strip_prefix("has-type=") {
            // 记录类型
            match RecordType::from_str(type_str) {
                Ok(record_type) => return Ok(ValidationCondition::HasRecordType(record_type)),
                Err(_) => return Err(ClientError::InvalidArgument(format!("Invalid record type: {}", type_str))),
            }
        }
        
        if let Some(text) = s.strip_prefix("contains=") {
            // 包含文本
            return Ok(ValidationCondition::ContainsText(text.to_string()));
        }
        
        if s == "dnssec-validated" {
            // DNSSEC 验证
            return Ok(ValidationCondition::DnssecValidated);
        }
        
        Err(ClientError::InvalidArgument(format!("Invalid validation condition: {}", s)))
    }
}

// 执行 DoH 查询
pub async fn run_query(args: CliArgs) -> ClientResult<()> {
    // 1. 初始化 HTTP 客户端
    let http_client = build_http_client(&args)?;
    
    // 2. 构建请求
    let request = request::build_doh_request(&args, &http_client).await?;
    
    if args.verbose >= 3 {
        eprintln!("Sending request to {}...", args.server_url);
    }
    
    // 3. 发送请求并计时
    let start_time = Instant::now();
    let http_response = http_client.execute(request).await?;
    let duration = start_time.elapsed();
    
    if args.verbose >= 3 {
        eprintln!("Received response in {:?}.", duration);
    }
    
    // 4. 解析响应
    let mut doh_response = response::parse_doh_response(http_response).await?;
    doh_response.duration = duration; // 设置耗时
    
    // 5. 显示结果
    response::display_response(&doh_response, args.verbose);
    
    // 6. 验证结果
    if let Some(validation_conditions) = &args.validate {
        println!("\n{}", ";; Validating Response:".bold());
        
        let parsed_conditions = parse_validation_conditions(validation_conditions)?;
        validate_response(&doh_response, &parsed_conditions)?;
        
        // 如果验证通过，打印成功消息
        println!("{}", "All validation conditions passed!".green().bold());
    }
    
    Ok(())
}

// 解析验证条件字符串
fn parse_validation_conditions(validation_str: &str) -> ClientResult<Vec<ValidationCondition>> {
    let mut conditions = Vec::new();
    
    // 按逗号分隔条件
    for condition_str in validation_str.split(',') {
        let condition = ValidationCondition::from_str(condition_str.trim())?;
        conditions.push(condition);
    }
    
    if conditions.is_empty() {
        return Err(ClientError::InvalidArgument("No validation conditions specified".to_string()));
    }
    
    Ok(conditions)
}

// 验证 DoH 响应是否符合指定条件
fn validate_response(response: &DohResponse, conditions: &[ValidationCondition]) -> ClientResult<()> {
    let message = &response.message;
    
    for condition in conditions {
        match condition {
            ValidationCondition::ResponseCode(expected_rcode) => {
                let actual_rcode = message.response_code();
                if &actual_rcode != expected_rcode {
                    return Err(ClientError::Other(format!(
                        "Response code validation failed: expected {:?}, got {:?}", expected_rcode, actual_rcode
                    )));
                }
                println!("✓ {}: {:?}", "Response code".green(), expected_rcode);
            },
            ValidationCondition::ContainsIP(expected_ip) => {
                let mut found = false;
                
                // 检查 A 和 AAAA 记录
                for record in message.answers() {
                    if let Some(rdata) = record.data() {
                        let rdata_str = format!("{}", rdata);
                        if rdata_str.contains(expected_ip) {
                            found = true;
                            break;
                        }
                    }
                }
                
                if !found {
                    return Err(ClientError::Other(format!(
                        "IP address validation failed: expected to find {}", expected_ip
                    )));
                }
                println!("✓ {}: {}", "Contains IP".green(), expected_ip);
            },
            ValidationCondition::MinTTL(min_ttl) => {
                let mut all_above_min = true;
                
                for record in message.answers() {
                    if record.ttl() < *min_ttl {
                        all_above_min = false;
                        break;
                    }
                }
                
                if !all_above_min {
                    return Err(ClientError::Other(format!(
                        "TTL validation failed: expected minimum TTL of {}", min_ttl
                    )));
                }
                println!("✓ {}: {}", "Minimum TTL".green(), min_ttl);
            },
            ValidationCondition::MinAnswers(min_count) => {
                let actual_count = message.answers().len();
                if actual_count < *min_count {
                    return Err(ClientError::Other(format!(
                        "Answer count validation failed: expected at least {}, got {}", min_count, actual_count
                    )));
                }
                println!("✓ {}: {} (actual: {})", "Minimum answers".green(), min_count, actual_count);
            },
            ValidationCondition::HasRecordType(expected_type) => {
                let mut found = false;
                
                for record in message.answers() {
                    if record.record_type() == *expected_type {
                        found = true;
                        break;
                    }
                }
                
                if !found {
                    return Err(ClientError::Other(format!(
                        "Record type validation failed: expected to find {:?} record", expected_type
                    )));
                }
                println!("✓ {}: {:?}", "Has record type".green(), expected_type);
            },
            ValidationCondition::ContainsText(expected_text) => {
                let mut found = false;
                
                // 转换为正则表达式进行匹配
                let regex = match Regex::new(expected_text) {
                    Ok(r) => r,
                    Err(_) => return Err(ClientError::InvalidArgument(format!(
                        "Invalid regex pattern: {}", expected_text
                    ))),
                };
                
                // 检查所有记录
                for record in message.answers() {
                    if let Some(rdata) = record.data() {
                        let rdata_str = format!("{}", rdata);
                        if regex.is_match(&rdata_str) {
                            found = true;
                            break;
                        }
                    }
                }
                
                if !found {
                    return Err(ClientError::Other(format!(
                        "Text content validation failed: expected to match pattern '{}'", expected_text
                    )));
                }
                println!("✓ {}: '{}'", "Contains text".green(), expected_text);
            },
            ValidationCondition::DnssecValidated => {
                if !message.authentic_data() {
                    return Err(ClientError::Other(
                        "DNSSEC validation failed: AD bit not set in response".to_string()
                    ));
                }
                println!("✓ {}", "DNSSEC validated (AD bit set)".green());
            },
        }
    }
    
    Ok(())
}

// 构建配置好的 HTTP 客户端
fn build_http_client(args: &CliArgs) -> ClientResult<Client> {
    let mut client_builder = Client::builder()
        .timeout(Duration::from_secs(DEFAULT_HTTP_CLIENT_TIMEOUT));
    
    // 根据参数设置客户端配置
    
    // 如果 --insecure 参数被设置，禁用 TLS 证书验证
    if args.insecure {
        client_builder = client_builder
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true); // 增加接受无效主机名的设置
    }
    
    // 构建客户端
    client_builder.build().map_err(|e| ClientError::HttpClientError(format!("{}", e)))
}

// 打印错误消息
pub fn print_error(error: &ClientError) {
    eprintln!("{} {}", "Error:".red().bold(), error);
    
    // 提供一些额外的上下文信息
    match error {
        ClientError::InvalidArgument(_) => {
            eprintln!("Please check if the command line arguments are correct. Use --help to view help information.");
        }
        ClientError::HttpClientError(_) => {
            eprintln!("Please check your network connection and server URL. Use -k parameter to skip TLS certificate verification.");
        }
        ClientError::UrlError(_) => {
            eprintln!("Please ensure you have provided the correct URL, including protocol prefix (https://) and path (/dns-query).");
        }
        _ => {
            // 通用提示
            eprintln!("Use -v parameter to view more detailed information.");
        }
    }
}
