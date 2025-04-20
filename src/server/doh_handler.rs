// src/server/doh_handler.rs

use std::net::IpAddr;
use std::sync::Arc;
use axum::{
    extract::{Query, State},
    http::{header, StatusCode, Request},
    response::IntoResponse,
    routing::{get, post},
    Router, Json,
};
use serde::{Deserialize, Serialize};
use tokio::time::Instant;
use trust_dns_proto::op::{Message, MessageType, OpCode, ResponseCode};
use trust_dns_proto::rr::{DNSClass, Name, RecordType};
use tracing::{debug, warn, info};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as BASE64_ENGINE};
use crate::common::error::{AppError, Result};
use crate::common::consts::{
    CONTENT_TYPE_DNS_JSON, 
    CONTENT_TYPE_DNS_MESSAGE,
    DNS_RECORD_TYPE_A, DNS_CLASS_IN, IP_HEADER_NAMES,
    MAX_REQUEST_SIZE,
};
use crate::server::cache::{CacheKey, DnsCache};
use crate::server::config::ServerConfig;
use crate::server::metrics::{DnsMetrics, METRICS};
use crate::server::upstream::UpstreamManager;


/// 共享的服务器状态
#[derive(Clone)]
pub struct ServerState {
    /// 配置
    pub config: ServerConfig,
    /// 上游解析管理器
    pub upstream: Arc<UpstreamManager>,
    /// DNS 缓存
    pub cache: Arc<DnsCache>,
    /// 指标收集器
    pub metrics: Arc<DnsMetrics>,
}

/// DNS-over-HTTPS JSON 请求参数
#[derive(Debug, Deserialize)]
pub struct DnsJsonRequest {
    /// 查询名称
    pub name: String,
    /// 查询类型
    #[serde(default = "default_record_type")]
    pub type_value: u16,
    /// 查询类
    #[serde(default = "default_dns_class")]
    pub dns_class: Option<u16>,
    /// 是否启用 DNSSEC
    #[serde(default)]
    pub dnssec: bool,
    /// 是否启用检查禁用
    #[serde(default)]
    pub cd: bool,
}

/// DNS-over-HTTPS GET 请求参数（RFC 8484）
#[derive(Debug, Deserialize)]
pub struct DnsMsgGetRequest {
    /// DNS 请求的 Base64url 编码
    pub dns: String,
}

/// DNS-over-HTTPS JSON 响应格式
#[derive(Debug, Serialize)]
pub struct DnsJsonResponse {
    /// 响应状态代码
    pub status: u16,
    /// 是否被截断
    #[serde(default)]
    pub tc: bool,
    /// 是否递归可用
    #[serde(default)]
    pub rd: bool,
    /// 是否递归期望
    #[serde(default)]
    pub ra: bool,
    /// 是否 AD 标志（DNSSEC 验证）
    #[serde(default)]
    pub ad: bool,
    /// 是否检查禁用
    #[serde(default)]
    pub cd: bool,
    /// 查询列表
    pub question: Vec<DnsJsonQuestion>,
    /// 应答记录列表
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub answer: Vec<DnsJsonAnswer>,
}

/// DNS-over-HTTPS JSON 查询
#[derive(Debug, Serialize)]
pub struct DnsJsonQuestion {
    /// 查询名称
    pub name: String,
    /// 查询类型
    pub type_value: u16,
}

/// DNS-over-HTTPS JSON 应答记录
#[derive(Debug, Serialize)]
pub struct DnsJsonAnswer {
    /// 记录名称
    pub name: String,
    /// 记录类型
    pub type_value: u16,
    /// 记录类
    pub class: u16,
    /// 生存时间（TTL）
    pub ttl: u32,
    /// 记录数据
    pub data: String,
}

/// 创建 DoH 路由
pub fn doh_routes(state: ServerState) -> Router {
    Router::new()
        // JSON API 路由（兼容性）
        .route("/resolve", get(handle_dns_json_query))
        // RFC 8484 标准路由
        .route("/dns-query", get(handle_dns_wire_get))
        .route("/dns-query", post(handle_dns_wire_post))
        // 添加状态
        .with_state(state)
}

/// 处理 DNS JSON 查询 (GET 请求，application/dns-json 兼容格式)
#[axum::debug_handler]
async fn handle_dns_json_query(
    State(state): State<ServerState>,
    Query(params): Query<DnsJsonRequest>,
    req: Request<axum::body::Body>,
) -> impl IntoResponse {
    // 提取客户端 IP
    let client_ip = get_client_ip_from_request(&req);
    
    // 记录开始时间
    let start = Instant::now();
    
    // 更新请求指标
    state.metrics.record_request("GET", CONTENT_TYPE_DNS_JSON);
    
    debug!(name = %params.name, type_value = params.type_value, client_ip = ?client_ip, "DNS JSON query received");
    
    // 创建 DNS 查询消息
    let query_message = match create_dns_message_from_json_request(&params) {
        Ok(msg) => msg,
        Err(e) => {
            // 记录请求错误
            info!(
                name = %params.name,
                type_value = params.type_value,
                client_ip = ?client_ip,
                error = %e,
                "DNS-over-HTTPS request parameter error"
            );
            return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
        }
    };
    
    // 发送/接收 DNS 查询响应
    let (response_message, is_cached) = match process_query(
        state.upstream.as_ref(),
        state.cache.as_ref(),
        &query_message,
        client_ip,
    ).await {
        Ok((msg, cached)) => (msg, cached),
        Err(e) => {
            // 记录处理错误
            info!(
                name = %params.name,
                type_value = params.type_value,
                client_ip = ?client_ip,
                error = %e,
                "DNS-over-HTTPS query processing failed"
            );
            return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
        }
    };
    
    // 转换为 JSON 响应
    let json_response = match dns_message_to_json_response(&response_message) {
        Ok(resp) => resp,
        Err(e) => {
            // 记录响应转换错误
            info!(
                name = %params.name,
                type_value = params.type_value,
                client_ip = ?client_ip,
                error = %e,
                "DNS-over-HTTPS response conversion failed"
            );
            return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
        }
    };
    
    // 更新响应指标
    let duration = start.elapsed();
    state.metrics.record_response(
        "GET",
        u16::from(response_message.response_code().low()),
        duration,
    );
    
    // 记录请求完成的详细日志
    let answer_count = json_response.answer.len();
    let rcode = response_message.response_code();
    let query_time_ms = duration.as_millis();
    
    info!(
        name = %params.name,
        type_value = params.type_value,
        client_ip = ?client_ip,
        response_code = ?rcode,
        answer_count = answer_count,
        dnssec_validated = response_message.authentic_data(),
        query_time_ms = query_time_ms,
        is_cached = is_cached,
        "DNS-over-HTTPS request completed"
    );
    
    // 只在调试级别时记录详细记录信息，减少运行时开销
    if !json_response.answer.is_empty() && tracing::enabled!(tracing::Level::DEBUG) {
        let record_details: Vec<String> = json_response.answer.iter()
            .map(|ans| format!("{}({}): {}", ans.name, RecordType::from(ans.type_value), ans.data))
            .collect();
            
        debug!(
            name = %params.name,
            client_ip = ?client_ip,
            records = ?record_details,
            "DNS-over-HTTPS response record details"
        );
    }
    
    // 返回 JSON 响应
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, CONTENT_TYPE_DNS_JSON)],
        Json(json_response),
    ).into_response()
}

/// 处理 DNS-over-HTTPS GET 请求 (RFC 8484 标准，application/dns-message)
#[axum::debug_handler]
async fn handle_dns_wire_get(
    State(state): State<ServerState>,
    Query(params): Query<DnsMsgGetRequest>,
    req: Request<axum::body::Body>,
) -> impl IntoResponse {
    // 提取客户端 IP
    let client_ip = get_client_ip_from_request(&req);
    
    // 记录开始时间
    let start = Instant::now();
    
    // 更新请求指标
    state.metrics.record_request("GET", CONTENT_TYPE_DNS_MESSAGE);
    
    debug!(client_ip = ?client_ip, "DNS GET RFC 8484 query received");
    
    // 解码 Base64url 查询参数
    let dns_wire = match BASE64_ENGINE.decode(&params.dns) {
        Ok(wire) => wire,
        Err(e) => {
            info!(client_ip = ?client_ip, error = ?e, "Invalid base64url encoding in DNS parameter");
            return (StatusCode::BAD_REQUEST, "Invalid base64url encoding").into_response();
        }
    };
    
    // 检查请求大小
    if dns_wire.len() > MAX_REQUEST_SIZE {
        info!(client_ip = ?client_ip, size = dns_wire.len(), "DNS request too large");
        return (StatusCode::BAD_REQUEST, "DNS request too large").into_response();
    }
    
    // 解析 DNS 查询消息
    let query_message = match Message::from_vec(&dns_wire) {
        Ok(msg) => msg,
        Err(e) => {
            info!(client_ip = ?client_ip, error = ?e, "Invalid DNS message in request");
            return (StatusCode::BAD_REQUEST, "Invalid DNS message format").into_response();
        }
    };
    
    // 处理查询
    let query_name = query_message.queries().first().map_or("unknown".to_string(), |q| q.name().to_string());
    let query_type = query_message.queries().first().map_or(0, |q| q.query_type().into());
    
    // 发送/接收 DNS 查询响应
    let (response_message, is_cached) = match process_query(
        state.upstream.as_ref(),
        state.cache.as_ref(),
        &query_message,
        client_ip,
    ).await {
        Ok((msg, cached)) => (msg, cached),
        Err(e) => {
            // 记录处理错误
            info!(
                name = %query_name,
                type_value = query_type,
                client_ip = ?client_ip,
                error = %e,
                "DNS-over-HTTPS wire query processing failed"
            );
            return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
        }
    };
    
    // 序列化响应
    let response_wire = match response_message.to_vec() {
        Ok(wire) => wire,
        Err(e) => {
            info!(
                name = %query_name,
                type_value = query_type,
                client_ip = ?client_ip,
                error = ?e,
                "Failed to serialize DNS response"
            );
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to serialize DNS response").into_response();
        }
    };
    
    // 更新响应指标
    let duration = start.elapsed();
    state.metrics.record_response(
        "GET",
        u16::from(response_message.response_code().low()),
        duration,
    );
    
    // 记录请求完成的详细日志
    let answer_count = response_message.answer_count();
    let rcode = response_message.response_code();
    let query_time_ms = duration.as_millis();
    
    info!(
        name = %query_name,
        type_value = query_type,
        client_ip = ?client_ip,
        response_code = ?rcode,
        answer_count = answer_count,
        dnssec_validated = response_message.authentic_data(),
        query_time_ms = query_time_ms,
        is_cached = is_cached,
        "DNS-over-HTTPS RFC 8484 GET request completed"
    );
    
    // 返回二进制响应
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, CONTENT_TYPE_DNS_MESSAGE)],
        response_wire,
    ).into_response()
}

/// 处理 DNS-over-HTTPS POST 请求 (RFC 8484 标准，application/dns-message)
#[axum::debug_handler]
async fn handle_dns_wire_post(
    State(state): State<ServerState>,
    req: Request<axum::body::Body>,
) -> impl IntoResponse {
    // 提取客户端 IP
    let client_ip = get_client_ip_from_request(&req);
    
    // 检查 Content-Type
    let content_type = req.headers().get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
        
    if content_type != CONTENT_TYPE_DNS_MESSAGE {
        info!(client_ip = ?client_ip, content_type = %content_type, "Invalid Content-Type in DNS POST request");
        return (StatusCode::BAD_REQUEST, "Invalid Content-Type, expected application/dns-message").into_response();
    }
    
    // 记录开始时间
    let start = Instant::now();
    
    // 更新请求指标
    state.metrics.record_request("POST", CONTENT_TYPE_DNS_MESSAGE);
    
    debug!(client_ip = ?client_ip, "DNS POST RFC 8484 query received");
    
    // 提取请求体 - 限制大小以防止资源耗尽攻击
    let (_parts, body) = req.into_parts();
    let body_bytes = match axum::body::to_bytes(body, MAX_REQUEST_SIZE).await {
        Ok(bytes) => bytes,
        Err(e) => {
            info!(client_ip = ?client_ip, error = ?e, "Failed to read request body");
            return (StatusCode::BAD_REQUEST, "Failed to read request body").into_response();
        }
    };
    
    // 如果请求体为空，返回错误
    if body_bytes.is_empty() {
        info!(client_ip = ?client_ip, "Empty request body");
        return (StatusCode::BAD_REQUEST, "Empty request body").into_response();
    }
    
    // 解析 DNS 查询消息
    let query_message = match Message::from_vec(&body_bytes) {
        Ok(msg) => msg,
        Err(e) => {
            info!(client_ip = ?client_ip, error = ?e, "Invalid DNS message in POST request body");
            return (StatusCode::BAD_REQUEST, "Invalid DNS message format").into_response();
        }
    };
    
    // 处理查询
    let query_name = query_message.queries().first().map_or("unknown".to_string(), |q| q.name().to_string());
    let query_type = query_message.queries().first().map_or(0, |q| q.query_type().into());
    
    // 发送/接收 DNS 查询响应
    let (response_message, is_cached) = match process_query(
        state.upstream.as_ref(),
        state.cache.as_ref(),
        &query_message,
        client_ip,
    ).await {
        Ok((msg, cached)) => (msg, cached),
        Err(e) => {
            // 记录处理错误
            info!(
                name = %query_name,
                type_value = query_type,
                client_ip = ?client_ip,
                error = %e,
                "DNS-over-HTTPS wire query processing failed"
            );
            return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
        }
    };
    
    // 序列化响应
    let response_wire = match response_message.to_vec() {
        Ok(wire) => wire,
        Err(e) => {
            info!(
                name = %query_name,
                type_value = query_type,
                client_ip = ?client_ip,
                error = ?e,
                "Failed to serialize DNS response"
            );
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to serialize DNS response").into_response();
        }
    };
    
    // 更新响应指标
    let duration = start.elapsed();
    state.metrics.record_response(
        "POST",
        u16::from(response_message.response_code().low()),
        duration,
    );
    
    // 记录请求完成的详细日志
    let answer_count = response_message.answer_count();
    let rcode = response_message.response_code();
    let query_time_ms = duration.as_millis();
    
    info!(
        name = %query_name,
        type_value = query_type,
        client_ip = ?client_ip,
        response_code = ?rcode,
        answer_count = answer_count,
        dnssec_validated = response_message.authentic_data(),
        query_time_ms = query_time_ms,
        is_cached = is_cached,
        "DNS-over-HTTPS RFC 8484 POST request completed"
    );
    
    // 返回二进制响应
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, CONTENT_TYPE_DNS_MESSAGE)],
        response_wire,
    ).into_response()
}

/// 从请求中提取客户端 IP
fn get_client_ip_from_request<T>(req: &Request<T>) -> IpAddr {
    // 尝试从 X-Forwarded-For 等头部提取客户端 IP
    let headers = req.headers();
    
    for header_name in &IP_HEADER_NAMES {
        if let Some(value) = headers.get(*header_name) {
            if let Ok(value_str) = value.to_str() {
                if let Some(ip) = value_str.split(',').next() {
                    if let Ok(ip_addr) = ip.trim().parse::<IpAddr>() {
                        return ip_addr;
                    }
                }
            }
        }
    }
    
    // 如果没有找到有效的 IP，使用传输层的源 IP
    match req.extensions().get::<axum::extract::ConnectInfo<std::net::SocketAddr>>() {
        Some(connect_info) => connect_info.ip(),
        None => std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)), // 默认为本地回环
    }
}

/// 处理 DNS 查询
async fn process_query(
    upstream: &UpstreamManager,
    cache: &DnsCache,
    query_message: &Message,
    _client_ip: IpAddr,
) -> Result<(Message, bool)> {  // 返回元组，第二个参数表示是否缓存命中
    // 检查查询消息是否有效
    if query_message.message_type() != MessageType::Query {
        return Err(AppError::Http("Not a query message type".to_string()));
    }
    
    // 仅在存在查询时才记录查询类型
    if let Some(query) = query_message.queries().first() {
        let query_type = query.query_type().to_string();
        METRICS.with(|m| m.record_dns_query_type(&query_type));
    } else {
        return Err(AppError::Http("No query found in message".to_string()));
    }
    
    // 从查询消息构建缓存键
    let cache_key = CacheKey::from(query_message);
    
    // 尝试从缓存获取响应
    if let Some(cached_response) = cache.get(&cache_key).await {
        debug!(?cache_key, "Cache hit");
        METRICS.with(|m| m.cache_hits.inc());
        
        // 创建新的响应消息，更新 ID 与查询消息匹配
        let mut response = cached_response.clone();
        response.set_id(query_message.id());
        
        // 记录DNS响应码
        let rcode = response.response_code().to_string();
        METRICS.with(|m| m.record_dns_rcode(&rcode));
        
        return Ok((response, true));  // 返回缓存命中标记
    }
    
    // 缓存未命中，转发到上游服务器
    debug!(?cache_key, "Cache miss, querying upstream server");
    METRICS.with(|m| m.cache_misses.inc());
    
    // 执行上游查询
    let start = Instant::now();
    let response = upstream.resolve(query_message).await?;
    let duration = start.elapsed();
    
    // 记录查询时间 - 使用 get_or_insert_with 避免不必要的字符串分配
    let resolver_info = match query_message.queries().first() {
        Some(query) => format!("{}:{}", query.name(), query.query_type()),
        None => "unknown".to_string(),
    };
    
    METRICS.with(|m| m.record_upstream_query(&resolver_info, duration));
    
    // 记录 DNS 响应码
    let rcode = response.response_code().to_string();
    METRICS.with(|m| m.record_dns_rcode(&rcode));
    
    // 记录 DNSSEC 验证结果
    METRICS.with(|m| m.record_dnssec_validation(response.authentic_data()));
    
    // 将响应存入缓存（只缓存成功的响应）
    let rcode = response.response_code();
    if rcode == ResponseCode::NoError || rcode == ResponseCode::NXDomain {
        if let Err(e) = cache.put(cache_key, response.clone()).await {
            warn!(error = ?e, "Cache response failed");
        }
    } else {
        // 记录错误响应类型
        debug!(
            rcode = ?response.response_code(),
            "DNS error response"
        );
    }
    
    Ok((response, false))  // 返回非缓存命中标记
}

/// 从 JSON 请求创建 DNS 查询消息
fn create_dns_message_from_json_request(request: &DnsJsonRequest) -> Result<Message> {
    // 解析域名 - 验证输入域名的合法性
    let name = match Name::parse(&request.name, None) {
        Ok(name) => name,
        Err(e) => {
            return Err(AppError::Http(format!("Invalid domain name: {}", e)));
        }
    };
    
    // 解析记录类型
    let rtype = match RecordType::from(request.type_value) {
        RecordType::Unknown(..) => {
            return Err(AppError::Http(format!("Invalid record type: {}", request.type_value)));
        }
        rt => rt,
    };
    
    // 解析 DNS 类
    let _dns_class = match request.dns_class {
        Some(class) => {
            // 检查已知有效的 DNS 类型
            match class {
                1 | 3 | 4 | 254 | 255 => DNSClass::from_u16(class),
                _ => return Err(AppError::Http(format!("Invalid DNS class: {}", class))),
            }
        },
        None => Ok(DNSClass::IN),
    }?;
    
    // 创建 DNS 查询消息 - 使用 fastrand 提高性能
    let mut message = Message::new();
    message
        .set_id(fastrand::u16(..))
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .set_checking_disabled(request.cd)
        .set_recursion_desired(true);
        
    // 添加查询
    let query = trust_dns_proto::op::Query::query(name, rtype);
    message.add_query(query);
    
    Ok(message)
}

/// 将 DNS 响应消息转换为 JSON 响应
fn dns_message_to_json_response(message: &Message) -> Result<DnsJsonResponse> {
    // 创建响应对象
    let mut response = DnsJsonResponse {
        status: u16::from(message.response_code().low()),
        tc: message.truncated(),
        rd: message.recursion_desired(),
        ra: message.recursion_available(),
        ad: message.authentic_data(),
        cd: message.checking_disabled(),
        question: Vec::new(),
        answer: Vec::new(),
    };
    
    // 预先分配容量以减少内存重分配
    let query_count = message.queries().len();
    let answer_count = message.answers().len();
    response.question.reserve(query_count);
    response.answer.reserve(answer_count);
    
    // 添加查询
    for query in message.queries() {
        response.question.push(DnsJsonQuestion {
            name: query.name().to_string(),
            type_value: query.query_type().into(),
        });
    }
    
    // 添加应答记录
    for record in message.answers() {
        let data = match record.data() {
            Some(rdata) => rdata.to_string(),
            None => continue,
        };
        
        response.answer.push(DnsJsonAnswer {
            name: record.name().to_string(),
            type_value: record.record_type().into(),
            class: record.dns_class().into(),
            ttl: record.ttl(),
            data,
        });
    }
    
    Ok(response)
}

// 默认值函数
fn default_record_type() -> u16 {
    DNS_RECORD_TYPE_A
}

fn default_dns_class() -> Option<u16> {
    Some(DNS_CLASS_IN)
}
