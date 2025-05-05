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
use crate::server::error::{ServerError, Result};
use crate::common::consts::{
    CONTENT_TYPE_DNS_JSON, 
    CONTENT_TYPE_DNS_MESSAGE,
    DNS_RECORD_TYPE_A, DNS_CLASS_IN, IP_HEADER_NAMES,
    MAX_REQUEST_SIZE,
    BLACKHOLE_UPSTREAM_GROUP_NAME,
};
use crate::server::cache::{CacheKey, DnsCache};
use crate::server::config::ServerConfig;
use crate::server::metrics::{DnsMetrics, METRICS};
use crate::server::routing::{Router, RouteDecision};
use crate::server::upstream::{UpstreamManager, UpstreamSelection};


// 共享的服务器状态
#[derive(Clone)]
pub struct ServerState {
    // 配置
    pub config: ServerConfig,
    // 上游解析管理器
    pub upstream: Arc<UpstreamManager>,
    // DNS 路由器
    pub router: Arc<Router>,
    // DNS 缓存
    pub cache: Arc<DnsCache>,
    // 指标收集器
    pub metrics: Arc<DnsMetrics>,
}

// DNS-over-HTTPS JSON 请求参数
#[derive(Debug, Deserialize)]
pub struct DnsJsonRequest {
    // 查询名称
    pub name: String,
    // 查询类型
    #[serde(default = "default_record_type")]
    pub type_value: u16,
    // 查询类
    #[serde(default = "default_dns_class")]
    pub dns_class: Option<u16>,
    // 是否启用 DNSSEC
    #[serde(default)]
    pub dnssec: bool,
    // 是否启用检查禁用
    #[serde(default)]
    pub cd: bool,
}

// DNS-over-HTTPS GET 请求参数（RFC 8484）
#[derive(Debug, Deserialize)]
pub struct DnsMsgGetRequest {
    // DNS 请求的 Base64url 编码
    pub dns: String,
}

// DNS-over-HTTPS JSON 响应格式
#[derive(Debug, Serialize)]
pub struct DnsJsonResponse {
    // 响应状态代码
    pub status: u16,
    // 是否被截断
    #[serde(default)]
    pub tc: bool,
    // 是否递归可用
    #[serde(default)]
    pub rd: bool,
    // 是否递归期望
    #[serde(default)]
    pub ra: bool,
    // 是否 AD 标志（DNSSEC 验证）
    #[serde(default)]
    pub ad: bool,
    // 是否检查禁用
    #[serde(default)]
    pub cd: bool,
    // 查询列表
    pub question: Vec<DnsJsonQuestion>,
    // 应答记录列表
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub answer: Vec<DnsJsonAnswer>,
}

// DNS-over-HTTPS JSON 查询
#[derive(Debug, Serialize)]
pub struct DnsJsonQuestion {
    // 查询名称
    pub name: String,
    // 查询类型
    pub type_value: u16,
}

// DNS-over-HTTPS JSON 应答记录
#[derive(Debug, Serialize)]
pub struct DnsJsonAnswer {
    // 记录名称
    pub name: String,
    // 记录类型
    pub type_value: u16,
    // 记录类
    pub class: u16,
    // 生存时间（TTL）
    pub ttl: u32,
    // 记录数据
    pub data: String,
}

// 创建 DoH 路由
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

// 处理 DNS JSON 查询 (GET 请求，application/dns-json 兼容格式)
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
        state.router.as_ref(),
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

// 处理 DNS GET 请求（RFC 8484）
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
    
    debug!(client_ip = ?client_ip, "DNS-over-HTTPS GET request received");
    
    // 解码请求参数中的 DNS 消息（Base64url 编码）
    let query_message = match BASE64_ENGINE.decode(&params.dns) {
        Ok(data) => {
            match Message::from_vec(&data) {
                Ok(msg) => msg,
                Err(e) => {
                    info!(
                        client_ip = ?client_ip,
                        error = %e,
                        "Failed to parse DNS message from base64"
                    );
                    return (StatusCode::BAD_REQUEST, "Invalid DNS message format").into_response();
                }
            }
        },
        Err(e) => {
            info!(
                client_ip = ?client_ip,
                error = %e,
                "Failed to decode base64 DNS query parameter"
            );
            return (StatusCode::BAD_REQUEST, "Invalid base64 encoding").into_response();
        }
    };
    
    // 从查询获取域名（用于日志）
    let domain = query_message.queries().first().map_or_else(
        || String::from("unknown"), 
        |q| q.name().to_string()
    );
    
    // 处理查询
    let (response_message, is_cached) = match process_query(
        state.upstream.as_ref(),
        state.router.as_ref(),
        state.cache.as_ref(),
        &query_message,
        client_ip,
    ).await {
        Ok((msg, cached)) => (msg, cached),
        Err(e) => {
            info!(
                domain = %domain,
                client_ip = ?client_ip,
                error = %e,
                "DNS-over-HTTPS wire query processing failed"
            );
            return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
        }
    };
    
    // 将响应消息转换为二进制格式
    let response_bytes = match response_message.to_vec() {
        Ok(bytes) => bytes,
        Err(e) => {
            info!(
                domain = %domain,
                client_ip = ?client_ip,
                error = %e,
                "Failed to serialize DNS response message"
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
    
    // 记录请求完成
    let qtype = query_message.queries().first().map_or_else(
        || String::from("unknown"), 
        |q| format!("{:?}", q.query_type())
    );
    
    let answer_count = response_message.answer_count();
    let rcode = response_message.response_code();
    let query_time_ms = duration.as_millis();
    
    info!(
        domain = %domain,
        qtype = %qtype,
        client_ip = ?client_ip,
        answer_count = answer_count,
        response_code = ?rcode,
        dnssec_validated = response_message.authentic_data(),
        query_time_ms = query_time_ms,
        is_cached = is_cached,
        "DNS-over-HTTPS wire GET request completed"
    );
    
    // 返回响应
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, CONTENT_TYPE_DNS_MESSAGE)],
        response_bytes,
    ).into_response()
}

// 处理 DNS POST 请求（RFC 8484）
#[axum::debug_handler]
async fn handle_dns_wire_post(
    State(state): State<ServerState>,
    req: Request<axum::body::Body>,
) -> impl IntoResponse {
    // 提取客户端 IP
    let client_ip = get_client_ip_from_request(&req);
    
    // 记录开始时间
    let start = Instant::now();
    
    // 更新请求指标
    state.metrics.record_request("POST", CONTENT_TYPE_DNS_MESSAGE);
    
    debug!(client_ip = ?client_ip, "DNS-over-HTTPS POST request received");
    
    // 验证内容类型
    let is_valid_content_type = req.headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.starts_with(CONTENT_TYPE_DNS_MESSAGE))
        .unwrap_or(false);
        
    if !is_valid_content_type {
        info!(
            client_ip = ?client_ip,
            "Invalid content type for DNS-over-HTTPS POST request"
        );
        return (StatusCode::UNSUPPORTED_MEDIA_TYPE, "Invalid content type").into_response();
    }
    
    // 读取请求体
    let body_bytes = match hyper::body::to_bytes(req.into_body()).await {
        Ok(bytes) => bytes,
        Err(e) => {
            info!(
                client_ip = ?client_ip,
                error = %e,
                "Failed to read DNS-over-HTTPS POST request body"
            );
            return (StatusCode::BAD_REQUEST, "Failed to read request body").into_response();
        }
    };
    
    // 检查请求大小
    if body_bytes.len() > MAX_REQUEST_SIZE {
        info!(
            client_ip = ?client_ip,
            size = body_bytes.len(),
            max_size = MAX_REQUEST_SIZE,
            "DNS-over-HTTPS POST request body too large"
        );
        return (StatusCode::PAYLOAD_TOO_LARGE, "Request body too large").into_response();
    }
    
    // 解析 DNS 消息
    let query_message = match Message::from_vec(&body_bytes) {
        Ok(msg) => msg,
        Err(e) => {
            info!(
                client_ip = ?client_ip,
                error = %e,
                "Failed to parse DNS message from POST body"
            );
            return (StatusCode::BAD_REQUEST, "Invalid DNS message format").into_response();
        }
    };
    
    // 从查询获取域名（用于日志）
    let domain = query_message.queries().first().map_or_else(
        || String::from("unknown"), 
        |q| q.name().to_string()
    );
    
    // 处理查询
    let (response_message, is_cached) = match process_query(
        state.upstream.as_ref(),
        state.router.as_ref(),
        state.cache.as_ref(),
        &query_message,
        client_ip,
    ).await {
        Ok((msg, cached)) => (msg, cached),
        Err(e) => {
            info!(
                domain = %domain,
                client_ip = ?client_ip,
                error = %e,
                "DNS-over-HTTPS wire query processing failed"
            );
            return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
        }
    };
    
    // 将响应消息转换为二进制格式
    let response_bytes = match response_message.to_vec() {
        Ok(bytes) => bytes,
        Err(e) => {
            info!(
                domain = %domain,
                client_ip = ?client_ip,
                error = %e,
                "Failed to serialize DNS response message"
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
    
    // 记录请求完成
    let qtype = query_message.queries().first().map_or_else(
        || String::from("unknown"), 
        |q| format!("{:?}", q.query_type())
    );
    
    let answer_count = response_message.answer_count();
    let rcode = response_message.response_code();
    let query_time_ms = duration.as_millis();
    
    info!(
        domain = %domain,
        qtype = %qtype,
        client_ip = ?client_ip,
        answer_count = answer_count,
        response_code = ?rcode,
        dnssec_validated = response_message.authentic_data(),
        query_time_ms = query_time_ms,
        is_cached = is_cached,
        "DNS-over-HTTPS wire POST request completed"
    );
    
    // 返回响应
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, CONTENT_TYPE_DNS_MESSAGE)],
        response_bytes,
    ).into_response()
}

// 从请求中提取客户端 IP
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

// 处理 DNS 查询
async fn process_query(
    upstream: &UpstreamManager,
    router: &Router,
    cache: &DnsCache,
    query_message: &Message,
    client_ip: IpAddr,
) -> Result<(Message, bool)> {  // 返回元组，第二个参数表示是否缓存命中
    // 检查查询消息
    let queries = query_message.queries();
    if queries.is_empty() {
        return Err(ServerError::Other("No queries in DNS message".to_string()));
    }
    
    // 获取DNS查询域名和类型
    let query = &queries[0];
    let domain = query.name().to_string();
    let qtype = query.query_type();
    
    debug!(domain = %domain, qtype = ?qtype, "Processing DNS query");
    
    // 创建缓存键
    let cache_key = CacheKey::new(query.name().clone(), query.query_type(), query.query_class());
    
    // 检查缓存
    if cache.is_enabled() {
        if let Some(cached_message) = cache.get(&cache_key).await {
            debug!(domain = %domain, qtype = ?qtype, "Cache hit");
            
            // 记录缓存命中指标
            METRICS.with(|m| m.record_cache_hit());
            
            // 克隆缓存的消息并复制原始查询的ID
            let mut response = cached_message.clone();
            response.set_id(query_message.id());
            
            return Ok((response, true));
        }
        
        // 记录缓存未命中指标
        METRICS.with(|m| m.record_cache_miss());
    }
    
    // 查询域名并获取路由决策
    let route_decision = router.match_domain(&domain).await;
    
    debug!(domain = %domain, qtype = ?qtype, decision = ?route_decision, "DNS routing decision");
    
    // 处理黑洞决策
    if route_decision == RouteDecision::Blackhole {
        info!(domain = %domain, "Query blocked by blackhole rule");
        
        // 记录被黑洞规则阻止的请求
        METRICS.with(|m| m.record_blackhole_request());
        
        // 记录DNS响应代码
        METRICS.with(|m| m.record_dns_rcode("NXDomain"));
        
        // 创建 NXDOMAIN 响应
        let mut response = Message::new();
        response.set_id(query_message.id());
        response.set_message_type(MessageType::Response);
        response.set_op_code(query_message.op_code());
        response.set_response_code(ResponseCode::NXDomain); // 不存在的域名
        response.set_recursion_desired(query_message.recursion_desired());
        response.set_recursion_available(true);
        response.add_query(query.clone());
        
        // 如果启用了缓存，使用负缓存 TTL 进行缓存
        if cache.is_enabled() {
            cache.put(&cache_key, &response, cache.negative_ttl()).await;
        }
        
        return Ok((response, false));
    }
    
    // 将路由决策转换为上游选择
    let upstream_selection = match route_decision {
        RouteDecision::UseGroup(group_name) => {
            debug!(domain = %domain, group = %group_name, "Using upstream group");
            UpstreamSelection::Group(group_name)
        },
        RouteDecision::UseGlobal => {
            debug!(domain = %domain, "Using global upstream");
            UpstreamSelection::Global
        },
        RouteDecision::Blackhole => unreachable!(), // 已经在上面处理过
    };
    
    // 执行上游查询
    let response_message = upstream.resolve(query_message, upstream_selection).await?;
    
    // 记录DNS响应代码
    METRICS.with(|m| m.record_dns_rcode(&response_message.response_code().to_string()));
    
    // 缓存结果（如果启用）
    if cache.is_enabled() {
        let ttl = cache.calculate_ttl(&response_message);
        cache.put(&cache_key, &response_message, ttl).await;
    }
    
    Ok((response_message, false))
}

// 从 JSON 请求创建 DNS 查询消息
fn create_dns_message_from_json_request(request: &DnsJsonRequest) -> Result<Message> {
    // 解析域名 - 验证输入域名的合法性
    let name = match Name::parse(&request.name, None) {
        Ok(name) => name,
        Err(e) => {
            return Err(ServerError::Http(format!("Invalid domain name: {}", e)));
        }
    };
    
    // 解析记录类型
    let rtype = match RecordType::from(request.type_value) {
        RecordType::Unknown(..) => {
            return Err(ServerError::Http(format!("Invalid record type: {}", request.type_value)));
        }
        rt => rt,
    };
    
    // 解析 DNS 类
    let _dns_class = match request.dns_class {
        Some(class) => {
            // 检查已知有效的 DNS 类型
            match class {
                1 | 3 | 4 | 254 | 255 => DNSClass::from_u16(class),
                _ => return Err(ServerError::Http(format!("Invalid DNS class: {}", class))),
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

// 将 DNS 响应消息转换为 JSON 响应
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
