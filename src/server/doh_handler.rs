// src/server/doh_handler.rs

use axum::{
    body::{Bytes, to_bytes},
    extract::{Path, Query, State},
    http::{header, StatusCode, Request},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router, Json, body::Body,
};
use hyper;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::time::Instant;
use trust_dns_proto::op::{Message, MessageType, OpCode, ResponseCode};
use trust_dns_proto::rr::{DNSClass, Name, RecordType};
use tracing::{debug, error, info, trace, warn};
use std::str::FromStr;

use crate::common::error::{AppError, Result};
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
        .route("/dns-query", get(handle_dns_json_query).post(handle_dns_message_query))
        .with_state(state)
}

/// 处理 DNS JSON 查询 (GET 请求)
#[axum::debug_handler]
async fn handle_dns_json_query(
    State(state): State<ServerState>,
    Query(params): Query<DnsJsonRequest>,
) -> impl IntoResponse {
    // 提取客户端 IP
    let client_ip = get_client_ip_from_request(&Request::new(()));
    
    // 记录开始时间
    let start = Instant::now();
    
    // 更新请求指标
    state.metrics.record_request("GET", "application/dns-json");
    
    debug!(name = %params.name, type_value = params.type_value, client_ip = ?client_ip, "DNS JSON query received");
    
    // 创建 DNS 查询消息
    let query_message = match create_dns_message_from_json_request(&params) {
        Ok(msg) => msg,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    
    // 发送/接收 DNS 查询响应
    let response_message = match process_query(
        state.upstream.as_ref(),
        state.cache.as_ref(),
        &query_message,
        client_ip,
    ).await {
        Ok(msg) => msg,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    
    // 转换为 JSON 响应
    let json_response = match dns_message_to_json_response(&response_message) {
        Ok(resp) => resp,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    
    // 更新响应指标
    let duration = start.elapsed();
    state.metrics.record_response(
        "GET",
        u16::from(response_message.response_code().low()),
        duration,
    );
    
    // 返回 JSON 响应
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/dns-json")],
        Json(json_response),
    ).into_response()
}

/// 处理 DNS 二进制消息查询 (POST 请求)
#[axum::debug_handler]
async fn handle_dns_message_query(
    State(state): State<ServerState>,
    req: Request<Body>,
) -> impl IntoResponse {
    // 提取客户端 IP
    let client_ip = get_client_ip_from_request(&req);
    
    // 记录开始时间
    let start = Instant::now();
    
    // 更新请求指标
    state.metrics.record_request("POST", "application/dns-message");
    
    // 提取请求体
    let bytes = match to_bytes(req.into_body(), 4096).await {
        Ok(bytes) => bytes,
        Err(e) => {
            error!(error = ?e, "Failed to read request body");
            state.metrics.record_error("read_body");
            return (StatusCode::BAD_REQUEST, format!("Failed to read request body: {}", e)).into_response();
        }
    };
    
    // 解析 DNS 查询消息
    let query_message = match Message::from_vec(&bytes) {
        Ok(msg) => msg,
        Err(e) => {
            error!(error = ?e, "Failed to parse DNS query message");
            state.metrics.record_error("decode_request");
            return (StatusCode::BAD_REQUEST, format!("Failed to parse DNS query message: {}", e)).into_response();
        }
    };
    
    // 记录查询信息
    if let Some(query) = query_message.queries().first() {
        debug!(
            name = %query.name(),
            type_value = ?query.query_type(),
            client_ip = ?client_ip,
            "DNS wire format query received"
        );
    }
    
    // 处理 DNS 查询
    let response_message = match process_query(
        state.upstream.as_ref(),
        state.cache.as_ref(),
        &query_message,
        client_ip,
    ).await {
        Ok(msg) => msg,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    
    // 将响应消息转换为字节
    let response_bytes = match response_message.to_vec() {
        Ok(bytes) => bytes,
        Err(e) => {
            error!(error = ?e, "Failed to encode DNS response message");
            state.metrics.record_error("encode_response");
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to encode DNS response message: {}", e)).into_response();
        }
    };
    
    // 更新响应指标
    let duration = start.elapsed();
    state.metrics.record_response(
        "POST",
        u16::from(response_message.response_code().low()),
        duration,
    );
    
    // 返回二进制响应
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/dns-message")],
        response_bytes,
    ).into_response()
}

/// 从请求中提取客户端 IP
fn get_client_ip_from_request<T>(req: &Request<T>) -> IpAddr {
    // 尝试从 X-Forwarded-For 等头部提取客户端 IP
    let headers = req.headers();
    
    for header_name in &[
        "X-Forwarded-For",
        "X-Real-IP",
        "CF-Connecting-IP",
    ] {
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
    client_ip: IpAddr,
) -> Result<Message> {
    // 检查查询消息是否有效
    if query_message.message_type() != MessageType::Query {
        return Err(AppError::Http("不是查询类型的消息".to_string()));
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
        return Ok(response);
    }
    
    // 缓存未命中，转发到上游服务器
    debug!(?cache_key, "Cache miss, querying upstream server");
    METRICS.with(|m| m.cache_misses.inc());
    
    // 执行上游查询
    let start = Instant::now();
    let response = upstream.resolve(query_message).await?;
    let duration = start.elapsed();
    
    // 记录查询时间
    let resolver_info = if let Some(query) = query_message.queries().first() {
        format!("{}:{}", query.name(), query.query_type())
    } else {
        "unknown".to_string()
    };
    
    METRICS.with(|m| m.record_upstream_query(&resolver_info, duration));
    
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
            "DNS 错误响应"
        );
    }
    
    Ok(response)
}

/// 从 JSON 请求创建 DNS 查询消息
fn create_dns_message_from_json_request(request: &DnsJsonRequest) -> Result<Message> {
    // 解析域名
    let name = match Name::parse(&request.name, None) {
        Ok(name) => name,
        Err(e) => {
            return Err(AppError::Http(format!("无效的域名: {}", e)));
        }
    };
    
    // 解析记录类型
    let rtype = match RecordType::from(request.type_value) {
        RecordType::Unknown(..) => {
            return Err(AppError::Http(format!("无效的记录类型: {}", request.type_value)));
        }
        rt => rt,
    };
    
    // 解析 DNS 类
    let dns_class = match request.dns_class {
        Some(class) => {
            // 检查是否为未知类型（由于API变更，需要通过其他方式检测）
            if class > 0 && class != 1 && class != 3 && class != 4 && class != 254 && class != 255 {
                return Err(AppError::Http(format!("无效的 DNS 类: {}", class)));
            }
            DNSClass::from_u16(class)
        },
        None => Ok(DNSClass::IN),
    }?;
    
    // 创建 DNS 查询消息
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
    1 // A 记录
}

fn default_dns_class() -> Option<u16> {
    Some(1) // IN 类
}
