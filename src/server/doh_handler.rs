// src/server/doh_handler.rs

use std::net::IpAddr;
use std::sync::Arc;
use axum::{
    extract::{Query, State},
    http::{header, StatusCode, Request},
    response::IntoResponse,
    routing::{get, post},
    Router as AxumRouter, Json,
};
use axum::body::to_bytes;
use serde::{Deserialize, Serialize};
use tokio::time::Instant;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RecordType};
use tracing::{debug, info};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as BASE64_ENGINE};
use crate::server::error::{ServerError, Result};
use crate::common::consts::{
    CONTENT_TYPE_DNS_JSON, 
    CONTENT_TYPE_DNS_MESSAGE,
    DNS_RECORD_TYPE_A, DNS_CLASS_IN, IP_HEADER_NAMES,
    MAX_REQUEST_SIZE,
    DOH_JSON_API_PATH, DOH_STANDARD_PATH,
    DOH_FORMAT_JSON, DOH_FORMAT_WIRE,
};
use crate::server::cache::{CacheKey, DnsCache};
use crate::server::config::ServerConfig;
use crate::server::routing::{RouteDecision, Router as DnsRouter};
use crate::server::upstream::{UpstreamManager, UpstreamSelection};
use crate::server::ecs::{EcsProcessor};
use crate::server::metrics::METRICS;

// HTTP 方法常量
const HTTP_METHOD_GET: &str = "GET";
const HTTP_METHOD_POST: &str = "POST";

// DNS 事件类型常量
const DNS_EVENT_RECEIVED: &str = "received";
const DNS_EVENT_PARAMETER_ERROR: &str = "parameter_error";
const DNS_EVENT_PROCESSING_FAILED: &str = "processing_failed";
const DNS_EVENT_PARSE_ERROR: &str = "parse_error";
const DNS_EVENT_BASE64_DECODE_ERROR: &str = "base64_decode_error";

// DNS 查询类型常量
const DNS_QUERY_TYPE_UNKNOWN: &str = "Unknown";

// DNS 响应相关常量
const DNS_RESPONSE_NXDOMAIN_BLACKHOLE: &str = "NXDomain_Blackhole";

// 路由结果常量
const ROUTE_RESULT_RULE_MATCH: &str = "rule_match";
const ROUTE_RESULT_BLACKHOLE: &str = "blackhole";  
const ROUTE_RESULT_DEFAULT: &str = "default";

// 错误消息常量
const ERROR_INVALID_DNS_MESSAGE: &str = "Invalid DNS message format";
const ERROR_INVALID_BASE64: &str = "Invalid base64 encoding";
const ERROR_SERIALIZE_RESPONSE: &str = "Failed to serialize DNS response";
const ERROR_INVALID_CONTENT_TYPE: &str = "Invalid content type";
const ERROR_REQUEST_TOO_LARGE: &str = "Request body too large";
const ERROR_READ_REQUEST_BODY: &str = "Failed to read request body";

// 共享的服务器状态
#[derive(Clone)]
pub struct ServerState {
    // 配置
    pub config: ServerConfig,
    // 上游解析管理器
    pub upstream: Arc<UpstreamManager>,
    // DNS 路由器
    pub router: Arc<DnsRouter>,
    // DNS 缓存
    pub cache: Arc<DnsCache>,
}

// DNS-over-HTTPS JSON 请求参数
#[derive(Debug, Deserialize, Serialize, utoipa::ToSchema)]
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
#[derive(Debug, Deserialize, Serialize, utoipa::ToSchema)]
pub struct DnsMsgGetRequest {
    // DNS 请求的 Base64url 编码
    pub dns: String,
}

// DNS-over-HTTPS JSON 响应格式
#[derive(Debug, Serialize, Clone, utoipa::ToSchema)]
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
#[derive(Debug, Serialize, Clone, utoipa::ToSchema)]
pub struct DnsJsonQuestion {
    // 查询名称
    pub name: String,
    // 查询类型
    pub type_value: u16,
}

// DNS-over-HTTPS JSON 应答记录
#[derive(Debug, Serialize, Clone, utoipa::ToSchema)]
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
pub fn doh_routes(state: ServerState) -> AxumRouter {
    AxumRouter::new()
        // JSON API 路由（兼容性）
        .route(DOH_JSON_API_PATH, get(handle_dns_json_query))
        // RFC 8484 标准路由
        .route(DOH_STANDARD_PATH, get(handle_dns_wire_get))
        .route(DOH_STANDARD_PATH, post(handle_dns_wire_post))
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
    
    // 相关指标 - 预先提取为常量，避免重复创建
    let path = DOH_JSON_API_PATH;
    let format = DOH_FORMAT_JSON;
    let http_version = format!("{:?}", req.version());
    let method = HTTP_METHOD_GET;
    
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
            
            // 记录错误状态码 - 提前计算一次，重复使用
            let status = StatusCode::BAD_REQUEST;
            let status_str = status.as_u16().to_string();
            let error_body = e.to_string();
            let error_body_len = error_body.len() as f64;
            
            // 记录指标
            {
                METRICS.http_requests_total()
                    .with_label_values(&[method, path, &status_str, format, &http_version])
                    .inc();
                
                // 记录请求持续时间
                let duration = start.elapsed().as_secs_f64();
                METRICS.http_request_duration_seconds()
                    .with_label_values(&[method, path, format])
                    .observe(duration);
                
                // 记录DNS查询错误
                METRICS.dns_queries_total()
                    .with_label_values(&[&params.type_value.to_string(), DNS_EVENT_PARAMETER_ERROR])
                    .inc();
                
                METRICS.http_response_bytes()
                    .with_label_values(&[method, path])
                    .observe(error_body_len);
            }
            
            // 返回错误响应
            return (status, error_body).into_response();
        }
    };
    
    // 记录DNS查询类型 - 提前计算一次，避免重复计算
    let query_type = if let Some(q) = query_message.queries().first() {
        format!("{:?}", q.query_type())
    } else {
        DNS_QUERY_TYPE_UNKNOWN.to_string()
    };
    
    {
        METRICS.dns_queries_total()
            .with_label_values(&[&query_type, DNS_EVENT_RECEIVED])
            .inc();
        
        METRICS.dns_query_type_total()
            .with_label_values(&[&query_type])
            .inc();
    }
    
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
            
            // 记录错误状态码 - 提前计算一次，重复使用
            let status = StatusCode::INTERNAL_SERVER_ERROR;
            let status_str = status.as_u16().to_string();
            let error_body = e.to_string();
            let error_body_len = error_body.len() as f64;
            
            // 记录指标
            {
                METRICS.http_requests_total()
                    .with_label_values(&[method, path, &status_str, format, &http_version])
                    .inc();
                
                // 记录请求持续时间
                let duration = start.elapsed().as_secs_f64();
                METRICS.http_request_duration_seconds()
                    .with_label_values(&[method, path, format])
                    .observe(duration);
                
                // 记录DNS查询错误
                METRICS.dns_queries_total()
                    .with_label_values(&[&query_type, DNS_EVENT_PROCESSING_FAILED])
                    .inc();
                
                METRICS.http_response_bytes()
                    .with_label_values(&[method, path])
                    .observe(error_body_len);
            }
            
            // 返回错误响应
            return (status, error_body).into_response();
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
            
            // 记录错误状态码 - 提前计算一次，重复使用
            let status = StatusCode::INTERNAL_SERVER_ERROR;
            let status_str = status.as_u16().to_string();
            let error_body = e.to_string();
            let error_body_len = error_body.len() as f64;
            
            // 记录指标
            {
                METRICS.http_requests_total()
                    .with_label_values(&[method, path, &status_str, format, &http_version])
                    .inc();
                
                // 记录请求持续时间
                let duration = start.elapsed().as_secs_f64();
                METRICS.http_request_duration_seconds()
                    .with_label_values(&[method, path, format])
                    .observe(duration);
                
                METRICS.http_response_bytes()
                    .with_label_values(&[method, path])
                    .observe(error_body_len);
            }
            
            // 返回错误响应
            return (status, error_body).into_response();
        }
    };
    
    // 计算持续时间
    let duration = start.elapsed();
    
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
        // 使用迭代器和预分配容量优化字符串收集
        let mut record_details = Vec::with_capacity(json_response.answer.len());
        for ans in &json_response.answer {
            record_details.push(format!("{}({}): {}", ans.name, RecordType::from(ans.type_value), ans.data));
        }
            
        debug!(
            name = %params.name,
            client_ip = ?client_ip,
            records = ?record_details,
            "DNS-over-HTTPS response record details"
        );
    }
    
    // 记录成功状态码和持续时间
    let status = StatusCode::OK.as_u16().to_string();
    {
        METRICS.http_requests_total()
            .with_label_values(&[method, path, &status, format, &http_version])
            .inc();
        
        // 记录请求持续时间
        METRICS.http_request_duration_seconds()
            .with_label_values(&[method, path, format])
            .observe(duration.as_secs_f64());
        
        // 记录DNS响应
        METRICS.dns_responses_total()
            .with_label_values(&[&format!("{:?}", rcode)])
            .inc();
    }
    
    // 准备JSON响应
    let json_response_body = Json(json_response.clone());
    
    // 提前计算响应大小估计，避免后续借用被移动的值
    let response_size_estimate = serde_json::to_string(&json_response).map(|s| s.len()).unwrap_or(0);
    
    // 返回 JSON 响应
    let response = (
        StatusCode::OK,
        [(header::CONTENT_TYPE, CONTENT_TYPE_DNS_JSON)],
        json_response_body,
    ).into_response();
    
    // 记录响应大小
    {
        METRICS.http_response_bytes()
            .with_label_values(&[method, path])
            .observe(response_size_estimate as f64);
    }
    
    response
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
    
    // 记录请求指标
    let path = DOH_STANDARD_PATH;
    let format = DOH_FORMAT_WIRE;
    let http_version = format!("{:?}", req.version());

    debug!(client_ip = ?client_ip, "DNS-over-HTTPS GET request received");
    
    // 解码请求参数中的 DNS 消息（Base64url 编码）
    let query_message = match BASE64_ENGINE.decode(&params.dns) {
        Ok(data) => {
            // 记录请求大小
            {
                METRICS.http_request_bytes()
                    .with_label_values(&[HTTP_METHOD_GET, path])
                    .observe(data.len() as f64);
            }
            
            match Message::from_vec(&data) {
                Ok(msg) => msg,
                Err(e) => {
                    info!(
                        client_ip = ?client_ip,
                        error = %e,
                        "Failed to parse DNS message from base64"
                    );
                    
                    // 记录错误状态
                    let status = StatusCode::BAD_REQUEST.as_u16().to_string();
                    {
                        METRICS.http_requests_total()
                            .with_label_values(&[HTTP_METHOD_GET, path, &status, format, &http_version])
                            .inc();
                        
                        // 记录请求持续时间
                        let duration = start.elapsed().as_secs_f64();
                        METRICS.http_request_duration_seconds()
                            .with_label_values(&[HTTP_METHOD_GET, path, format])
                            .observe(duration);
                        
                        // 记录DNS查询错误
                        METRICS.dns_queries_total()
                            .with_label_values(&[DNS_QUERY_TYPE_UNKNOWN, DNS_EVENT_PARSE_ERROR])
                            .inc();
                    }
                    
                    // 返回错误响应
                    let error_body = ERROR_INVALID_DNS_MESSAGE;
                    let response = (StatusCode::BAD_REQUEST, error_body).into_response();
                    
                    // 记录响应大小
                    {
                        METRICS.http_response_bytes()
                            .with_label_values(&[HTTP_METHOD_GET, path])
                            .observe(error_body.len() as f64);
                    }
                    
                    return response;
                }
            }
        },
        Err(e) => {
            info!(
                client_ip = ?client_ip,
                error = %e,
                "Failed to decode base64 DNS query parameter"
            );
            
            // 记录错误状态
            let status = StatusCode::BAD_REQUEST.as_u16().to_string();
            {
                METRICS.http_requests_total()
                    .with_label_values(&[HTTP_METHOD_GET, path, &status, format, &http_version])
                    .inc();
                
                // 记录请求持续时间
                let duration = start.elapsed().as_secs_f64();
                METRICS.http_request_duration_seconds()
                    .with_label_values(&[HTTP_METHOD_GET, path, format])
                    .observe(duration);
                
                // 记录DNS查询错误
                METRICS.dns_queries_total()
                    .with_label_values(&[DNS_QUERY_TYPE_UNKNOWN, DNS_EVENT_BASE64_DECODE_ERROR])
                    .inc();
            }
            
            // 返回错误响应
            let error_body = ERROR_INVALID_BASE64;
            let response = (StatusCode::BAD_REQUEST, error_body).into_response();
            
            // 记录响应大小
            {
                METRICS.http_response_bytes()
                    .with_label_values(&[HTTP_METHOD_GET, path])
                    .observe(error_body.len() as f64);
            }
            
            return response;
        }
    };
    
    // 从查询获取域名（用于日志）
    let domain = query_message.queries().first().map_or_else(
        || "unknown".to_string(), 
        |q| q.name().to_utf8()
    );
    
    // 记录DNS查询类型
    let query_type = if let Some(q) = query_message.queries().first() {
        format!("{:?}", q.query_type())
    } else {
        DNS_QUERY_TYPE_UNKNOWN.to_string()
    };
    
    {
        METRICS.dns_queries_total()
            .with_label_values(&[&query_type, DNS_EVENT_RECEIVED])
            .inc();
        
        METRICS.dns_query_type_total()
            .with_label_values(&[&query_type])
            .inc();
    }
    
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
            
            // 记录错误状态
            let status = StatusCode::INTERNAL_SERVER_ERROR.as_u16().to_string();
            {
                METRICS.http_requests_total()
                    .with_label_values(&[HTTP_METHOD_GET, path, &status, format, &http_version])
                    .inc();
                
                // 记录请求持续时间
                let duration = start.elapsed().as_secs_f64();
                METRICS.http_request_duration_seconds()
                    .with_label_values(&[HTTP_METHOD_GET, path, format])
                    .observe(duration);
                
                // 记录DNS查询错误
                METRICS.dns_queries_total()
                    .with_label_values(&[&query_type, DNS_EVENT_PROCESSING_FAILED])
                    .inc();
            }
            
            // 返回错误响应
            let error_body = e.to_string();
            let response = (StatusCode::INTERNAL_SERVER_ERROR, error_body.clone()).into_response();
            
            // 记录响应大小
            {
                METRICS.http_response_bytes()
                    .with_label_values(&[HTTP_METHOD_GET, path])
                    .observe(error_body.len() as f64);
            }
            
            return response;
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
            
            // 记录错误状态
            let status = StatusCode::INTERNAL_SERVER_ERROR.as_u16().to_string();
            {
                METRICS.http_requests_total()
                    .with_label_values(&[HTTP_METHOD_GET, path, &status, format, &http_version])
                    .inc();
                
                // 记录请求持续时间
                let duration = start.elapsed().as_secs_f64();
                METRICS.http_request_duration_seconds()
                    .with_label_values(&[HTTP_METHOD_GET, path, format])
                    .observe(duration);
            }
            
            // 返回错误响应
            let error_body = ERROR_SERIALIZE_RESPONSE;
            let response = (StatusCode::INTERNAL_SERVER_ERROR, error_body).into_response();
            
            // 记录响应大小
            {
                METRICS.http_response_bytes()
                    .with_label_values(&[HTTP_METHOD_GET, path])
                    .observe(error_body.len() as f64);
            }
            
            return response;
        }
    };
    
    // 计算持续时间
    let duration = start.elapsed();
    
    // 记录请求完成
    let qtype = query_message.queries().first().map_or_else(
        || "unknown".to_string(), 
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
    
    // 记录成功状态和持续时间
    let status = StatusCode::OK.as_u16().to_string();
    {
        METRICS.http_requests_total()
            .with_label_values(&[HTTP_METHOD_GET, path, &status, format, &http_version])
            .inc();
        
        // 记录请求持续时间
        METRICS.http_request_duration_seconds()
            .with_label_values(&[HTTP_METHOD_GET, path, format])
            .observe(duration.as_secs_f64());
        
        // 记录DNS响应
        METRICS.dns_responses_total()
            .with_label_values(&[&format!("{:?}", rcode)])
            .inc();
        
        // 记录响应大小
        METRICS.http_response_bytes()
            .with_label_values(&[HTTP_METHOD_GET, path])
            .observe(response_bytes.len() as f64);
    }
    
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
    
    // 记录请求指标
    let path = DOH_STANDARD_PATH;
    let format = DOH_FORMAT_WIRE;
    let http_version = format!("{:?}", req.version());
    
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
        
        // 记录错误状态
        let status = StatusCode::UNSUPPORTED_MEDIA_TYPE.as_u16().to_string();
        {
            METRICS.http_requests_total()
                .with_label_values(&[HTTP_METHOD_POST, path, &status, format, &http_version])
                .inc();
            
            // 记录请求持续时间
            let duration = start.elapsed().as_secs_f64();
            METRICS.http_request_duration_seconds()
                .with_label_values(&[HTTP_METHOD_POST, path, format])
                .observe(duration);
        }
        
        // 返回错误响应
        let error_body = ERROR_INVALID_CONTENT_TYPE;
        let response = (StatusCode::UNSUPPORTED_MEDIA_TYPE, error_body).into_response();
        
        // 记录响应大小
        {
            METRICS.http_response_bytes()
                .with_label_values(&[HTTP_METHOD_POST, path])
                .observe(error_body.len() as f64);
        }
        
        return response;
    }
    
    // 读取请求体
    let body_bytes = match to_bytes(req.into_body(), MAX_REQUEST_SIZE).await {
        Ok(bytes) => {
            // 记录请求大小
            {
                METRICS.http_request_bytes()
                    .with_label_values(&[HTTP_METHOD_POST, path])
                    .observe(bytes.len() as f64);
            }
            
            bytes
        },
        Err(e) => {
            info!(
                client_ip = ?client_ip,
                error = %e,
                "Failed to read DNS-over-HTTPS POST request body"
            );
            
            // 记录错误状态
            let status = StatusCode::BAD_REQUEST.as_u16().to_string();
            {
                METRICS.http_requests_total()
                    .with_label_values(&[HTTP_METHOD_POST, path, &status, format, &http_version])
                    .inc();
                
                // 记录请求持续时间
                let duration = start.elapsed().as_secs_f64();
                METRICS.http_request_duration_seconds()
                    .with_label_values(&[HTTP_METHOD_POST, path, format])
                    .observe(duration);
            }
            
            // 返回错误响应
            let error_body = ERROR_READ_REQUEST_BODY;
            let response = (StatusCode::BAD_REQUEST, error_body).into_response();
            
            // 记录响应大小
            {
                METRICS.http_response_bytes()
                    .with_label_values(&[HTTP_METHOD_POST, path])
                    .observe(error_body.len() as f64);
            }
            
            return response;
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
        
        // 记录错误状态
        let status = StatusCode::PAYLOAD_TOO_LARGE.as_u16().to_string();
        {
            METRICS.http_requests_total()
                .with_label_values(&[HTTP_METHOD_POST, path, &status, format, &http_version])
                .inc();
            
            // 记录请求持续时间
            let duration = start.elapsed().as_secs_f64();
            METRICS.http_request_duration_seconds()
                .with_label_values(&[HTTP_METHOD_POST, path, format])
                .observe(duration);
        }
        
        // 返回错误响应
        let error_body = ERROR_REQUEST_TOO_LARGE;
        let response = (StatusCode::PAYLOAD_TOO_LARGE, error_body).into_response();
        
        // 记录响应大小
        {
            METRICS.http_response_bytes()
                .with_label_values(&[HTTP_METHOD_POST, path])
                .observe(error_body.len() as f64);
        }
        
        return response;
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
            
            // 记录错误状态
            let status = StatusCode::BAD_REQUEST.as_u16().to_string();
            {
                METRICS.http_requests_total()
                    .with_label_values(&[HTTP_METHOD_POST, path, &status, format, &http_version])
                    .inc();
                
                // 记录请求持续时间
                let duration = start.elapsed().as_secs_f64();
                METRICS.http_request_duration_seconds()
                    .with_label_values(&[HTTP_METHOD_POST, path, format])
                    .observe(duration);
                
                // 记录DNS查询错误
                METRICS.dns_queries_total()
                    .with_label_values(&[DNS_QUERY_TYPE_UNKNOWN, DNS_EVENT_PARSE_ERROR])
                    .inc();
            }
            
            // 返回错误响应
            let error_body = "Invalid DNS message format";
            let response = (StatusCode::BAD_REQUEST, error_body).into_response();
            
            // 记录响应大小
            {
                METRICS.http_response_bytes()
                    .with_label_values(&[HTTP_METHOD_POST, path])
                    .observe(error_body.len() as f64);
            }
            
            return response;
        }
    };
    
    // 从查询获取域名（用于日志）
    let domain = query_message.queries().first().map_or_else(
        || "unknown".to_string(), 
        |q| q.name().to_utf8()
    );
    
    // 记录DNS查询类型
    let query_type = if let Some(q) = query_message.queries().first() {
        format!("{:?}", q.query_type())
    } else {
        DNS_QUERY_TYPE_UNKNOWN.to_string()
    };
    
    {
        METRICS.dns_queries_total()
            .with_label_values(&[&query_type, DNS_EVENT_RECEIVED])
            .inc();
        
        METRICS.dns_query_type_total()
            .with_label_values(&[&query_type])
            .inc();
    }
    
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
            
            // 记录错误状态
            let status = StatusCode::INTERNAL_SERVER_ERROR.as_u16().to_string();
            {
                METRICS.http_requests_total()
                    .with_label_values(&[HTTP_METHOD_POST, path, &status, format, &http_version])
                    .inc();
                
                // 记录请求持续时间
                let duration = start.elapsed().as_secs_f64();
                METRICS.http_request_duration_seconds()
                    .with_label_values(&[HTTP_METHOD_POST, path, format])
                    .observe(duration);
                
                // 记录DNS查询错误
                METRICS.dns_queries_total()
                    .with_label_values(&[&query_type, DNS_EVENT_PROCESSING_FAILED])
                    .inc();
            }
            
            // 返回错误响应
            let error_body = e.to_string();
            let response = (StatusCode::INTERNAL_SERVER_ERROR, error_body.clone()).into_response();
            
            // 记录响应大小
            {
                METRICS.http_response_bytes()
                    .with_label_values(&[HTTP_METHOD_POST, path])
                    .observe(error_body.len() as f64);
            }
            
            return response;
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
            
            // 记录错误状态
            let status = StatusCode::INTERNAL_SERVER_ERROR.as_u16().to_string();
            {
                METRICS.http_requests_total()
                    .with_label_values(&[HTTP_METHOD_POST, path, &status, format, &http_version])
                    .inc();
                
                // 记录请求持续时间
                let duration = start.elapsed().as_secs_f64();
                METRICS.http_request_duration_seconds()
                    .with_label_values(&[HTTP_METHOD_POST, path, format])
                    .observe(duration);
            }
            
            // 返回错误响应
            let error_body = ERROR_SERIALIZE_RESPONSE;
            let response = (StatusCode::INTERNAL_SERVER_ERROR, error_body).into_response();
            
            // 记录响应大小
            {
                METRICS.http_response_bytes()
                    .with_label_values(&[HTTP_METHOD_POST, path])
                    .observe(error_body.len() as f64);
            }
            
            return response;
        }
    };
    
    // 计算持续时间
    let duration = start.elapsed();
    
    // 记录请求完成
    let qtype = query_message.queries().first().map_or_else(
        || "unknown".to_string(), 
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
    
    // 记录成功状态和持续时间
    let status = StatusCode::OK.as_u16().to_string();
    {
        METRICS.http_requests_total()
            .with_label_values(&[HTTP_METHOD_POST, path, &status, format, &http_version])
            .inc();
        
        // 记录请求持续时间
        METRICS.http_request_duration_seconds()
            .with_label_values(&[HTTP_METHOD_POST, path, format])
            .observe(duration.as_secs_f64());
        
        // 记录DNS响应
        METRICS.dns_responses_total()
            .with_label_values(&[&format!("{:?}", rcode)])
            .inc();
        
        // 记录响应大小
        METRICS.http_response_bytes()
            .with_label_values(&[HTTP_METHOD_POST, path])
            .observe(response_bytes.len() as f64);
    }
    
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
    router: &DnsRouter,
    cache: &DnsCache,
    query_message: &Message,
    client_ip: IpAddr,
) -> Result<(Message, bool)> {  // 返回元组，第二个参数表示是否缓存命中
    // 检查查询有效性
    if query_message.queries().is_empty() {
        return Err(ServerError::InvalidQuery("Empty query section".to_string()));
    }
    
    // 获取第一个查询
    let query = &query_message.queries()[0];
    
    // 提取客户端 ECS 数据
    let client_ecs = EcsProcessor::extract_ecs_from_message(query_message);
    
    // 创建缓存键 - 只创建一次，避免重复计算
    let cache_key = if let Some(ecs) = &client_ecs {
        // 使用 ECS 数据创建缓存键，无需克隆 name
        CacheKey::with_ecs(
            query.name().clone(),
            query.query_type(),
            query.query_class(),
            ecs
        )
    } else {
        // 使用基本信息创建缓存键，无需克隆 name
        CacheKey::new(
            query.name().clone(),
            query.query_type(),
            query.query_class()
        )
    };
    
    // 尝试从缓存获取
    if cache.is_enabled() {
        if let Some(cached_response) = cache.get_with_ecs(&cache_key, client_ecs.as_ref()).await {
            // 从缓存构建响应（复制请求 ID 等信息）
            let mut response = cached_response;
            response.set_id(query_message.id());
            
            return Ok((response, true));
        }
    }
    
    // 缓存未命中，需要查询上游
    
    // 使用路由器确定上游组 - 提前获取域名UTF8字符串，避免重复转换
    let domain_name = query.name().to_utf8();
    let route_decision = router.match_domain(&domain_name).await;
    
    // 记录路由结果指标
    match &route_decision {
        RouteDecision::UseGroup(_) => {
            METRICS.route_results_total()
                .with_label_values(&[ROUTE_RESULT_RULE_MATCH])
                .inc();
        },
        RouteDecision::Blackhole => {
            METRICS.route_results_total()
                .with_label_values(&[ROUTE_RESULT_BLACKHOLE])
                .inc();
        },
        RouteDecision::UseGlobal => {
            METRICS.route_results_total()
                .with_label_values(&[ROUTE_RESULT_DEFAULT])
                .inc();
        },
    }
    
    // 选择上游
    let upstream_selection = match route_decision {
        RouteDecision::UseGroup(group_name) => UpstreamSelection::Group(group_name),
        RouteDecision::Blackhole => {
            // 黑洞策略 - 创建一个响应，直接重用查询信息
            let mut response = Message::new();
            response.set_id(query_message.id())
                .set_message_type(MessageType::Response)
                .set_recursion_desired(query_message.recursion_desired())
                .set_recursion_available(true)
                .set_response_code(ResponseCode::NXDomain);
            
            // 复制查询部分
            for q in query_message.queries() {
                response.add_query(q.clone());
            }
            
            // 记录DNS响应（黑洞）
            {
                METRICS.dns_responses_total()
                    .with_label_values(&[DNS_RESPONSE_NXDOMAIN_BLACKHOLE])
                    .inc();
            }
            
            // 不缓存黑洞响应
            return Ok((response, false));
        },
        RouteDecision::UseGlobal => UpstreamSelection::Global,
    };
    
    // 查询上游，传递客户端 IP 和 ECS 数据 - 避免临时变量
    let response = upstream.resolve(
        query_message, 
        upstream_selection, 
        Some(client_ip), 
        client_ecs.as_ref()
    ).await?;
    
    // 判断响应代码，避免重复检查
    let response_code = response.response_code();
    let cache_enabled = cache.is_enabled();
    
    // 缓存响应
    if cache_enabled {
        if response_code == ResponseCode::NoError {
            cache.put_with_auto_ttl_and_ecs(&cache_key, &response, client_ecs.as_ref()).await?;
        } else if response_code == ResponseCode::NXDomain {
            // 缓存负响应
            let negative_ttl = cache.negative_ttl();
            cache.put_with_ecs(&cache_key, &response, negative_ttl, client_ecs.as_ref()).await?;
        }
    }
    
    Ok((response, false))
}

// 从 JSON 请求创建 DNS 查询消息
fn create_dns_message_from_json_request(request: &DnsJsonRequest) -> Result<Message> {
    // 解析域名 - 验证输入域名的合法性
    let name = match Name::parse(&request.name, None) {
        Ok(name) => name,
        Err(e) => {
            // 使用静态字符串减少分配
            let error_msg = format!("Invalid domain name: {}", e);
            return Err(ServerError::Http(error_msg));
        }
    };
    
    // 解析记录类型
    let rtype = match RecordType::from(request.type_value) {
        RecordType::Unknown(..) => {
            // 使用静态字符串减少分配
            let error_msg = format!("Invalid record type: {}", request.type_value);
            return Err(ServerError::Http(error_msg));
        }
        rt => rt,
    };
    
    // 解析 DNS 类
    let _dns_class = match request.dns_class {
        Some(class) => {
            // 检查已知有效的 DNS 类型
            match class {
                1 | 3 | 4 | 254 | 255 => Ok::<DNSClass, ServerError>(DNSClass::from(class)),
                _ => {
                    // 使用静态字符串减少分配
                    let error_msg = format!("Invalid DNS class: {}", class);
                    return Err(ServerError::Http(error_msg));
                }
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
    let query = hickory_proto::op::Query::query(name, rtype);
    message.add_query(query);
    
    Ok(message)
}

// 将 DNS 响应消息转换为 JSON 响应
fn dns_message_to_json_response(message: &Message) -> Result<DnsJsonResponse> {
    // 获取消息元素数量，用于预分配空间
    let query_count = message.queries().len();
    let answer_count = message.answers().len();
    
    // 创建响应对象，预分配空间以减少内存重分配
    let mut response = DnsJsonResponse {
        status: u16::from(message.response_code().low()),
        tc: message.truncated(),
        rd: message.recursion_desired(),
        ra: message.recursion_available(),
        ad: message.authentic_data(),
        cd: message.checking_disabled(),
        question: Vec::with_capacity(query_count),
        answer: Vec::with_capacity(answer_count),
    };
    
    // 添加查询
    for query in message.queries() {
        // 提前获取name字符串，减少重复转换
        let name_str = query.name().to_utf8();
        let type_value = query.query_type().into();
        
        response.question.push(DnsJsonQuestion {
            name: name_str,
            type_value,
        });
    }
    
    // 添加应答记录
    for record in message.answers() {
        let data = match record.data() {
            Some(rdata) => rdata.to_string(),
            None => continue,
        };
        
        // 提前获取name字符串，减少重复转换
        let name_str = record.name().to_utf8();
        let type_value = record.record_type().into();
        let class = record.dns_class().into();
        let ttl = record.ttl();
        
        response.answer.push(DnsJsonAnswer {
            name: name_str,
            type_value,
            class,
            ttl,
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
