use axum::Router;
use utoipa::OpenApi;
use utoipa_scalar::{Scalar, Servable};
use crate::server::doh_handler::{DnsJsonRequest, DnsMsgGetRequest, DnsJsonResponse};

// DoH API 文档
#[derive(OpenApi)]
#[openapi(
    paths(
        get_dns_json_query,
        get_dns_wire_query,
        post_dns_wire_query,
    ),
    components(
        schemas(DnsJsonRequest, DnsMsgGetRequest, DnsJsonResponse)
    ),
    tags(
        (name = "DoH", description = "DNS over HTTPS API")
    )
)]
pub struct ApiDoc;

// 创建 API 文档路由
pub fn create_scalar_routes() -> Router {
    Router::new()
        .merge(Scalar::with_url("/scalar", ApiDoc::openapi()))
}

/// Query DNS records in JSON format (GET)
#[utoipa::path(
    get,
    path = "/resolve",
    operation_id = "getDnsJsonQuery",
    tag = "DoH",
    params(
        ("name" = String, Query, description = "Domain name to query"),
        ("type" = Option<u16>, Query, description = "DNS record type, defaults to 1 (A record)"),
        ("dns_class" = Option<u16>, Query, description = "DNS class, defaults to 1 (IN)"),
        ("dnssec" = Option<bool>, Query, description = "Enable DNSSEC, defaults to false"),
        ("cd" = Option<bool>, Query, description = "Enable checking disabled, defaults to false")
    ),
    responses(
        (status = 200, description = "DNS query successful", body = DnsJsonResponse),
        (status = 400, description = "Invalid request parameters", body = String),
        (status = 500, description = "Internal server error", body = String)
    )
)]
pub fn get_dns_json_query() {}

/// Query DNS records in binary format (GET)
#[utoipa::path(
    get,
    path = "/dns-query",
    operation_id = "getDnsWireQuery",
    tag = "DoH",
    params(
        ("dns" = String, Query, description = "Base64url encoded DNS request")
    ),
    responses(
        (status = 200, description = "DNS query successful", content_type = "application/dns-message"),
        (status = 400, description = "Invalid request parameters", body = String),
        (status = 500, description = "Internal server error", body = String)
    )
)]
pub fn get_dns_wire_query() {}

/// Query DNS records in binary format (POST)
#[utoipa::path(
    post,
    path = "/dns-query",
    operation_id = "postDnsWireQuery",
    tag = "DoH",
    request_body(content_type = "application/dns-message", description = "Binary content of DNS request message"),
    responses(
        (status = 200, description = "DNS query successful", content_type = "application/dns-message"),
        (status = 400, description = "Invalid request parameters", body = String),
        (status = 415, description = "Unsupported media type", body = String),
        (status = 500, description = "Internal server error", body = String)
    )
)]
pub fn post_dns_wire_query() {}