// src/server/metrics.rs

use axum::{routing::get, Router};
use prometheus::{
    GaugeVec, HistogramVec, 
    IntCounter, IntCounterVec, IntGauge, Registry,
    opts, register_gauge_vec, register_histogram_vec,
    register_int_counter_vec, register_int_counter,
    register_int_gauge
};
use std::thread_local;

// 线程本地存储的指标实例
thread_local! {
    pub static METRICS: DnsMetrics = DnsMetrics::new();
}

// DNS 服务器性能指标
pub struct DnsMetrics {
    registry: Registry,
    
    // 1. 请求处理和性能指标
    http_requests_total: IntCounterVec,
    http_request_duration_seconds: HistogramVec,
    http_request_bytes: HistogramVec,
    http_response_bytes: HistogramVec,
    rate_limit_rejected_total: IntCounterVec,
    
    // 2. 缓存效率和状态指标
    cache_entries: IntGauge, 
    cache_capacity: IntGauge,
    cache_operations_total: IntCounterVec,
    cache_ttl_seconds: HistogramVec,
    
    // 3. DNS 查询统计指标
    dns_queries_total: IntCounterVec,
    dns_responses_total: IntCounterVec,
    dns_query_type_total: IntCounterVec,
    dns_query_duration_seconds: HistogramVec,
    
    // 4. 上游 DNS 解析器指标
    upstream_requests_total: IntCounterVec,
    upstream_failures_total: IntCounterVec,
    upstream_duration_seconds: HistogramVec,
    
    // 5. DNS 路由/拆分功能指标
    route_results_total: IntCounterVec,
    route_rules: GaugeVec,
    
    // 6. DNSSEC 验证指标
    dnssec_validations_total: IntCounterVec,
    
    // 7. ECS 处理指标
    ecs_processed_total: IntCounterVec,
    ecs_cache_matches_total: IntCounter,
    
    // 8. 持久化缓存功能指标
    cache_persist_operations_total: IntCounterVec,
    cache_persist_duration_seconds: HistogramVec,
}

impl Default for DnsMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsMetrics {
    // 创建新的指标收集器
    pub fn new() -> Self {
        let registry = Registry::new();
        
        // 1. 请求处理和性能指标
        let http_requests_total = register_int_counter_vec!(
            opts!("owdns_http_requests_total", "Total HTTP requests processed by the server, classified by method, path, status, format and HTTP version"),
            &["method", "path", "status", "format", "http_version"]
        ).unwrap();
        registry.register(Box::new(http_requests_total.clone())).unwrap();
        
        let http_request_duration_seconds = register_histogram_vec!(
            opts!("owdns_http_request_duration_seconds", "HTTP request processing duration in seconds, classified by method, path and format").into(),
            &["method", "path", "format"]
        ).unwrap();
        registry.register(Box::new(http_request_duration_seconds.clone())).unwrap();
        
        let http_request_bytes = register_histogram_vec!(
            opts!("owdns_http_request_bytes", "HTTP request size in bytes, classified by method and path").into(),
            &["method", "path"]
        ).unwrap();
        registry.register(Box::new(http_request_bytes.clone())).unwrap();
        
        let http_response_bytes = register_histogram_vec!(
            opts!("owdns_http_response_bytes", "HTTP response size in bytes, classified by method and path").into(),
            &["method", "path"]
        ).unwrap();
        registry.register(Box::new(http_response_bytes.clone())).unwrap();
        
        let rate_limit_rejected_total = register_int_counter_vec!(
            opts!("owdns_rate_limit_rejected_total", "Total requests rejected by rate limiting, classified by client IP address"),
            &["client_ip"]
        ).unwrap();
        registry.register(Box::new(rate_limit_rejected_total.clone())).unwrap();
        
        // 2. 缓存效率和状态指标
        let cache_entries = register_int_gauge!(
            opts!("owdns_cache_entries", "Current number of DNS cache entries")
        ).unwrap();
        registry.register(Box::new(cache_entries.clone())).unwrap();
        
        let cache_capacity = register_int_gauge!(
            opts!("owdns_cache_capacity", "Maximum capacity of the DNS cache")
        ).unwrap();
        registry.register(Box::new(cache_capacity.clone())).unwrap();
        
        let cache_operations_total = register_int_counter_vec!(
            opts!("owdns_cache_operations_total", "Total cache operations, classified by operation type (hit, miss, insert, evict, expire)"),
            &["operation"]
        ).unwrap();
        registry.register(Box::new(cache_operations_total.clone())).unwrap();
        
        let cache_ttl_seconds = register_histogram_vec!(
            opts!("owdns_cache_ttl_seconds", "TTL distribution of DNS cache entries in seconds").into(),
            &[]
        ).unwrap();
        registry.register(Box::new(cache_ttl_seconds.clone())).unwrap();
        
        // 3. DNS 查询统计指标
        let dns_queries_total = register_int_counter_vec!(
            opts!("owdns_dns_queries_total", "Total DNS queries received, classified by query type and status"),
            &["query_type", "status"]
        ).unwrap();
        registry.register(Box::new(dns_queries_total.clone())).unwrap();
        
        let dns_responses_total = register_int_counter_vec!(
            opts!("owdns_dns_responses_total", "Total DNS responses sent, classified by response code (RCODE)"),
            &["rcode"]
        ).unwrap();
        registry.register(Box::new(dns_responses_total.clone())).unwrap();
        
        let dns_query_type_total = register_int_counter_vec!(
            opts!("owdns_dns_query_type_total", "Total DNS queries by record type (A, AAAA, MX, etc.)"),
            &["type"]
        ).unwrap();
        registry.register(Box::new(dns_query_type_total.clone())).unwrap();
        
        let dns_query_duration_seconds = register_histogram_vec!(
            opts!("owdns_dns_query_duration_seconds", "DNS query processing duration in seconds, classified by query type").into(),
            &["query_type"]
        ).unwrap();
        registry.register(Box::new(dns_query_duration_seconds.clone())).unwrap();
        
        // 4. 上游 DNS 解析器指标
        let upstream_requests_total = register_int_counter_vec!(
            opts!("owdns_upstream_requests_total", "Total requests sent to upstream DNS resolvers, classified by resolver address, protocol and upstream group"),
            &["resolver", "protocol", "upstream_group"]
        ).unwrap();
        registry.register(Box::new(upstream_requests_total.clone())).unwrap();
        
        let upstream_failures_total = register_int_counter_vec!(
            opts!("owdns_upstream_failures_total", "Total upstream resolver failures, classified by failure type, resolver address and upstream group"),
            &["type", "resolver", "upstream_group"]
        ).unwrap();
        registry.register(Box::new(upstream_failures_total.clone())).unwrap();
        
        let upstream_duration_seconds = register_histogram_vec!(
            opts!("owdns_upstream_duration_seconds", "Upstream query duration in seconds, classified by resolver address, protocol and upstream group").into(),
            &["resolver", "protocol", "upstream_group"]
        ).unwrap();
        registry.register(Box::new(upstream_duration_seconds.clone())).unwrap();
        
        // 5. DNS 路由/拆分功能指标
        let route_results_total = register_int_counter_vec!(
            opts!("owdns_route_results_total", "Total routing results, classified by result type (rule_match, blackhole, default)"),
            &["result"]
        ).unwrap();
        registry.register(Box::new(route_results_total.clone())).unwrap();
        
        let route_rules = register_gauge_vec!(
            opts!("owdns_route_rules", "Current active routing rules, classified by rule type (exact, regex, wildcard, file, url)"),
            &["type"]
        ).unwrap();
        registry.register(Box::new(route_rules.clone())).unwrap();
        
        // 6. DNSSEC 验证指标
        let dnssec_validations_total = register_int_counter_vec!(
            opts!("owdns_dnssec_validations_total", "Total DNSSEC validations performed, classified by validation status (success, failure)"),
            &["status"]
        ).unwrap();
        registry.register(Box::new(dnssec_validations_total.clone())).unwrap();
        
        // 7. ECS 处理指标
        let ecs_processed_total = register_int_counter_vec!(
            opts!("owdns_ecs_processed_total", "Total EDNS Client Subnet (ECS) operations processed, classified by policy (strip, forward, anonymize)"),
            &["policy"]
        ).unwrap();
        registry.register(Box::new(ecs_processed_total.clone())).unwrap();
        
        let ecs_cache_matches_total = register_int_counter!(
            opts!("owdns_ecs_cache_matches_total", "Total ECS-aware cache matches")
        ).unwrap();
        registry.register(Box::new(ecs_cache_matches_total.clone())).unwrap();
        
        // 8. 持久化缓存功能指标
        let cache_persist_operations_total = register_int_counter_vec!(
            opts!("owdns_cache_persist_operations_total", "Total cache persistence operations, classified by operation type (save, load)"),
            &["operation"]
        ).unwrap();
        registry.register(Box::new(cache_persist_operations_total.clone())).unwrap();
        
        let cache_persist_duration_seconds = register_histogram_vec!(
            opts!("owdns_cache_persist_duration_seconds", "Cache persistence operation duration in seconds, classified by operation type (save, load)").into(),
            &["operation"]
        ).unwrap();
        registry.register(Box::new(cache_persist_duration_seconds.clone())).unwrap();

        DnsMetrics {
            registry,
            http_requests_total,
            http_request_duration_seconds,
            http_request_bytes,
            http_response_bytes,
            rate_limit_rejected_total,
            cache_entries,
            cache_capacity,
            cache_operations_total,
            cache_ttl_seconds,
            dns_queries_total,
            dns_responses_total,
            dns_query_type_total,
            dns_query_duration_seconds,
            upstream_requests_total,
            upstream_failures_total,
            upstream_duration_seconds,
            route_results_total,
            route_rules,
            dnssec_validations_total,
            ecs_processed_total,
            ecs_cache_matches_total,
            cache_persist_operations_total,
            cache_persist_duration_seconds,
        }
    }
    
    // 获取 Prometheus 注册表
    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    // 导出当前指为字符串（用于测试）
    pub fn export_metrics(&self) -> String {
        let encoder = prometheus::TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = String::new();
        encoder.encode_utf8(&metric_families, &mut buffer).unwrap();
        buffer
    }
    
    // 下面是各个指标的getter方法，用于其他模块增加计数或设置值
    
    // 1. 请求处理和性能指标
    pub fn http_requests_total(&self) -> &IntCounterVec {
        &self.http_requests_total
    }
    
    pub fn http_request_duration_seconds(&self) -> &HistogramVec {
        &self.http_request_duration_seconds
    }
    
    pub fn http_request_bytes(&self) -> &HistogramVec {
        &self.http_request_bytes
    }
    
    pub fn http_response_bytes(&self) -> &HistogramVec {
        &self.http_response_bytes
    }
    
    pub fn rate_limit_rejected_total(&self) -> &IntCounterVec {
        &self.rate_limit_rejected_total
    }
    
    // 2. 缓存效率和状态指标
    pub fn cache_entries(&self) -> &IntGauge {
        &self.cache_entries
    }
    
    pub fn cache_capacity(&self) -> &IntGauge {
        &self.cache_capacity
    }
    
    pub fn cache_operations_total(&self) -> &IntCounterVec {
        &self.cache_operations_total
    }
    
    pub fn cache_ttl_seconds(&self) -> &HistogramVec {
        &self.cache_ttl_seconds
    }
    
    // 3. DNS 查询统计指标
    pub fn dns_queries_total(&self) -> &IntCounterVec {
        &self.dns_queries_total
    }
    
    pub fn dns_responses_total(&self) -> &IntCounterVec {
        &self.dns_responses_total
    }
    
    pub fn dns_query_type_total(&self) -> &IntCounterVec {
        &self.dns_query_type_total
    }
    
    pub fn dns_query_duration_seconds(&self) -> &HistogramVec {
        &self.dns_query_duration_seconds
    }
    
    // 4. 上游 DNS 解析器指标
    pub fn upstream_requests_total(&self) -> &IntCounterVec {
        &self.upstream_requests_total
    }
    
    pub fn upstream_failures_total(&self) -> &IntCounterVec {
        &self.upstream_failures_total
    }
    
    pub fn upstream_duration_seconds(&self) -> &HistogramVec {
        &self.upstream_duration_seconds
    }
    
    // 5. DNS 路由/拆分功能指标
    pub fn route_results_total(&self) -> &IntCounterVec {
        &self.route_results_total
    }
    
    pub fn route_rules(&self) -> &GaugeVec {
        &self.route_rules
    }
    
    // 6. DNSSEC 验证指标
    pub fn dnssec_validations_total(&self) -> &IntCounterVec {
        &self.dnssec_validations_total
    }
    
    // 7. ECS 处理指标
    pub fn ecs_processed_total(&self) -> &IntCounterVec {
        &self.ecs_processed_total
    }
    
    pub fn ecs_cache_matches_total(&self) -> &IntCounter {
        &self.ecs_cache_matches_total
    }
    
    // 8. 持久化缓存功能指标
    pub fn cache_persist_operations_total(&self) -> &IntCounterVec {
        &self.cache_persist_operations_total
    }
    
    pub fn cache_persist_duration_seconds(&self) -> &HistogramVec {
        &self.cache_persist_duration_seconds
    }
}

// 提供指标导出路由
pub fn metrics_routes() -> Router {
    Router::new().route(
        "/metrics",
        get(|| async {
            let encoder = prometheus::TextEncoder::new();
            
            // 线程安全地获取所有注册的指标
            let metric_families = METRICS.with(|m| m.registry().gather());
            
            // 编码为文本格式
            let mut buffer = String::new();
            encoder.encode_utf8(&metric_families, &mut buffer).unwrap();
            
            // 返回响应
            (
                axum::http::StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, prometheus::TEXT_FORMAT)],
                buffer
            )
        }),
    )
} 

