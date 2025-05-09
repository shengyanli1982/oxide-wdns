// src/server/metrics.rs

use axum::{routing::get, Router};
use prometheus::{
    HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, Opts, Registry,
};
use std::time::Duration;
use std::thread_local;

// 线程本地存储的指标实例
thread_local! {
    pub static METRICS: DnsMetrics = DnsMetrics::new();
}

// DNS 服务器性能指标
pub struct DnsMetrics {
    registry: Registry,
    
    // 总请求计数
    pub total_requests: IntCounter,
    // 按 HTTP 方法和内容类型分类的请求计数
    pub requests_by_method_type: IntCounterVec,
    // 按状态码分类的响应计数
    pub responses_by_status: IntCounterVec,
    // 请求处理时间直方图
    pub request_duration: HistogramVec,
    // 缓存命中计数
    pub cache_hits: IntCounter,
    // 缓存未命中计数
    pub cache_misses: IntCounter,
    // 缓存当前大小
    pub cache_size: IntGauge,
    // DNSSEC 验证成功计数
    pub dnssec_validation_success: IntCounter,
    // DNSSEC 验证失败计数
    pub dnssec_validation_failure: IntCounter,
    // 按上游组或全局标识分类的查询计数
    pub upstream_queries: IntCounterVec,
    // 上游组或全局标识查询时间直方图
    pub upstream_query_duration: HistogramVec,
    // 按响应代码分类的 DNS 响应计数
    pub dns_responses_by_rcode: IntCounterVec,
    // 按查询类型分类的 DNS 查询计数
    pub dns_queries_by_type: IntCounterVec,
    // 速率限制计数
    pub rate_limited_requests: IntCounter,
    // 按 IP 分类的速率限制计数
    pub rate_limited_requests_by_ip: IntCounterVec,
    // 被 Blackhole 阻止的请求计数
    pub blackhole_requests_total: IntCounter,
    // 规则源更新状态计数
    pub rule_source_updates_total: IntCounterVec,
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
        
        // 创建总请求计数指标
        let total_requests = IntCounter::new(
            "doh_requests_total",
            "Total number of DNS-over-HTTPS requests",
        )
        .unwrap();
        
        // 创建按方法和内容类型分类的请求计数指标
        let requests_by_method_type = IntCounterVec::new(
            Opts::new(
                "doh_requests_by_method", 
                "Request count by HTTP method and content type"
            ),
            &["method", "content_type"],
        )
        .unwrap();
        
        // 创建按状态码分类的响应计数指标
        let responses_by_status = IntCounterVec::new(
            Opts::new(
                "doh_responses_by_status", 
                "Response count by status code"
            ),
            &["method", "status"],
        )
        .unwrap();
        
        // 创建请求处理时间直方图
        let request_duration = HistogramVec::new(
            HistogramOpts::new(
                "doh_request_duration_seconds",
                "DNS-over-HTTPS request processing time in seconds",
            )
            .buckets(vec![
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
            ]),
            &["method"],
        )
        .unwrap();
        
        // 创建缓存相关指标
        let cache_hits = IntCounter::new("doh_cache_hits_total", "Number of cache hits").unwrap();
        let cache_misses = IntCounter::new("doh_cache_misses_total", "Number of cache misses").unwrap();
        let cache_size = IntGauge::new("doh_cache_entries", "Current number of cache entries").unwrap();
        
        // 创建 DNSSEC 相关指标
        let dnssec_validation_success = IntCounter::new(
            "doh_dnssec_valid_total",
            "Number of successful DNSSEC validations",
        )
        .unwrap();
        
        let dnssec_validation_failure = IntCounter::new(
            "doh_dnssec_invalid_total",
            "Number of failed DNSSEC validations",
        )
        .unwrap();
        
        // 创建上游解析器相关指标 (按上游标识符)
        let upstream_queries = IntCounterVec::new(
            Opts::new("doh_upstream_queries_total", "Query count by upstream identifier (group name or global)"),
            &["upstream_identifier"],
        )
        .unwrap();
        
        let upstream_query_duration = HistogramVec::new(
            HistogramOpts::new(
                "doh_upstream_duration_seconds",
                "Upstream query time in seconds by upstream identifier (group name or global)",
            )
            .buckets(vec![
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
            ]),
            &["upstream_identifier"],
        )
        .unwrap();
        
        // 创建按响应代码分类的 DNS 响应计数指标
        let dns_responses_by_rcode = IntCounterVec::new(
            Opts::new(
                "doh_dns_responses_by_rcode", 
                "DNS response count by response code"
            ),
            &["rcode"],
        )
        .unwrap();
        
        // 创建按查询类型分类的 DNS 查询计数指标
        let dns_queries_by_type = IntCounterVec::new(
            Opts::new(
                "doh_dns_queries_by_type",
                "DNS query count by record type"
            ),
            &["type"],
        )
        .unwrap();
        
        // 创建速率限制相关指标
        let rate_limited_requests = IntCounter::new(
            "doh_rate_limited_total",
            "Number of rate limited requests",
        )
        .unwrap();
        
        let rate_limited_requests_by_ip = IntCounterVec::new(
            Opts::new(
                "doh_rate_limited_by_ip",
                "Rate limited requests by client IP (last octet anonymized)"
            ),
            &["client_ip"],
        )
        .unwrap();
        
        // 创建 Blackhole 阻止计数指标
        let blackhole_requests_total = IntCounter::new(
            "doh_blackhole_total",
            "Total number of requests blocked by blackhole rule",
        )
        .unwrap();

        // 创建规则源更新状态指标
        let rule_source_updates_total = IntCounterVec::new(
            Opts::new(
                "doh_rule_updates_total",
                "Count of rule source update attempts by type and status",
            ),
            &["source_type", "status"],
        )
        .unwrap();
        
        // 注册所有指标
        registry.register(Box::new(total_requests.clone())).unwrap();
        registry.register(Box::new(requests_by_method_type.clone())).unwrap();
        registry.register(Box::new(responses_by_status.clone())).unwrap();
        registry.register(Box::new(request_duration.clone())).unwrap();
        registry.register(Box::new(cache_hits.clone())).unwrap();
        registry.register(Box::new(cache_misses.clone())).unwrap();
        registry.register(Box::new(cache_size.clone())).unwrap();
        registry.register(Box::new(dnssec_validation_success.clone())).unwrap();
        registry.register(Box::new(dnssec_validation_failure.clone())).unwrap();
        registry.register(Box::new(upstream_queries.clone())).unwrap();
        registry.register(Box::new(upstream_query_duration.clone())).unwrap();
        registry.register(Box::new(dns_responses_by_rcode.clone())).unwrap();
        registry.register(Box::new(dns_queries_by_type.clone())).unwrap();
        registry.register(Box::new(rate_limited_requests.clone())).unwrap();
        registry.register(Box::new(rate_limited_requests_by_ip.clone())).unwrap();
        registry.register(Box::new(blackhole_requests_total.clone())).unwrap();
        registry.register(Box::new(rule_source_updates_total.clone())).unwrap();
        
        DnsMetrics {
            registry,
            total_requests,
            requests_by_method_type,
            responses_by_status,
            request_duration,
            cache_hits,
            cache_misses,
            cache_size,
            dnssec_validation_success,
            dnssec_validation_failure,
            upstream_queries,
            upstream_query_duration,
            dns_responses_by_rcode,
            dns_queries_by_type,
            rate_limited_requests,
            rate_limited_requests_by_ip,
            blackhole_requests_total,
            rule_source_updates_total,
        }
    }
    
    // 获取 Prometheus 注册表
    pub fn registry(&self) -> &Registry {
        &self.registry
    }
    
    // 记录请求
    pub fn record_request(&self, method: &str, content_type: &str) {
        self.total_requests.inc();
        self.requests_by_method_type
            .with_label_values(&[method, content_type])
            .inc();
    }
    
    // 记录响应
    pub fn record_response(&self, method: &str, status: u16, duration: Duration) {
        self.responses_by_status
            .with_label_values(&[method, &status.to_string()])
            .inc();
            
        self.request_duration
            .with_label_values(&[method])
            .observe(duration.as_secs_f64());
            
        // 记录响应代码
        self.dns_responses_by_rcode
            .with_label_values(&[&status.to_string()])
            .inc();
    }
    
    // 记录DNS响应码
    pub fn record_dns_rcode(&self, rcode: &str) {
        self.dns_responses_by_rcode
            .with_label_values(&[rcode])
            .inc();
    }
    
    // 记录DNS查询类型
    pub fn record_dns_query_type(&self, query_type: &str) {
        self.dns_queries_by_type
            .with_label_values(&[query_type])
            .inc();
    }
    
    // 记录上游查询 (按上游标识符)
    pub fn record_upstream_query(&self, upstream_identifier: &str, duration: Duration) {
        self.upstream_queries
            .with_label_values(&[upstream_identifier])
            .inc();
            
        self.upstream_query_duration
            .with_label_values(&[upstream_identifier])
            .observe(duration.as_secs_f64());
    }
    
    // 记录缓存大小
    pub fn record_cache_size(&self, size: u64) {
        self.cache_size.set(size as i64);
    }
    
    // 记录缓存命中
    pub fn record_cache_hit(&self) {
        self.cache_hits.inc();
    }
    
    // 记录缓存未命中
    pub fn record_cache_miss(&self) {
        self.cache_misses.inc();
    }
    
    // 更新 DNSSEC 验证结果
    pub fn record_dnssec_validation(&self, success: bool) {
        if success {
            self.dnssec_validation_success.inc();
        } else {
            self.dnssec_validation_failure.inc();
        }
    }
    
    // 记录速率限制
    pub fn record_rate_limit(&self, client_ip: &str) {
        self.rate_limited_requests.inc();
        
        // 匿名化客户端 IP 的最后一个八位字节以增强隐私保护
        let anonymized_ip = if let Some(last_dot_pos) = client_ip.rfind('.') {
            // IPv4
            format!("{}.*", &client_ip[..last_dot_pos])
        } else if let Some(last_colon_pos) = client_ip.rfind(':') {
            // IPv6
            format!("{}:*", &client_ip[..last_colon_pos])
        } else {
            // 无法识别的格式，使用通用值
            "unknown".to_string()
        };
        
        self.rate_limited_requests_by_ip
            .with_label_values(&[&anonymized_ip])
            .inc();
    }

    // 记录被 Blackhole 阻止的请求
    pub fn record_blackhole_request(&self) {
        self.blackhole_requests_total.inc();
    }

    // 记录规则源更新状态
    pub fn record_rule_source_update(&self, source_type: &str, status: &str) {
        self.rule_source_updates_total
            .with_label_values(&[source_type, status])
            .inc();
    }

    // 导出当前指标为字符串（用于测试）
    pub fn export_metrics(&self) -> String {
        let encoder = prometheus::TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = String::new();
        encoder.encode_utf8(&metric_families, &mut buffer).unwrap();
        buffer
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

