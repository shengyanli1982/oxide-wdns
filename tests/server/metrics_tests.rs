// tests/server/metrics_tests.rs

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use axum::{routing::get, Router};
    use tokio::net::TcpListener;
    use reqwest::Client;
    use std::time::Duration;
    // 从项目的公共API中导入，而不是使用 crate::
    use oxide_wdns::server::metrics::{DnsMetrics, METRICS};
    use tracing::info;

    // === 辅助函数 ===
    fn setup_metrics() -> Arc<DnsMetrics> {
        Arc::new(DnsMetrics::new())
    }

    async fn setup_metrics_server() -> String {
        // 使用Axum框架创建一个提供指标的测试服务器
        let app = Router::new().route(
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
        );

        // 绑定到随机端口
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        
        // 启动服务器（后台运行）
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        
        format!("http://{}", addr)
    }

    #[tokio::test]
    async fn test_metrics_request_total_counter() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_metrics_request_total_counter");

        // 1. 获取/创建指标注册表
        info!("Setting up DnsMetrics...");
        let metrics = setup_metrics();
        info!("DnsMetrics set up.");

        // 2. 调用记录请求的方法
        let method = "GET";
        let content_type = "application/dns-message";
        info!(method, content_type, "Recording request...");
        metrics.record_request(method, content_type);
        info!("Request recorded.");

        // 3. 读取请求总数计数器的值
        // 注意：total_requests 貌似没有标签，直接获取
        let value = metrics.total_requests.get();
        info!(counter_value = value, "Retrieved total_requests counter value.");

        // 4. 断言：计数器值增加了 1
        assert_eq!(value, 1, "Request counter should be incremented by 1");
        info!("Validated counter value.");
        info!("Test completed: test_metrics_request_total_counter");
    }

    #[tokio::test]
    async fn test_metrics_error_total_counter() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_metrics_error_total_counter");

        // 1. 获取/创建指标注册表
        info!("Setting up DnsMetrics...");
        let metrics = setup_metrics();
        info!("DnsMetrics set up.");

        // 2. 调用记录错误的方法
        let error_type = "dns_format_error";
        info!(error_type, "Recording error...");
        metrics.record_error(error_type);
        info!("Error recorded.");

        // 3. 读取错误总数计数器的值
        let value = metrics.errors.with_label_values(&[error_type]).get();
        info!(counter_value = value, error_type, "Retrieved errors counter value for type.");

        // 4. 断言：计数器值增加了 1
        assert_eq!(value, 1, "Error counter should be incremented by 1");
        info!("Validated counter value.");
        info!("Test completed: test_metrics_error_total_counter");
    }

    #[tokio::test]
    async fn test_metrics_cache_hit_counter() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_metrics_cache_hit_counter");

        // 1. 获取/创建指标注册表
        info!("Setting up DnsMetrics...");
        let metrics = setup_metrics();
        info!("DnsMetrics set up.");

        // 2. 调用记录缓存命中的方法
        info!("Recording cache hit...");
        metrics.record_cache_hit();
        info!("Cache hit recorded.");

        // 3. 读取缓存命中计数器的值
        let value = metrics.cache_hits.get();
        info!(counter_value = value, "Retrieved cache_hits counter value.");

        // 4. 断言：计数器值增加了 1
        assert_eq!(value, 1, "Cache hit counter should be incremented by 1");
        info!("Validated counter value.");
        info!("Test completed: test_metrics_cache_hit_counter");
    }

    #[tokio::test]
    async fn test_metrics_cache_miss_counter() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_metrics_cache_miss_counter");

        // 1. 获取/创建指标注册表
        info!("Setting up DnsMetrics...");
        let metrics = setup_metrics();
        info!("DnsMetrics set up.");

        // 2. 调用记录缓存未命中的方法
        info!("Recording cache miss...");
        metrics.record_cache_miss();
        info!("Cache miss recorded.");

        // 3. 读取缓存未命中计数器的值
        let value = metrics.cache_misses.get();
        info!(counter_value = value, "Retrieved cache_misses counter value.");

        // 4. 断言：计数器值增加了 1
        assert_eq!(value, 1, "Cache miss counter should be incremented by 1");
        info!("Validated counter value.");
        info!("Test completed: test_metrics_cache_miss_counter");
    }

    #[tokio::test]
    async fn test_metrics_upstream_query_duration_histogram() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_metrics_upstream_query_duration_histogram");

        // 1. 获取/创建指标注册表
        info!("Setting up DnsMetrics...");
        let metrics = setup_metrics();
        info!("DnsMetrics set up.");

        // 2. 调用记录上游查询持续时间的方法
        let upstream_id = "cloudflare";
        let duration = Duration::from_millis(150); // 150毫秒
        info!(upstream_id, ?duration, "Recording upstream query duration...");
        metrics.record_upstream_query(upstream_id, duration);
        info!("Upstream query duration recorded.");

        // 3. 获取直方图的样本总数
        let sample_count = metrics.upstream_query_duration
            .with_label_values(&[upstream_id])
            .get_sample_count();
        info!(sample_count, upstream_id, "Retrieved histogram sample count.");

        // 4. 断言：直方图至少有一个样本
        assert_eq!(sample_count, 1, "Histogram should have recorded exactly one sample");
        info!("Validated sample count.");

        // 5. 获取样本的总和
        let sample_sum = metrics.upstream_query_duration
            .with_label_values(&[upstream_id])
            .get_sample_sum();
        info!(sample_sum, upstream_id, "Retrieved histogram sample sum.");

        // 6. 断言：样本总和应该是duration转换为秒后的值（接近0.15）
        let expected_sum = duration.as_secs_f64();
        assert!(
            (sample_sum - expected_sum).abs() < 0.001, 
            "Sample sum ({}) should be approximately {} seconds", sample_sum, expected_sum
        );
        info!(sample_sum, expected_sum, "Validated sample sum.");
        info!("Test completed: test_metrics_upstream_query_duration_histogram");
    }

    #[tokio::test]
    async fn test_metrics_prometheus_output_format() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_metrics_prometheus_output_format");

        // 1. 创建服务器并获取URL
        info!("Setting up metrics HTTP server...");
        let server_url = setup_metrics_server().await;
        info!(server_url, "Metrics server started.");

        // 2. 设置一些指标数据（在线程本地存储中）
        info!("Recording some metrics data...");
        METRICS.with(|m| {
            m.record_request("GET", "application/dns-message");
            m.record_cache_hit();
            m.record_dns_query_type("A");
            m.record_error("parse_error");
            info!("Metrics data recorded.");
        });

        // 3. 请求指标端点
        let client = Client::new();
        let metrics_url = format!("{}/metrics", server_url);
        info!(url = %metrics_url, "Sending request to metrics endpoint...");
        let response = client.get(&metrics_url)
            .send()
            .await
            .expect("Failed to send request");
        info!(status = %response.status(), "Received response from metrics endpoint.");

        // 4. 检查响应状态
        assert_eq!(response.status().as_u16(), 200, "Expected 200 OK response");

        // 5. 获取响应体
        info!("Reading response body...");
        let body = response.text().await.expect("Failed to get response body");
        info!(body_len = body.len(), "Response body read.");

        // 6. 验证输出格式包含预期的指标名称
        info!("Validating Prometheus output format...");
        assert!(body.contains("doh_requests_total"), "Output should contain total requests metric");
        assert!(body.contains("doh_cache_hits"), "Output should contain cache hits metric");
        assert!(body.contains("doh_dns_queries_by_type"), "Output should contain DNS queries by type metric");
        assert!(body.contains("doh_errors"), "Output should contain errors metric");
        info!("Validated presence of key metric names.");

        // 7. 验证输出包含必要的Prometheus元数据
        assert!(body.contains("# HELP"), "Output should contain HELP metadata");
        assert!(body.contains("# TYPE"), "Output should contain TYPE metadata");
        info!("Validated presence of HELP and TYPE metadata.");
        info!("Test completed: test_metrics_prometheus_output_format");
    }

    #[tokio::test]
    async fn test_metrics_reset_or_recreate() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_metrics_reset_or_recreate");

        // 1. 创建第一个指标实例并记录数据
        info!("Creating first DnsMetrics instance (metrics1)...");
        let metrics1 = DnsMetrics::new();
        info!("Recording data in metrics1...");
        metrics1.total_requests.inc();
        metrics1.record_cache_hit();
        let val1_req = metrics1.total_requests.get();
        let val1_hit = metrics1.cache_hits.get();
        info!(total_requests = val1_req, cache_hits = val1_hit, "Initial values for metrics1.");
        assert_eq!(val1_req, 1);
        assert_eq!(val1_hit, 1);

        // 2. 创建新的指标实例（模拟重置）
        info!("Creating second DnsMetrics instance (metrics2)...");
        let metrics2 = DnsMetrics::new();
        info!("Second instance created.");

        // 3. 验证新实例的计数器为初始状态（0）
        let val2_req = metrics2.total_requests.get();
        let val2_hit = metrics2.cache_hits.get();
        info!(total_requests = val2_req, cache_hits = val2_hit, "Initial values for metrics2.");
        assert_eq!(val2_req, 0, "New instance total_requests should have counter value 0");
        assert_eq!(val2_hit, 0, "New instance cache_hits should have counter value 0");
        info!("Validated that new instance counters start at 0.");
        info!("Test completed: test_metrics_reset_or_recreate");
    }

    #[tokio::test]
    async fn test_metrics_dns_routing() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_metrics_dns_routing");
        
        // 创建指标实例
        let metrics = Arc::new(DnsMetrics::new());
        
        // 记录各种路由情况的指标
        metrics.record_routing_decision("special_group", "example.com");
        metrics.record_routing_decision("special_group", "example.org");
        metrics.record_routing_decision("cn_group", "example.cn");
        metrics.record_routing_decision("__blackhole__", "ads.example.com");
        metrics.record_routing_decision("__blackhole__", "malware.example.com");
        metrics.record_routing_decision("__global__", "random.example.net");
        
        // 导出指标
        let metrics_text = metrics.export_metrics();
        
        // 验证是否包含各个上游组的指标
        assert!(metrics_text.contains("dns_routing_decisions{group=\"special_group\"} 2"), 
                "Metrics should include 2 routings for special_group");
        assert!(metrics_text.contains("dns_routing_decisions{group=\"cn_group\"} 1"), 
                "Metrics should include 1 routing for cn_group");
        assert!(metrics_text.contains("dns_routing_decisions{group=\"__blackhole__\"} 2"), 
                "Metrics should include 2 routings for __blackhole__");
        assert!(metrics_text.contains("dns_routing_decisions{group=\"__global__\"} 1"), 
                "Metrics should include 1 routing for __global__");
        
        // 验证黑洞请求指标
        assert!(metrics_text.contains("dns_blackhole_requests_total 2"), 
                "Metrics should include 2 blackhole requests");
        
        info!("Test completed: test_metrics_dns_routing");
    }
    
    #[tokio::test]
    async fn test_metrics_rule_file_updates() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_metrics_rule_file_updates");
        
        // 创建指标实例
        let metrics = Arc::new(DnsMetrics::new());
        
        // 记录规则文件更新指标
        metrics.record_rule_file_update_success("/tmp/blocked.txt");
        metrics.record_rule_file_update_success("/tmp/blocked.txt");
        metrics.record_rule_file_update_failure("/tmp/nonexistent.txt", "File not found");
        
        // 记录规则URL更新指标
        metrics.record_rule_url_update_success("https://example.com/blocked.txt");
        metrics.record_rule_url_update_failure("https://invalid.com/404.txt", "404 Not Found");
        metrics.record_rule_url_update_failure("https://invalid.com/404.txt", "404 Not Found");
        
        // 导出指标
        let metrics_text = metrics.export_metrics();
        
        // 验证文件更新指标
        assert!(metrics_text.contains("dns_rule_file_updates_total{status=\"success\"} 2"), 
                "Metrics should include 2 successful file updates");
        assert!(metrics_text.contains("dns_rule_file_updates_total{status=\"failure\"} 1"), 
                "Metrics should include 1 failed file update");
        
        // 验证URL更新指标
        assert!(metrics_text.contains("dns_rule_url_updates_total{status=\"success\"} 1"), 
                "Metrics should include 1 successful URL update");
        assert!(metrics_text.contains("dns_rule_url_updates_total{status=\"failure\"} 2"), 
                "Metrics should include 2 failed URL updates");
        
        info!("Test completed: test_metrics_rule_file_updates");
    }
} 