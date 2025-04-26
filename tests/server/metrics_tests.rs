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
        // 1. 获取/创建指标注册表
        let metrics = setup_metrics();
        
        // 2. 调用记录请求的方法
        metrics.record_request("GET", "application/dns-message");
        
        // 3. 读取请求总数计数器的值
        let value = metrics.total_requests.get();
        
        // 4. 断言：计数器值增加了 1
        assert_eq!(value, 1, "Request counter should be incremented by 1");
    }

    #[tokio::test]
    async fn test_metrics_error_total_counter() {
        // 1. 获取/创建指标注册表
        let metrics = setup_metrics();
        
        // 2. 调用记录错误的方法
        metrics.record_error("dns_format_error");
        
        // 3. 读取错误总数计数器的值
        let value = metrics.errors.with_label_values(&["dns_format_error"]).get();
        
        // 4. 断言：计数器值增加了 1
        assert_eq!(value, 1, "Error counter should be incremented by 1");
    }

    #[tokio::test]
    async fn test_metrics_cache_hit_counter() {
        // 1. 获取/创建指标注册表
        let metrics = setup_metrics();
        
        // 2. 调用记录缓存命中的方法
        metrics.cache_hits.inc();
        
        // 3. 读取缓存命中计数器的值
        let value = metrics.cache_hits.get();
        
        // 4. 断言：计数器值增加了 1
        assert_eq!(value, 1, "Cache hit counter should be incremented by 1");
    }

    #[tokio::test]
    async fn test_metrics_cache_miss_counter() {
        // 1. 获取/创建指标注册表
        let metrics = setup_metrics();
        
        // 2. 调用记录缓存未命中的方法
        metrics.cache_misses.inc();
        
        // 3. 读取缓存未命中计数器的值
        let value = metrics.cache_misses.get();
        
        // 4. 断言：计数器值增加了 1
        assert_eq!(value, 1, "Cache miss counter should be incremented by 1");
    }

    #[tokio::test]
    async fn test_metrics_upstream_query_duration_histogram() {
        // 1. 获取/创建指标注册表
        let metrics = setup_metrics();
        
        // 2. 调用记录上游查询持续时间的方法
        let duration = Duration::from_millis(150); // 150毫秒
        metrics.record_upstream_query("cloudflare", duration);
        
        // 3. 获取直方图的样本总数
        let sample_count = metrics.upstream_query_duration
            .with_label_values(&["cloudflare"])
            .get_sample_count();
        
        // 4. 断言：直方图至少有一个样本
        assert_eq!(sample_count, 1, "Histogram should have recorded exactly one sample");
        
        // 5. 获取样本的总和
        let sample_sum = metrics.upstream_query_duration
            .with_label_values(&["cloudflare"])
            .get_sample_sum();
        
        // 6. 断言：样本总和应该是duration转换为秒后的值（接近0.15）
        assert!(
            (sample_sum - 0.15).abs() < 0.001, 
            "Sample sum should be approximately 0.15 seconds"
        );
    }

    #[tokio::test]
    async fn test_metrics_prometheus_output_format() {
        // 1. 创建服务器并获取URL
        let server_url = setup_metrics_server().await;
        
        // 2. 设置一些指标数据（在线程本地存储中）
        METRICS.with(|m| {
            m.record_request("GET", "application/dns-message");
            m.cache_hits.inc();
            m.record_dns_query_type("A");
            m.record_error("parse_error");
        });
        
        // 3. 请求指标端点
        let client = Client::new();
        let response = client.get(format!("{}/metrics", server_url))
            .send()
            .await
            .expect("Failed to send request");
        
        // 4. 检查响应状态
        assert_eq!(response.status().as_u16(), 200, "Expected 200 OK response");
        
        // 5. 获取响应体
        let body = response.text().await.expect("Failed to get response body");
        
        // 6. 验证输出格式包含预期的指标名称
        assert!(body.contains("doh_requests_total"), "Output should contain total requests metric");
        assert!(body.contains("doh_cache_hits"), "Output should contain cache hits metric");
        assert!(body.contains("doh_dns_queries_by_type"), "Output should contain DNS queries by type metric");
        assert!(body.contains("doh_errors"), "Output should contain errors metric");
        
        // 7. 验证输出包含必要的Prometheus元数据
        assert!(body.contains("# HELP"), "Output should contain HELP metadata");
        assert!(body.contains("# TYPE"), "Output should contain TYPE metadata");
    }

    #[tokio::test]
    async fn test_metrics_reset_or_recreate() {
        // 1. 创建第一个指标实例并记录数据
        let metrics1 = DnsMetrics::new();
        metrics1.total_requests.inc();
        metrics1.cache_hits.inc();
        assert_eq!(metrics1.total_requests.get(), 1);
        assert_eq!(metrics1.cache_hits.get(), 1);
        
        // 2. 创建新的指标实例（模拟重置）
        let metrics2 = DnsMetrics::new();
        
        // 3. 验证新实例的计数器为初始状态（0）
        assert_eq!(metrics2.total_requests.get(), 0, "New instance should have counter value 0");
        assert_eq!(metrics2.cache_hits.get(), 0, "New instance should have counter value 0");
    }
} 