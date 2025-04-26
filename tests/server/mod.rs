// tests/server/mod.rs

// 声明测试模块
mod cache_tests;
mod config_tests;
mod doh_handler_advanced_tests;
// mod doh_upstream_test; // 可以取消注释或删除，取决于是否保留原始文件
// mod dnssec_test;      // 可以取消注释或删除
// mod rate_limit_tests; // 可以取消注释或删除
mod health_tests;
mod metrics_tests;
mod security_advanced_tests;
mod server_integration_tests;
mod signal_tests; // 信号测试可能需要特殊处理
mod upstream_tests;

// 可以考虑在此处放置一些跨模块共享的测试辅助函数或设置逻辑
// 例如： fn setup_test_environment() -> TestContext { ... } 