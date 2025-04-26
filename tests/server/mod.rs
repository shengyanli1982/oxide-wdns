// tests/server/mod.rs

// 声明测试模块
mod cache_tests;
mod config_tests;
mod doh_handler_advanced_tests;
mod health_tests;
mod metrics_tests;
mod server_integration_tests;
mod signal_tests; // 信号测试可能需要特殊处理
mod upstream_tests;

// 注意：在Rust测试中，不需要使用pub use语句导出测试模块
// 可以通过 cargo test -p oxide-wdns server::server_integration_tests 等方式直接运行指定测试
