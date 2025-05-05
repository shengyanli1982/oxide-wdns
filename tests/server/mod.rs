// tests/server/mod.rs

// 公共测试模块，包含共享的测试函数和工具
pub mod mock_http_server;

// 声明测试模块
mod args_tests;
mod cache_tests;
mod config_tests;
mod doh_handler_advanced_tests;
mod health_tests;
mod metrics_tests;
mod routing_tests; // 新增的DNS分流测试模块
mod server_integration_tests;
mod signal_tests; // 信号测试可能需要特殊处理
mod upstream_tests;

// 注意：在Rust测试中，不需要使用pub use语句导出测试模块
// 可以通过 cargo test -p oxide-wdns server::server_integration_tests 等方式直接运行指定测试
