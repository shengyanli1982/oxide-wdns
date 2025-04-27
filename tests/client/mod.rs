// tests/client/mod.rs

// 客户端模块集成测试

// 测试子模块
mod args_tests;
mod request_tests;
mod response_tests;
mod core_tests;
mod error_tests;
mod cli_integration_tests; 

// 注意：在Rust测试中，不需要使用pub use语句导出测试模块
// 可以通过 cargo test -p oxide-wdns client::client_integration_tests 等方式直接运行指定测试