# 基于 Rust 的 DNS-over-HTTPS (DoH) 服务器设计需求

## 一、 核心功能

1.  **协议标准:** 严格遵循 IETF DNS-over-HTTPS (RFC 8484) 协议标准。
    -   **推荐库:** 无特定库，依赖于 HTTP 和 DNS 库的实现。
2.  **DoH 格式:**
    -   支持 DoH **JSON 格式** (`application/dns-json`)。
    -   支持 DoH **Wireformat 格式** (`application/dns-message`)，以提高效率和兼容性。
    -   **推荐库:** `trust-dns-proto` (用于 Wireformat 编解码), `serde_json` (用于 JSON 序列化/反序列化)。
3.  **HTTP 方法与版本:**
    -   HTTP 服务需支持 **HTTP/1.1 和 HTTP/2.0** 协议。
    -   支持处理 **GET 和 POST** 类型的 DoH 请求。
    -   **推荐库:** `axum` (用于构建 HTTP 服务器和路由), 底层依赖 `hyper`, `tokio`。
4.  **DNSSEC:** 支持对上游查询启用 **DNSSEC**，并对响应进行验证。
    -   **推荐库:** `trust-dns-resolver` (内置 DNSSEC 验证逻辑)。
5.  **上游解析器:**
    -   支持在配置文件中配置一个或多个**上游 DNS 解析器** (IP 地址、端口、协议: UDP/TCP/DoT/DoH)。
    -   实现与上游服务器的 DNS 查询逻辑 (包括 EDNS(0) 支持)。
    -   考虑实现基本的上游服务器**轮询或随机选择**策略。
    -   **推荐库:** `trust-dns-resolver` (用于向上游发送查询), `trust-dns-proto` (用于构建 DNS 查询消息)。

## 二、 缓存

7.  **LRU 缓存:**
    -   内部使用 Moka 实现 LRU 缓存。
    -   支持在配置文件中设置缓存**初始大小**、**最小 TTL** 和 **最大 TTL**。
    -   支持**负缓存** (Negative Caching)，缓存 NXDOMAIN 等错误结果。
    -   **推荐库:** `moka`。

## 三、 配置与管理

8.  **配置文件:**
    -   使用 YAML 格式的配置文件。
    -   支持通过 `serde` 进行解析。
    -   配置文件应包含：监听地址/端口、TLS 配置、上游服务器列表、缓存参数 (大小、TTL)、日志级别等。
    -   **推荐库:** `serde`, `serde_yaml`。
9.  **命令行参数:**
    -   使用 `clap` 解析命令行参数。
    -   主要实现 `-c, --config <PATH>` 指定配置文件路径。
    -   实现 `-t, --test` 参数，用于测试配置文件有效性。
    -   **推荐库:** `clap`。

## 四、 可观测性 (Observability)

10. **结构化日志:** 使用 `tracing` 库实现**结构化日志** (如 JSON 格式)，方便日志收集和分析。
    -   **推荐库:** `tracing`, `tracing-subscriber`。
11. **Prometheus 指标:**
    -   提供 `/metrics` 接口输出 Prometheus 指标。
    -   **核心指标:** 请求总数、按方法/状态码/协议 (HTTP/1.1, HTTP/2) 划分的请求计数、请求延迟直方图。
    -   **DNS 相关指标:** DNSSEC 验证成功/失败计数、按 RCODE 划分的响应计数、按上游服务器划分的查询计数/延迟。
    -   **缓存指标:** 缓存命中率、未命中率、当前条目数、驱逐数量。
    -   **推荐库:** `prometheus`。集成到 `axum` 路由。
12. **健康检查:** 提供 `/health` 接口，返回 200 状态码和 "ok" 字符串。
    -   **推荐库:** `axum` (用于实现路由)。

## 五、 健壮性与安全

13. **异步处理与框架:** 使用 `axum` 框架结合 `tokio` 实现异步 I/O 处理。
    -   **推荐库:** `axum`, `tokio`。
14. **优雅关闭:** 支持服务接收到终止信号时**优雅关闭**，完成正在处理的请求。
    -   **推荐库:** `tokio` (信号处理), `axum` (提供优雅关闭支持)。
15. **速率限制:** 实现基于源 IP 的**请求速率限制**，防止滥用。
    -   **推荐库:** `tower-governor` (作为 `axum` 中间件)。
16. **输入验证:** 对传入的 HTTP 请求和 DNS 查询进行**严格的输入验证**。
    -   **推荐库:** 结合 `axum` 的 extractor 和 `trust-dns-proto` 的解析能力进行。
17. **内存分配器 (全局):**
    -   **推荐库:** `mimalloc` (需要全局配置)。

## 六、 测试

18. **单元测试:** 为核心逻辑 (如 DNSSEC 验证、缓存操作) 编写单元测试。
    -   **工具:** Rust 内建测试框架 (`#[test]`)。
19. **集成测试:** 编写端到端测试，模拟客户端发送 DoH 请求 (包括 JSON/Wireformat, GET/POST)，验证完整流程。
    -   **工具:** Rust 内建测试框架 (`tests` 目录), 可能需要 `reqwest` 客户端库来发送 HTTP 请求。
