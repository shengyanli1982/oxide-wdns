# DoH 客户端测试工具 (`owdns-cli`) 设计要求

## 目标

创建一个命令行工具 (`owdns-cli`)，用于测试和验证 DoH 服务器的功能、兼容性和性能，特别是针对 `test/server.md` 中设计的服务端能力。

## 核心需求

1.  **发送 DoH 查询:** 能够向指定的 DoH 服务器 URL 发送 DNS 查询。
2.  **支持协议变体:**
    -   **HTTPS:** 支持通过 HTTPS 进行通信。
    -   **HTTP 版本:** 支持指定使用 HTTP/1.1 或 HTTP/2 (依赖客户端库能力)。
    -   **DoH 格式:** 支持发送 `application/dns-json` (JSON) 和 `application/dns-message` (Wireformat) 格式的请求。
    -   **HTTP 方法:** 支持使用 GET 和 POST 方法发送请求。
3.  **查询定制:**
    -   指定查询的 **域名 (Domain Name)**。
    -   指定查询的 **记录类型 (Record Type)** (如 A, AAAA, MX, CNAME, TXT, SRV, NS, SOA 等)。
    -   **DNSSEC DO 位:** 能够控制查询中是否设置 DNSSEC OK (DO) 标志。
4.  **服务端 `/dns-query` 端点测试:**
    -   能够向 `/dns-query` 端点发送标准 DoH 查询。
5.  **响应处理:**
    -   解析并以**可读格式**显示收到的 DNS 响应 (无论是 JSON 还是 Wireformat 解析后的结果)。
    -   显示请求的**耗时**。
    -   清晰地报告任何 HTTP 或 DNS 级别的**错误**。
6.  **安全性选项:**
    -   支持**跳过 TLS 证书验证** (使用 `-k` 或 `--insecure` 标志)，方便测试使用自签名证书的本地开发服务器。
7.  **易用性:**
    -   提供清晰的命令行接口和帮助信息。
    -   提供详细输出选项 (`-v` 或 `--verbose`)，显示完整的请求和响应细节 (包括 Headers)。

## 可选的增强功能

-   **原始载荷查询:** 支持直接提供十六进制编码的 DNS 查询报文作为载荷 (`--payload`)，用于高级或边界测试。
-   **结果验证:** 支持定义预期的响应内容或 RCODE，并自动判断测试是否通过。

## 命令行接口设计 (使用 `clap` 风格)

```bash
owdns-cli [OPTIONS] <SERVER_URL> <DOMAIN>
```

**参数 (Arguments):**

-   `<SERVER_URL>`: 必需。DoH 服务器的完整 URL (例如: `https://localhost:8080/dns-query`)。
-   `<DOMAIN>`: 必需。要查询的域名。

**选项 (Options):**

-   `-t, --type <TYPE>`: 指定 DNS 查询类型 (默认: `A`)。例如: `AAAA`, `MX`, `TXT`。
-   `--format <FORMAT>`: 指定 DoH 请求格式 (`json` 或 `wire`，默认: `wire`)。
-   `-X, --method <METHOD>`: 指定 HTTP 方法 (`GET` 或 `POST`)。默认根据查询大小和格式自动选择，或可强制指定。
-   `--http <VERSION>`: 指定首选的 HTTP 版本 (`1.1` 或 `2`)。
-   `--dnssec`: 在 DNS 查询中设置 DNSSEC OK (DO) 位。
-   `--payload <HEX_PAYLOAD>`: 发送原始 DNS 查询报文 (十六进制编码)。覆盖 `<DOMAIN>` 和 `-t, --type` 参数。
-   `-k, --insecure`: 跳过 TLS 证书验证。
-   `-v, --verbose`: 显示详细的请求和响应信息 (包括 HTTP 头)。多次使用增加详细程度。
-   `-h, --help`: 显示帮助信息。
-   `-V, --version`: 显示版本信息。

## 技术选型建议

-   **HTTP 客户端:** `reqwest`
-   **命令行解析:** `clap`
-   **DNS 协议处理:** `trust-dns-proto`
-   **JSON 处理:** `serde`, `serde_json`
-   **异步运行时:** `tokio`
