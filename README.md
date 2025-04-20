# Oxide-WDNS - Rust DNS-over-HTTPS 服务器

基于 Rust 实现的高性能 DNS-over-HTTPS (DoH) 服务器，严格遵循 RFC 8484 标准。

## 主要功能

-   支持标准的 DNS-over-HTTPS 协议 (RFC 8484)
-   支持 DoH JSON 格式和 Wireformat 格式
-   支持 GET 和 POST 请求方法
-   支持 HTTP/1.1 和 HTTP/2.0
-   支持 DNSSEC 验证
-   支持多种上游 DNS 协议：UDP、TCP、DoT (DNS-over-TLS)、DoH (DNS-over-HTTPS)
-   内置 LRU 缓存优化性能
-   提供 Prometheus 指标监控
-   实现速率限制和输入验证，提高安全性

## 编译

确保已安装 Rust 开发环境 (1.70.0+)：

```bash
# 克隆仓库
git clone https://github.com/yourusername/oxide-wdns.git
cd oxide-wdns

# 编译
cargo build --release

# 二进制文件位于 target/release/owdns
```

## 配置

服务器使用 YAML 格式的配置文件，默认为 `config.yaml`。示例配置文件已包含在项目中。

```yaml
# 服务器监听地址
listen_addr: 127.0.0.1:3053

# 日志配置
log:
    level: info
    json: false

# 上游 DNS 服务器配置
upstream:
    enable_dnssec: true
    query_timeout: 5
    resolvers:
        - address: 8.8.8.8:53
          protocol: udp
        - address: cloudflare-dns.com@1.1.1.1:853
          protocol: dot
        - address: https://dns.quad9.net/dns-query
          protocol: doh

# 缓存配置
cache:
    enabled: true
    size: 10000
    min_ttl: 60
    max_ttl: 86400
# 更多配置项请参考配置文件示例
```

## 运行

```bash
# 使用默认配置文件 (config.yaml)
./target/release/owdns

# 指定配置文件
./target/release/owdns -c /path/to/config.yaml

# 启用详细日志
./target/release/owdns -v

# 仅测试配置有效性
./target/release/owdns -t
```

## 命令行工具

项目同时提供了一个命令行工具 `owdns-cli` 用于配置验证：

```bash
# 验证配置文件
./target/release/owdns-cli validate -c /path/to/config.yaml
```

## 使用示例

### 作为 DoH 服务器

启动服务器后，可以通过以下方式使用：

1. **DoH JSON 格式 (GET)**：

```
https://localhost:3053/dns-query?name=example.com&type=A
```

2. **DoH Wireformat 格式 (POST)**：

```bash
curl -X POST --data-binary @dns-query.bin \
     -H "Content-Type: application/dns-message" \
     https://localhost:3053/dns-query
```

## 指标监控

服务器提供了 Prometheus 格式的指标，可以通过 `/metrics` 端点访问：

```
http://localhost:3053/metrics
```

主要指标包括：

-   请求总数
-   按 HTTP 方法和内容类型的请求分类
-   按状态码的响应分类
-   请求延迟直方图
-   缓存命中率统计
-   DNSSEC 验证统计
-   上游解析器性能统计

## 健康检查

通过访问 `/health` 端点可以检查服务器健康状态：

```
http://localhost:3053/health
```

## 许可证

MIT
