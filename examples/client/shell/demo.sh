#!/bin/bash

# 这个脚本演示如何使用 curl 发送 DNS-over-HTTPS 查询
# 注意: 需要使用外部工具生成 DNS 查询包

# 使用预先生成的 DNS 查询二进制文件 (query.bin)
# 该文件包含一个查询 www.example.com 的 A 记录的 DNS 查询
# 如果你需要自己生成，可以使用 Python:
#
# import dns.message
# query = dns.message.make_query('www.example.com', 'A')
# with open('query.bin', 'wb') as f:
#     f.write(query.to_wire())

# 设置 DoH 服务器 URL
DOH_SERVER="http://localhost:8080/dns-query"

echo "--- Sending DNS-over-HTTP Query (www.example.com A Record) ---"
echo "Using server: $DOH_SERVER"
echo "Request method: POST"
echo

# 使用 curl 发送 DNS-over-HTTPS 查询
# --insecure 选项用于忽略 SSL 证书验证 (仅用于测试)
# -s 静默模式，不显示进度信息
# -D - 将响应头输出到标准输出
curl -s -D - \
     -X POST \
     -H "Content-Type: application/dns-message" \
     -H "Accept: application/dns-message" \
     -d @query.bin \
     "$DOH_SERVER"

echo
echo
echo "Note: This script only returns the raw binary response."
echo "Use implementations in other languages for easier response parsing."
