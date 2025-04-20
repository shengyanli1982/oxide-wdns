# 示例：查询 www.example.com 的 A 记录 (假设 DNS 查询已保存到文件 query.bin)
# 你需要先生成这个二进制的 DNS 查询文件 (query.bin)
# 例如，可以用类似下面的 Python 片段生成：
# import dns.message
# query = dns.message.make_query('www.example.com', 'A')
# with open('query.bin', 'wb') as f:
#     f.write(query.to_wire())


# 使用 curl 发送 DNS 查询
curl -i -X POST \
    -H "Content-Type: application/dns-message" \
    -H "Accept: application/dns-message" \
    -d @query.bin \
    "http://localhost:8080/dns-query"
