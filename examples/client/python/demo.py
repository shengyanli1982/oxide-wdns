# pip install requests dnspython

import logging

import dns.message
import dns.rdatatype
import requests

# 配置日志记录
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def query_doh(
    server_url: str, domain_name: str, query_type: dns.rdatatype.RdataType = dns.rdatatype.A
) -> dns.message.Message | None:
    """
    向指定的 DoH 服务器发送 DNS 查询。

    Args:
        server_url: DoH 服务器的 URL (例如: "https://localhost:8080/dns-query")。
        domain_name: 要查询的域名 (例如: "example.com")。
        query_type: 查询记录的类型 (例如: dns.rdatatype.A, dns.rdatatype.AAAA, dns.rdatatype.MX)。
                    默认为 A 记录。

    Returns:
        如果成功，返回解析后的 DNS 响应消息对象 (dns.message.Message)。
        如果失败，返回 None。
    """
    # 1. 使用 dnspython 构建 DNS 查询消息
    query = dns.message.make_query(domain_name, query_type)
    # 将查询消息序列化为 wire 格式 (二进制数据)
    query_wire = query.to_wire()

    # 2. 设置 HTTP 请求头
    headers = {
        # 指定期望接收 DNS 消息格式
        "Accept": "application/dns-message",
        # 指定发送的数据是 DNS 消息格式 (对于 POST 请求)
        "Content-Type": "application/dns-message",
    }

    try:
        # 3. 发送 HTTPS POST 请求
        logger.info(f"向 {server_url} 发送查询: {domain_name} ({dns.rdatatype.to_text(query_type)})")
        response = requests.post(server_url, headers=headers, data=query_wire, timeout=10)  # 设置超时时间

        # 4. 检查 HTTP 响应状态码
        response.raise_for_status()  # 如果状态码不是 2xx，则抛出异常

        # 5. 检查响应的内容类型
        if response.headers.get("Content-Type") != "application/dns-message":
            logger.error(f"服务器返回了非预期的 Content-Type: {response.headers.get('Content-Type')}")
            return None

        # 6. 使用 dnspython 解析响应体中的 DNS 消息
        response_message = dns.message.from_wire(response.content)
        logger.info(f"收到来自 {server_url} 的响应")
        return response_message

    except requests.exceptions.RequestException as e:
        logger.error(f"请求 DoH 服务器时出错: {e}")
        return None
    except dns.exception.DNSException as e:
        logger.error(f"解析 DNS 响应时出错: {e}")
        return None
    except Exception as e:
        logger.error(f"发生未知错误: {e}")
        return None


# --- 示例用法 ---
if __name__ == "__main__":
    # 常用的公共 DoH 服务器 URL
    # Cloudflare: "https://cloudflare-dns.com/dns-query"
    # Google: "https://dns.google/dns-query"
    # Quad9: "https://dns.quad9.net/dns-query"
    doh_server = "https://localhost:8080/dns-query"
    domain_to_query = "www.example.com"

    # 查询 A 记录
    print(f"\n--- 查询 A 记录 ({domain_to_query}) ---")
    a_response = query_doh(doh_server, domain_to_query, dns.rdatatype.A)
    if a_response:
        print("原始响应:\n", a_response)
        print("\n解析结果 (Answer Section):")
        if a_response.answer:
            for rrset in a_response.answer:
                print(rrset.to_text())
        else:
            print("未找到 A 记录。")
