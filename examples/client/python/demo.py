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
        server_url: DoH 服务器的 URL (例如: "http://localhost:8080/dns-query")。
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
        logger.info(f"Sending query to {server_url}: {domain_name} ({dns.rdatatype.to_text(query_type)})")
        response = requests.post(server_url, headers=headers, data=query_wire, timeout=10, verify=False)  # 设置超时时间

        # 4. 检查 HTTP 响应状态码
        response.raise_for_status()  # 如果状态码不是 2xx，则抛出异常

        # 5. 检查响应的内容类型
        if response.headers.get("Content-Type") != "application/dns-message":
            logger.error(f"Server returned unexpected Content-Type: {response.headers.get('Content-Type')}")
            return None

        # 6. 使用 dnspython 解析响应体中的 DNS 消息
        response_message = dns.message.from_wire(response.content)
        logger.info(f"Received response from {server_url}")
        return response_message

    except requests.exceptions.RequestException as e:
        logger.error(f"Error requesting DoH server: {e}")
        return None
    except dns.exception.DNSException as e:
        logger.error(f"Error parsing DNS response: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error occurred: {e}")
        return None


# --- 示例用法 ---
if __name__ == "__main__":
    # 标准路由
    doh_server = "http://localhost:8080/dns-query"
    domain_to_query = "www.example.com"

    # 查询 A 记录
    print(f"\n--- Querying A Record ({domain_to_query}) ---")
    a_response = query_doh(doh_server, domain_to_query, dns.rdatatype.A)
    if a_response:
        print("Raw Response:\n", a_response)
        print("\nParsed Results (Answer Section):")
        if a_response.answer:
            for rrset in a_response.answer:
                print(rrset.to_text())
        else:
            print("No A records found.")

    # 查询 AAAA 记录
    print(f"\n--- Querying AAAA Record ({domain_to_query}) ---")
    aaaa_response = query_doh(doh_server, domain_to_query, dns.rdatatype.AAAA)
    if aaaa_response:
        print("\nParsed Results (Answer Section):")
        if aaaa_response.answer:
            for rrset in aaaa_response.answer:
                print(rrset.to_text())
        else:
            print("No AAAA records found.")

    # 查询 MX 记录
    print("\n--- Querying MX Record (google.com) ---")
    mx_response = query_doh(doh_server, "google.com", dns.rdatatype.MX)
    if mx_response:
        print("\nParsed Results (Answer Section):")
        if mx_response.answer:
            for rrset in mx_response.answer:
                print(rrset.to_text())
        else:
            print("No MX records found.")

    # 查询一个不存在的域名
    print("\n--- Querying Non-existent Domain (nonexistent-domain-askljhfdsa.com) ---")
    nx_response = query_doh(doh_server, "nonexistent-domain-askljhfdsa.com", dns.rdatatype.A)
    if nx_response:
        print("Response Code:", dns.rcode.to_text(nx_response.rcode()))
        print("\nParsed Results (Answer Section):")
        if nx_response.answer:
            for rrset in nx_response.answer:
                print(rrset.to_text())
        else:
            print("No records found.")
