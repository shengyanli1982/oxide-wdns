import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.*;
import okhttp3.*;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

public class DoHClient {
    private static final Logger logger = LoggerFactory.getLogger(DoHClient.class);
    private static final OkHttpClient httpClient = new OkHttpClient.Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(10, TimeUnit.SECONDS)
            .writeTimeout(10, TimeUnit.SECONDS)
            .build();

    /**
     * 向指定的 DoH 服务器发送 DNS 查询。
     *
     * @param serverUrl DoH 服务器的 URL (例如: "https://cloudflare-dns.com/dns-query")。
     * @param domainName 要查询的域名 (例如: "example.com")。
     * @param queryType 查询记录的类型 (例如: Type.A, Type.AAAA, Type.MX)。
     *                  默认为 A 记录。
     * @return 如果成功，返回解析后的 DNS 响应消息对象 (Message)。
     *         如果失败，返回 null。
     */
    public static Message queryDoh(String serverUrl, String domainName, int queryType) {
        try {
            // 1. 使用 dnsjava 构建 DNS 查询消息
            Record question = Record.newRecord(Name.fromString(domainName + "."), queryType, DClass.IN);
            Message query = Message.newQuery(question);
            // 将查询消息序列化为 wire 格式 (二进制数据)
            byte[] queryWire = query.toWire();

            // 2. 设置 HTTP 请求头
            RequestBody requestBody = RequestBody.create(
                    queryWire,
                    MediaType.parse("application/dns-message")
            );

            Request request = new Request.Builder()
                    .url(serverUrl)
                    .addHeader("Accept", "application/dns-message")
                    .post(requestBody)
                    .build();

            // 3. 发送 HTTPS POST 请求
            logger.info("向 {} 发送查询: {} ({})", serverUrl, domainName, Type.string(queryType));
            try (Response response = httpClient.newCall(request).execute()) {
                // 4. 检查 HTTP 响应状态码
                if (!response.isSuccessful()) {
                    logger.error("HTTP 请求失败: {}", response.code());
                    return null;
                }

                // 5. 检查响应的内容类型
                String contentType = response.header("Content-Type");
                if (!"application/dns-message".equals(contentType)) {
                    logger.error("服务器返回了非预期的 Content-Type: {}", contentType);
                    return null;
                }

                // 6. 使用 dnsjava 解析响应体中的 DNS 消息
                byte[] responseBody = response.body().bytes();
                Message responseMessage = new Message(responseBody);
                logger.info("收到来自 {} 的响应", serverUrl);
                return responseMessage;
            }
        } catch (IOException e) {
            logger.error("请求 DoH 服务器时出错: {}", e.getMessage());
            return null;
        } catch (TextParseException e) {
            logger.error("解析域名时出错: {}", e.getMessage());
            return null;
        } catch (Exception e) {
            logger.error("发生未知错误: {}", e.getMessage());
            return null;
        }
    }

    // --- 示例用法 ---
    public static void main(String[] args) {
        // 常用的公共 DoH 服务器 URL
        // Cloudflare: "https://cloudflare-dns.com/dns-query"
        // Google: "https://dns.google/dns-query"
        // Quad9: "https://dns.quad9.net/dns-query"
        String dohServer = "https://localhost:8080/dns-query";
        String domainToQuery = "www.example.com";

        // 查询 A 记录
        System.out.println("\n--- 查询 A 记录 (" + domainToQuery + ") ---");
        Message aResponse = queryDoh(dohServer, domainToQuery, Type.A);
        if (aResponse != null) {
            System.out.println("原始响应:\n" + aResponse);
            System.out.println("\n解析结果 (Answer Section):");
            Record[] answers = aResponse.getSectionArray(Section.ANSWER);
            if (answers.length > 0) {
                for (Record record : answers) {
                    System.out.println(record);
                }
            } else {
                System.out.println("未找到 A 记录。");
            }
        }

        // 查询 AAAA 记录
        System.out.println("\n--- 查询 AAAA 记录 (" + domainToQuery + ") ---");
        Message aaaaResponse = queryDoh(dohServer, domainToQuery, Type.AAAA);
        if (aaaaResponse != null) {
            // System.out.println("原始响应:\n" + aaaaResponse); // 可以取消注释查看完整响应
            System.out.println("\n解析结果 (Answer Section):");
            Record[] answers = aaaaResponse.getSectionArray(Section.ANSWER);
            if (answers.length > 0) {
                for (Record record : answers) {
                    System.out.println(record);
                }
            } else {
                System.out.println("未找到 AAAA 记录。");
            }
        }

        // 查询 MX 记录
        System.out.println("\n--- 查询 MX 记录 (google.com) ---");
        Message mxResponse = queryDoh(dohServer, "google.com", Type.MX);
        if (mxResponse != null) {
            // System.out.println("原始响应:\n" + mxResponse); // 可以取消注释查看完整响应
            System.out.println("\n解析结果 (Answer Section):");
            Record[] answers = mxResponse.getSectionArray(Section.ANSWER);
            if (answers.length > 0) {
                for (Record record : answers) {
                    System.out.println(record);
                }
            } else {
                System.out.println("未找到 MX 记录。");
            }
        }

        // 查询一个不存在的域名
        System.out.println("\n--- 查询不存在的域名 (nonexistent-domain-askljhfdsa.com) ---");
        Message nxResponse = queryDoh(dohServer, "nonexistent-domain-askljhfdsa.com", Type.A);
        if (nxResponse != null) {
            System.out.println("原始响应:\n" + nxResponse);
            System.out.println("\n解析结果 (Answer Section):");
            Record[] answers = nxResponse.getSectionArray(Section.ANSWER);
            if (answers.length > 0) {
                for (Record record : answers) {
                    System.out.println(record);
                }
            } else {
                // 对于不存在的域名，Answer Section 通常为空，RCODE 会是 NXDOMAIN
                System.out.println("未找到记录。响应码 (RCODE): " + Rcode.string(nxResponse.getRcode()));
            }
        }
    }
}