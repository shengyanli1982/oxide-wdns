import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.*;
import okhttp3.*;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.*;

public class DoHClient {
    private static final Logger logger = LoggerFactory.getLogger(DoHClient.class);
    private static final OkHttpClient httpClient = createOkHttpClient();

    /**
     * 创建忽略证书验证的 OkHttpClient（仅用于测试）
     */
    private static OkHttpClient createOkHttpClient() {
        try {
            // 创建一个信任所有证书的 TrustManager
            TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    public void checkClientTrusted(X509Certificate[] chain, String authType) {}
                    public void checkServerTrusted(X509Certificate[] chain, String authType) {}
                    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                }
            };

            // 创建 SSLContext，并使用上面的 TrustManager
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAllCerts, new java.security.SecureRandom());

            // 创建 OkHttpClient
            return new OkHttpClient.Builder()
                .connectTimeout(10, TimeUnit.SECONDS)
                .readTimeout(10, TimeUnit.SECONDS)
                .writeTimeout(10, TimeUnit.SECONDS)
                .sslSocketFactory(sslContext.getSocketFactory(), (X509TrustManager) trustAllCerts[0])
                .hostnameVerifier((hostname, session) -> true)
                .build();
        } catch (Exception e) {
            logger.error("Failed to create OkHttpClient: {}", e.getMessage());
            // 如果出错，使用默认配置
            return new OkHttpClient.Builder()
                .connectTimeout(10, TimeUnit.SECONDS)
                .readTimeout(10, TimeUnit.SECONDS)
                .writeTimeout(10, TimeUnit.SECONDS)
                .build();
        }
    }

    /**
     * 向指定的 DoH 服务器发送 DNS 查询。
     *
     * @param serverUrl DoH 服务器的 URL (例如: "http://localhost:8080/dns-query")。
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
            logger.info("Sending query to {}: {} ({})", serverUrl, domainName, Type.string(queryType));
            try (Response response = httpClient.newCall(request).execute()) {
                // 4. 检查 HTTP 响应状态码
                if (!response.isSuccessful()) {
                    logger.error("HTTP request failed: {}", response.code());
                    return null;
                }

                // 5. 检查响应的内容类型
                String contentType = response.header("Content-Type");
                if (!"application/dns-message".equals(contentType)) {
                    logger.error("Server returned unexpected Content-Type: {}", contentType);
                    return null;
                }

                // 6. 使用 dnsjava 解析响应体中的 DNS 消息
                byte[] responseBody = response.body().bytes();
                Message responseMessage = new Message(responseBody);
                logger.info("Received response from {}", serverUrl);
                return responseMessage;
            }
        } catch (IOException e) {
            logger.error("Error requesting DoH server: {}", e.getMessage());
            return null;
        } catch (TextParseException e) {
            logger.error("Error parsing domain name: {}", e.getMessage());
            return null;
        } catch (Exception e) {
            logger.error("Unexpected error occurred: {}", e.getMessage());
            return null;
        }
    }

    // --- 示例用法 ---
    public static void main(String[] args) {
        // 标准路由
        String dohServer = "http://localhost:8080/dns-query";
        String domainToQuery = "www.example.com";

        // 查询 A 记录
        System.out.println("\n--- Querying A Record (" + domainToQuery + ") ---");
        Message aResponse = queryDoh(dohServer, domainToQuery, Type.A);
        if (aResponse != null) {
            System.out.println("Raw Response:\n" + aResponse);
            System.out.println("\nParsed Results (Answer Section):");
            Record[] answers = aResponse.getSectionArray(Section.ANSWER);
            if (answers.length > 0) {
                for (Record record : answers) {
                    System.out.println(record);
                }
            } else {
                System.out.println("No A records found.");
            }
        }

        // 查询 AAAA 记录
        System.out.println("\n--- Querying AAAA Record (" + domainToQuery + ") ---");
        Message aaaaResponse = queryDoh(dohServer, domainToQuery, Type.AAAA);
        if (aaaaResponse != null) {
            System.out.println("\nParsed Results (Answer Section):");
            Record[] answers = aaaaResponse.getSectionArray(Section.ANSWER);
            if (answers.length > 0) {
                for (Record record : answers) {
                    System.out.println(record);
                }
            } else {
                System.out.println("No AAAA records found.");
            }
        }

        // 查询 MX 记录
        System.out.println("\n--- Querying MX Record (google.com) ---");
        Message mxResponse = queryDoh(dohServer, "google.com", Type.MX);
        if (mxResponse != null) {
            System.out.println("\nParsed Results (Answer Section):");
            Record[] answers = mxResponse.getSectionArray(Section.ANSWER);
            if (answers.length > 0) {
                for (Record record : answers) {
                    System.out.println(record);
                }
            } else {
                System.out.println("No MX records found.");
            }
        }

        // 查询一个不存在的域名
        System.out.println("\n--- Querying Non-existent Domain (nonexistent-domain-askljhfdsa.com) ---");
        Message nxResponse = queryDoh(dohServer, "nonexistent-domain-askljhfdsa.com", Type.A);
        if (nxResponse != null) {
            System.out.println("Response Code: " + Rcode.string(nxResponse.getRcode()));
            System.out.println("\nParsed Results (Answer Section):");
            Record[] answers = nxResponse.getSectionArray(Section.ANSWER);
            if (answers.length > 0) {
                for (Record record : answers) {
                    System.out.println(record);
                }
            } else {
                System.out.println("No records found.");
            }
        }
    }
}