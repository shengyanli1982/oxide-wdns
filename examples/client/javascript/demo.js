// npm install dns-packet
// node 18+

const { encode, decode, RECURSION_DESIRED } = require("dns-packet");

// 配置日志（简单示例）
const logger = {
    info: console.log,
    error: console.error,
};

/**
 * 向指定的 DoH 服务器发送 DNS 查询。
 *
 * @param {string} serverUrl DoH 服务器的 URL (例如: "http://localhost:8080/dns-query")。
 * @param {string} domainName 要查询的域名 (例如: "example.com")。
 * @param {string} queryType 查询记录的类型 (例如: "A", "AAAA", "MX")。默认为 "A"。
 * @returns {Promise<object|null>} 如果成功，返回解析后的 DNS 响应对象。如果失败，返回 null。
 */
async function queryDoh(serverUrl, domainName, queryType = "A") {
    // 1. 使用 dns-packet 构建 DNS 查询消息
    const queryBuf = encode({
        type: "query",
        id: Math.floor(Math.random() * 65535), // 随机生成 ID
        flags: RECURSION_DESIRED, // RD flag (Recursion Desired)
        questions: [
            {
                type: queryType.toUpperCase(), // 确保类型大写
                name: domainName,
                class: "IN", // Internet class
            },
        ],
    });

    // 2. 设置 HTTP 请求头
    const headers = {
        Accept: "application/dns-message",
        "Content-Type": "application/dns-message",
    };

    try {
        // 3. 发送 HTTPS POST 请求
        logger.info(`Sending query to ${serverUrl}: ${domainName} (${queryType})`);
        const response = await fetch(serverUrl, {
            method: "POST",
            headers: headers,
            body: queryBuf, // 发送 Buffer 数据
            timeout: 10000, // 设置超时时间 (毫秒)
        });

        // 4. 检查 HTTP 响应状态码
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status} ${response.statusText}`);
        }

        // 5. 检查响应的内容类型
        const contentType = response.headers.get("content-type");
        if (contentType !== "application/dns-message") {
            logger.error(`Server returned unexpected Content-Type: ${contentType}`);
            return null;
        }

        // 6. 使用 dns-packet 解析响应体中的 DNS 消息
        // 获取响应体为 ArrayBuffer
        const arrayBuffer = await response.arrayBuffer();
        const responseBuf = Buffer.from(arrayBuffer);

        const responseMessage = decode(responseBuf);
        logger.info(`Received response from ${serverUrl}`);
        return responseMessage;
    } catch (error) {
        if (error.name === "AbortError" || error.code === "ETIMEOUT" || error.code === "ECONNRESET") {
            logger.error(`Request timeout or connection reset: ${error.message}`);
        } else if (error instanceof Error && error.message.startsWith("HTTP error!")) {
            logger.error(`Error requesting DoH server: ${error.message}`);
        } else {
            logger.error(`Error processing DoH request/response: ${error}`);
        }
        return null;
    }
}

// --- 示例用法 ---
async function runExamples() {
    // 标准路由
    const dohServer = "http://localhost:8080/dns-query";
    const domainToQuery = "www.example.com";

    // 查询 A 记录
    console.log(`\n--- Querying A Record (${domainToQuery}) ---`);
    const aResponse = await queryDoh(dohServer, domainToQuery, "A");
    if (aResponse) {
        console.log("Raw Response:\n", JSON.stringify(aResponse, null, 2)); // 打印 JSON 格式
        console.log("\nParsed Results (Answers):");
        if (aResponse.answers && aResponse.answers.length > 0) {
            aResponse.answers.forEach((answer) => console.log(answer));
        } else {
            console.log("No A records found.");
        }
    }

    // 查询 AAAA 记录
    console.log(`\n--- Querying AAAA Record (${domainToQuery}) ---`);
    const aaaaResponse = await queryDoh(dohServer, domainToQuery, "AAAA");
    if (aaaaResponse) {
        console.log("\nParsed Results (Answers):");
        if (aaaaResponse.answers && aaaaResponse.answers.length > 0) {
            aaaaResponse.answers.forEach((answer) => console.log(answer));
        } else {
            console.log("No AAAA records found.");
        }
    }

    // 查询 MX 记录
    console.log(`\n--- Querying MX Record (google.com) ---`);
    const mxResponse = await queryDoh(dohServer, "google.com", "MX");
    if (mxResponse) {
        console.log("\nParsed Results (Answers):");
        if (mxResponse.answers && mxResponse.answers.length > 0) {
            mxResponse.answers.forEach((answer) => console.log(answer)); // MX 记录包含 preference 和 exchange
        } else {
            console.log("No MX records found.");
        }
    }

    // 查询一个不存在的域名
    console.log(`\n--- Querying Non-existent Domain (nonexistent-domain-askljhfdsa.com) ---`);
    const nxResponse = await queryDoh(dohServer, "nonexistent-domain-askljhfdsa.com", "A");
    if (nxResponse) {
        console.log("Response Code:", nxResponse.rcode);
        console.log("\nParsed Results (Answers):");
        if (nxResponse.answers && nxResponse.answers.length > 0) {
            nxResponse.answers.forEach((answer) => console.log(answer));
        } else {
            console.log("No records found.");
        }
    }
}

// 添加忽略SSL证书验证的代码（仅用于本地测试）
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

// 执行示例
runExamples().catch((err) => {
    console.error("Unexpected error running examples:", err);
});
