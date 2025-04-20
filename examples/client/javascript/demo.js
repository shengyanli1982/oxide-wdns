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
 * @param {string} serverUrl DoH 服务器的 URL (例如: "https://cloudflare-dns.com/dns-query")。
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
        logger.info(`向 ${serverUrl} 发送查询: ${domainName} (${queryType})`);
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
            logger.error(`服务器返回了非预期的 Content-Type: ${contentType}`);
            return null;
        }

        // 6. 使用 dns-packet 解析响应体中的 DNS 消息
        // node-fetch v2 返回 Buffer, v3+ 或内置 fetch 返回 ArrayBuffer
        const responseBuf = await response.buffer(); // 获取响应体为 Buffer (node-fetch v2)
        // 如果使用内置 fetch 或 node-fetch v3+, 需要:
        // const arrayBuffer = await response.arrayBuffer();
        // const responseBuf = Buffer.from(arrayBuffer);

        const responseMessage = decode(responseBuf);
        logger.info(`收到来自 ${serverUrl} 的响应`);
        return responseMessage;
    } catch (error) {
        if (error.name === "AbortError" || error.code === "ETIMEOUT" || error.code === "ECONNRESET") {
            logger.error(`请求 DoH 服务器超时或连接重置: ${error.message}`);
        } else if (error instanceof Error && error.message.startsWith("HTTP error!")) {
            logger.error(`请求 DoH 服务器时出错: ${error.message}`);
        } else {
            logger.error(`处理 DoH 请求/响应时出错: ${error}`);
        }
        return null;
    }
}

// --- 示例用法 ---
async function runExamples() {
    // 常用的公共 DoH 服务器 URL
    // Cloudflare: "https://cloudflare-dns.com/dns-query"
    // Google: "https://dns.google/dns-query"
    // Quad9: "https://dns.quad9.net/dns-query"
    // 本地: "https://localhost:8080/dns-query" or "http://localhost:8080/dns-query"
    const dohServer = "https://localhost:8080/dns-query";
    const domainToQuery = "www.example.com";

    // 查询 A 记录
    console.log(`\n--- 查询 A 记录 (${domainToQuery}) ---`);
    const aResponse = await queryDoh(dohServer, domainToQuery, "A");
    if (aResponse) {
        console.log("原始响应:\n", JSON.stringify(aResponse, null, 2)); // 打印 JSON 格式
        console.log("\n解析结果 (Answers):");
        if (aResponse.answers && aResponse.answers.length > 0) {
            aResponse.answers.forEach((answer) => console.log(answer));
        } else {
            console.log("未找到 A 记录。");
        }
    }

    // 查询 AAAA 记录
    console.log(`\n--- 查询 AAAA 记录 (${domainToQuery}) ---`);
    const aaaaResponse = await queryDoh(dohServer, domainToQuery, "AAAA");
    if (aaaaResponse) {
        // console.log("原始响应:\n", JSON.stringify(aaaaResponse, null, 2));
        console.log("\n解析结果 (Answers):");
        if (aaaaResponse.answers && aaaaResponse.answers.length > 0) {
            aaaaResponse.answers.forEach((answer) => console.log(answer));
        } else {
            console.log("未找到 AAAA 记录。");
        }
    }

    // 查询 MX 记录
    console.log(`\n--- 查询 MX 记录 (google.com) ---`);
    const mxResponse = await queryDoh(dohServer, "google.com", "MX");
    if (mxResponse) {
        // console.log("原始响应:\n", JSON.stringify(mxResponse, null, 2));
        console.log("\n解析结果 (Answers):");
        if (mxResponse.answers && mxResponse.answers.length > 0) {
            mxResponse.answers.forEach((answer) => console.log(answer)); // MX 记录包含 preference 和 exchange
        } else {
            console.log("未找到 MX 记录。");
        }
    }

    // 查询一个不存在的域名
    console.log(`\n--- 查询不存在的域名 (nonexistent-domain-askljhfdsa.com) ---`);
    const nxResponse = await queryDoh(dohServer, "nonexistent-domain-askljhfdsa.com", "A");
    if (nxResponse) {
        console.log("原始响应:\n", JSON.stringify(nxResponse, null, 2));
        console.log("\n解析结果 (Answers):");
        if (nxResponse.answers && nxResponse.answers.length > 0) {
            nxResponse.answers.forEach((answer) => console.log(answer));
        } else {
            // 检查响应状态码 (RCODE)
            console.log(`未找到记录。响应状态: ${nxResponse.rcode || "N/A"}`); // NXDOMAIN 表示不存在
        }
    }
}

// 执行示例
runExamples().catch((err) => {
    console.error("运行示例时发生意外错误:", err);
});
