package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// queryDoH向指定的DoH服务器发送DNS查询。
func queryDoH(serverURL string, domainName string, queryType dnsmessage.Type) (*dnsmessage.Message, error) {
	// 1. 使用 dnsmessage 构建 DNS 查询消息
	// 确保域名以点结尾 (FQDN)
	if domainName[len(domainName)-1] != '.' {
		domainName += "."
	}
	name, err := dnsmessage.NewName(domainName)
	if err != nil {
		return nil, fmt.Errorf("invalid domain name '%s': %w", domainName, err)
	}

	// 创建查询问题
	question := dnsmessage.Question{
		Name:  name,
		Type:  queryType,
		Class: dnsmessage.ClassINET,
	}

	// 构建查询消息
	// ID 设置为 0 通常可以接受，或者可以生成随机 ID
	// RecursionDesired 通常在客户端查询中设置为 true
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               0, // 可以设置为随机数，但 0 通常也有效
			Response:         false,
			OpCode:           0, // Standard Query
			RecursionDesired: true,
		},
		Questions: []dnsmessage.Question{question},
	}

	// 将查询消息打包为 wire 格式 (二进制数据)
	queryWire, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack DNS query: %w", err)
	}

	// 2. 准备 HTTP POST 请求
	req, err := http.NewRequest(http.MethodPost, serverURL, bytes.NewReader(queryWire))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// 设置 HTTP 请求头
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-Type", "application/dns-message")

	// 3. 发送 HTTPS POST 请求
	// 创建带超时的 HTTP 客户端，并忽略证书验证（仅用于测试）
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{
		Timeout:   10 * time.Second, // 设置超时
		Transport: transport,
	}

	log.Printf("Sending query to %s: %s (%s)\n", serverURL, domainName, queryType.String())
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute HTTP request: %w", err)
	}
	// 确保在函数结束时关闭响应体
	defer resp.Body.Close()

	// 4. 检查 HTTP 响应状态码
	if resp.StatusCode != http.StatusOK {
		// 尝试读取响应体以获取更多错误信息
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("DoH server returned unexpected status code %d: %s", resp.StatusCode, string(bodyBytes))
	}

	// 5. 检查响应的内容类型
	contentType := resp.Header.Get("Content-Type")
	if contentType != "application/dns-message" {
		return nil, fmt.Errorf("DoH server returned unexpected Content-Type: %s", contentType)
	}

	// 6. 读取并解析响应体中的 DNS 消息
	responseWire, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read HTTP response body: %w", err)
	}

	var responseMsg dnsmessage.Message
	err = responseMsg.Unpack(responseWire)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DNS response: %w", err)
	}

	log.Printf("Received response from %s\n", serverURL)
	return &responseMsg, nil
}

// --- 示例用法 ---
func main() {
	// 标准路由
	dohServer := "http://localhost:8080/dns-query"
	domainToQuery := "www.example.com"

	// --- 查询 A 记录 ---
	fmt.Printf("\n--- Querying A Record (%s) ---\n", domainToQuery)
	aResponse, err := queryDoH(dohServer, domainToQuery, dnsmessage.TypeA)
	if err != nil {
		log.Printf("Failed to query A record: %v\n", err)
	} else {
		fmt.Println("Raw Response Header:", aResponse.Header) // 打印响应头信息
		fmt.Println("Parsed Results (Answer Section):")
		if len(aResponse.Answers) > 0 {
			for _, answer := range aResponse.Answers {
				// 根据记录类型处理不同的资源记录
				switch rr := answer.Body.(type) {
				case *dnsmessage.AResource:
					fmt.Printf("A Record: %v.%v.%v.%v\n", rr.A[0], rr.A[1], rr.A[2], rr.A[3])
				default:
					fmt.Printf("Unknown record type: %T\n", rr)
				}
			}
		} else {
			fmt.Println("No A records found.")
		}
	}

	// --- 查询 AAAA 记录 ---
	fmt.Printf("\n--- Querying AAAA Record (%s) ---\n", domainToQuery)
	aaaaResponse, err := queryDoH(dohServer, domainToQuery, dnsmessage.TypeAAAA)
	if err != nil {
		log.Printf("Failed to query AAAA record: %v\n", err)
	} else {
		fmt.Println("Parsed Results (Answer Section):")
		if len(aaaaResponse.Answers) > 0 {
			for _, answer := range aaaaResponse.Answers {
				switch rr := answer.Body.(type) {
				case *dnsmessage.AAAAResource:
					fmt.Printf("AAAA Record: %x:%x:%x:%x:%x:%x:%x:%x\n",
						rr.AAAA[0:2], rr.AAAA[2:4], rr.AAAA[4:6], rr.AAAA[6:8],
						rr.AAAA[8:10], rr.AAAA[10:12], rr.AAAA[12:14], rr.AAAA[14:16])
				default:
					fmt.Printf("Unknown record type: %T\n", rr)
				}
			}
		} else {
			fmt.Println("No AAAA records found.")
		}
	}

	// --- 查询 MX 记录 ---
	fmt.Printf("\n--- Querying MX Record (google.com) ---\n")
	mxResponse, err := queryDoH(dohServer, "google.com", dnsmessage.TypeMX)
	if err != nil {
		log.Printf("Failed to query MX record: %v\n", err)
	} else {
		fmt.Println("Parsed Results (Answer Section):")
		if len(mxResponse.Answers) > 0 {
			for _, answer := range mxResponse.Answers {
				switch rr := answer.Body.(type) {
				case *dnsmessage.MXResource:
					fmt.Printf("MX Record: Priority=%d, Server=%s\n", rr.Pref, rr.MX.String())
				default:
					fmt.Printf("Unknown record type: %T\n", rr)
				}
			}
		} else {
			fmt.Println("No MX records found.")
		}
	}

	// --- 查询一个不存在的域名 ---
	fmt.Printf("\n--- Querying Non-existent Domain (nonexistent-domain-askljhfdsa.com) ---\n")
	nxDomain := "nonexistent-domain-askljhfdsa.com"
	nxResponse, err := queryDoH(dohServer, nxDomain, dnsmessage.TypeA)
	if err != nil {
		log.Printf("Failed to query %s: %v\n", nxDomain, err)
	} else {
		fmt.Println("Response Code:", nxResponse.Header.RCode.String())
		fmt.Println("Parsed Results (Answer Section):")
		if len(nxResponse.Answers) > 0 {
			for _, answer := range nxResponse.Answers {
				switch rr := answer.Body.(type) {
				case *dnsmessage.AResource:
					fmt.Printf("A Record: %v.%v.%v.%v\n", rr.A[0], rr.A[1], rr.A[2], rr.A[3])
				default:
					fmt.Printf("Unknown record type: %T\n", rr)
				}
			}
		} else {
			fmt.Println("No records found.")
		}
	}
}
