package main

import (
	"bytes"
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
		return nil, fmt.Errorf("无效的域名 '%s': %w", domainName, err)
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
		return nil, fmt.Errorf("打包 DNS 查询失败: %w", err)
	}

	// 2. 准备 HTTP POST 请求
	req, err := http.NewRequest(http.MethodPost, serverURL, bytes.NewReader(queryWire))
	if err != nil {
		return nil, fmt.Errorf("创建 HTTP 请求失败: %w", err)
	}

	// 设置 HTTP 请求头
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-Type", "application/dns-message")

	// 3. 发送 HTTPS POST 请求
	// 创建带超时的 HTTP 客户端
	client := &http.Client{
		Timeout: 10 * time.Second, // 设置超时
	}

	log.Printf("向 %s 发送查询: %s (%s)\n", serverURL, domainName, queryType.String())
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("执行 HTTP 请求失败: %w", err)
	}
	// 确保在函数结束时关闭响应体
	defer resp.Body.Close()

	// 4. 检查 HTTP 响应状态码
	if resp.StatusCode != http.StatusOK {
		// 尝试读取响应体以获取更多错误信息
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("DoH 服务器返回非预期状态码 %d: %s", resp.StatusCode, string(bodyBytes))
	}

	// 5. 检查响应的内容类型
	contentType := resp.Header.Get("Content-Type")
	if contentType != "application/dns-message" {
		return nil, fmt.Errorf("DoH 服务器返回了非预期的 Content-Type: %s", contentType)
	}

	// 6. 读取并解析响应体中的 DNS 消息
	responseWire, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取 HTTP 响应体失败: %w", err)
	}

	var responseMsg dnsmessage.Message
	err = responseMsg.Unpack(responseWire)
	if err != nil {
		return nil, fmt.Errorf("解析 DNS 响应失败: %w", err)
	}

	log.Printf("收到来自 %s 的响应\n", serverURL)
	return &responseMsg, nil
}

// --- 示例用法 ---
func main() {
	// 常用的公共 DoH 服务器 URL
	// Cloudflare: "https://cloudflare-dns.com/dns-query"
	// Google: "https://dns.google/dns-query"
	// Quad9: "https://dns.quad9.net/dns-query"
	dohServer := "https://cloudflare-dns.com/dns-query"
	domainToQuery := "www.example.com"

	// --- 查询 A 记录 ---
	fmt.Printf("\n--- 查询 A 记录 (%s) ---\n", domainToQuery)
	aResponse, err := queryDoH(dohServer, domainToQuery, dnsmessage.TypeA)
	if err != nil {
		log.Printf("查询 A 记录失败: %v\n", err)
	} else {
		fmt.Println("原始响应头:", aResponse.Header) // 打印响应头信息
		fmt.Println("解析结果 (Answer Section):")
		if len(aResponse.Answers) > 0 {
			for _, answer := range aResponse.Answers {
				// 根据记录类型处理不同的资源记录
				switch rr := answer.Body.(type) {
				case *dnsmessage.AResource:
					fmt.Printf("A记录: %v.%v.%v.%v\n", rr.A[0], rr.A[1], rr.A[2], rr.A[3])
				default:
					fmt.Printf("未知记录类型: %T\n", rr)
				}
			}
		} else {
			fmt.Println("未找到 A 记录。")
		}
	}

	// --- 查询 AAAA 记录 ---
	fmt.Printf("\n--- 查询 AAAA 记录 (%s) ---\n", domainToQuery)
	aaaaResponse, err := queryDoH(dohServer, domainToQuery, dnsmessage.TypeAAAA)
	if err != nil {
		log.Printf("查询 AAAA 记录失败: %v\n", err)
	} else {
		fmt.Println("解析结果 (Answer Section):")
		if len(aaaaResponse.Answers) > 0 {
			for _, answer := range aaaaResponse.Answers {
				switch rr := answer.Body.(type) {
				case *dnsmessage.AAAAResource:
					fmt.Printf("AAAA记录: %x:%x:%x:%x:%x:%x:%x:%x\n",
						rr.AAAA[0:2], rr.AAAA[2:4], rr.AAAA[4:6], rr.AAAA[6:8],
						rr.AAAA[8:10], rr.AAAA[10:12], rr.AAAA[12:14], rr.AAAA[14:16])
				default:
					fmt.Printf("未知记录类型: %T\n", rr)
				}
			}
		} else {
			fmt.Println("未找到 AAAA 记录。")
		}
	}

	// --- 查询 MX 记录 ---
	fmt.Printf("\n--- 查询 MX 记录 (google.com) ---\n")
	mxResponse, err := queryDoH(dohServer, "google.com", dnsmessage.TypeMX)
	if err != nil {
		log.Printf("查询 MX 记录失败: %v\n", err)
	} else {
		fmt.Println("解析结果 (Answer Section):")
		if len(mxResponse.Answers) > 0 {
			for _, answer := range mxResponse.Answers {
				switch rr := answer.Body.(type) {
				case *dnsmessage.MXResource:
					fmt.Printf("MX记录: 优先级=%d, 服务器=%s\n", rr.Pref, rr.MX.String())
				default:
					fmt.Printf("未知记录类型: %T\n", rr)
				}
			}
		} else {
			fmt.Println("未找到 MX 记录。")
		}
	}

	// --- 查询一个不存在的域名 ---
	fmt.Printf("\n--- 查询不存在的域名 (nonexistent-domain-askljhfdsa.com) ---\n")
	nxDomain := "nonexistent-domain-askljhfdsa.com"
	nxResponse, err := queryDoH(dohServer, nxDomain, dnsmessage.TypeA)
	if err != nil {
		log.Printf("查询 %s 失败: %v\n", nxDomain, err)
	} else {
		fmt.Println("原始响应头:", nxResponse.Header)
		fmt.Println("解析结果 (Answer Section):")
		if len(nxResponse.Answers) > 0 {
			for _, answer := range nxResponse.Answers {
				switch rr := answer.Body.(type) {
				case *dnsmessage.AResource:
					fmt.Printf("A记录: %v.%v.%v.%v\n", rr.A[0], rr.A[1], rr.A[2], rr.A[3])
				default:
					fmt.Printf("未知记录类型: %T\n", rr)
				}
			}
		} else {
			fmt.Printf("未找到记录。响应码 (RCode): %s (%d)\n", nxResponse.Header.RCode.String(), nxResponse.Header.RCode)
		}
	}
}
