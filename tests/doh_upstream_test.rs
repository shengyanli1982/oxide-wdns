use std::net::SocketAddr;
use tokio::test;
use trust_dns_proto::op::{Message, MessageType, OpCode};
use trust_dns_proto::rr::{Name, RecordType};

use oxide_wdns::server::config::{ServerConfig, UpstreamConfig, ResolverConfig, ResolverProtocol};
use oxide_wdns::server::upstream::UpstreamManager;

// 创建测试DNS查询
fn create_test_query(domain: &str, query_type: RecordType) -> Message {
    let name = Name::parse(domain, None).unwrap();
    
    let mut message = Message::new();
    message
        .set_id(1234) // 测试固定ID
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(true);
        
    // 添加查询
    let query = trust_dns_proto::op::Query::query(name, query_type);
    message.add_query(query);
    
    message
}

#[test]
async fn test_doh_upstream_resolver() {
    // 将此测试标记为跳过，除非显式启用
    if std::env::var("RUN_DOH_TEST").is_err() {
        println!("Skipping DoH upstream test. Set RUN_DOH_TEST=1 to enable.");
        return;
    }

    // 创建测试配置
    let config = ServerConfig {
        listen_addr: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
        listen_timeout: 120, // 添加服务器连接超时
        upstream: UpstreamConfig {
            resolvers: vec![
                // Cloudflare DoH服务器
                ResolverConfig {
                    address: "https://cloudflare-dns.com/dns-query".to_string(),
                    protocol: ResolverProtocol::Doh,
                },
                // Google DoH服务器作为备份
                ResolverConfig {
                    address: "https://dns.google/dns-query".to_string(),
                    protocol: ResolverProtocol::Doh,
                },
                // 标准UDP解析器作为后备
                ResolverConfig {
                    address: "8.8.8.8:53".to_string(),
                    protocol: ResolverProtocol::Udp,
                },
            ],
            enable_dnssec: true,
            query_timeout: 5,
        },
        cache: Default::default(),
        rate_limit: Default::default(),
        http_client: Default::default(), // 添加HTTP客户端配置
    };
    
    // 创建上游管理器
    let upstream = UpstreamManager::new(&config).await.expect("Failed to create upstream manager");
    
    // 创建测试查询
    let query = create_test_query("example.com", RecordType::A);
    
    // 执行查询
    let response = upstream.resolve(&query).await.expect("DoH query failed");
    
    // 验证响应
    assert_eq!(response.message_type(), MessageType::Response);
    assert_eq!(response.id(), query.id()); // ID应匹配查询
    assert!(!response.answers().is_empty(), "No answers returned");
    
    // 尝试查询AAAA记录
    let query = create_test_query("example.com", RecordType::AAAA);
    let response = upstream.resolve(&query).await.expect("DoH AAAA query failed");
    
    // 最低限度的验证 - 确保我们得到了响应
    assert_eq!(response.message_type(), MessageType::Response);
    
    println!("DoH upstream test passed successfully!");
} 