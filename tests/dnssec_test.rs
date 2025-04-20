// tests/dnssec_test.rs

use std::net::SocketAddr;
use trust_dns_proto::op::{Message, MessageType, OpCode, Query};
use trust_dns_proto::rr::{Name, RecordType};

use oxide_wdns::server::config::{
    ServerConfig, HttpServerConfig, DnsResolverConfig, UpstreamConfig, 
    ResolverConfig, ResolverProtocol, HttpClientConfig
};
use oxide_wdns::server::upstream::UpstreamManager;

// 创建测试查询消息
fn create_test_query(name: &str, record_type: RecordType, enable_cd: bool) -> Message {
    let name = Name::from_ascii(name).unwrap();
    let mut query = Message::new();
    query
        .set_id(1234)
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(true)
        .set_checking_disabled(enable_cd);
        
    let query_record = Query::query(name, record_type);
    
    query.add_query(query_record);
    query
}

// 测试辅助函数：创建基本的服务器配置
fn create_server_config(enable_dnssec: bool) -> ServerConfig {
    let upstream_config = UpstreamConfig {
        resolvers: vec![
            // 使用 Cloudflare 的公共 DNS，它支持 DNSSEC
            ResolverConfig {
                address: "1.1.1.1:53".to_string(),
                protocol: ResolverProtocol::Udp,
            },
            // 备用解析器
            ResolverConfig {
                address: "8.8.8.8:53".to_string(),
                protocol: ResolverProtocol::Udp,
            },
        ],
        enable_dnssec, // 可控制是否启用 DNSSEC
        query_timeout: 5,
    };
    
    ServerConfig {
        http: HttpServerConfig {
            listen_addr: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            timeout: 30,
            rate_limit: Default::default(),
        },
        dns: DnsResolverConfig {
            upstream: upstream_config,
            http_client: HttpClientConfig::default(),
            cache: Default::default(),
        },
    }
}

#[tokio::test]
async fn test_dnssec_ad_flag_disabled() {
    // 跳过真实网络测试，除非显式启用
    if std::env::var("RUN_DNSSEC_TEST").is_err() {
        println!("Skipping DNSSEC test. Set RUN_DNSSEC_TEST=1 to enable.");
        return;
    }
    
    // 创建配置，禁用 DNSSEC
    let config = create_server_config(false);
    
    // 创建上游管理器
    let upstream = UpstreamManager::new(&config).await.expect("Failed to create upstream manager");
    
    // 创建测试查询 - 使用已知支持DNSSEC的域名
    let query = create_test_query("iana.org", RecordType::A, false);
    
    // 执行查询
    let response = upstream.resolve(&query).await.expect("DNS query failed");
    
    // 验证结果：禁用 DNSSEC 时，AD 标志应为 false
    assert!(!response.authentic_data(), "AD flag should be false when DNSSEC is disabled");
    assert!(response.recursion_available(), "RA flag should be true");
    assert!(!response.checking_disabled(), "CD flag should be false");
}

#[tokio::test]
async fn test_dnssec_ad_flag_enabled() {
    // 跳过真实网络测试，除非显式启用
    if std::env::var("RUN_DNSSEC_TEST").is_err() {
        println!("Skipping DNSSEC test. Set RUN_DNSSEC_TEST=1 to enable.");
        return;
    }
    
    // 创建配置，启用 DNSSEC
    let config = create_server_config(true);
    
    // 创建上游管理器
    let upstream = UpstreamManager::new(&config).await.expect("Failed to create upstream manager");
    
    // 创建测试查询 - 使用已知支持DNSSEC的域名
    let query = create_test_query("iana.org", RecordType::A, false);
    
    // 执行查询
    let response = upstream.resolve(&query).await.expect("DNS query failed");
    
    // 验证结果：启用 DNSSEC 时，对于有记录的响应，AD 标志应为 true
    assert!(response.authentic_data(), "AD flag should be true when DNSSEC is enabled");
    assert!(response.recursion_available(), "RA flag should be true");
    assert!(!response.checking_disabled(), "CD flag should be false");
}

#[tokio::test]
async fn test_dnssec_with_cd_flag() {
    // 跳过真实网络测试，除非显式启用
    if std::env::var("RUN_DNSSEC_TEST").is_err() {
        println!("Skipping DNSSEC test. Set RUN_DNSSEC_TEST=1 to enable.");
        return;
    }
    
    // 创建配置，启用 DNSSEC
    let config = create_server_config(true);
    
    // 创建上游管理器
    let upstream = UpstreamManager::new(&config).await.expect("Failed to create upstream manager");
    
    // 创建测试查询，启用 CD 标志 - 使用已知支持DNSSEC的域名
    let query = create_test_query("iana.org", RecordType::A, true);
    
    // 执行查询
    let response = upstream.resolve(&query).await.expect("DNS query failed");
    
    // 验证结果：当 CD 标志设置时，AD 标志应为 false，即使 DNSSEC 启用
    assert!(!response.authentic_data(), "AD flag should be false when CD flag is enabled");
    assert!(response.recursion_available(), "RA flag should be true");
    assert!(response.checking_disabled(), "CD flag should be true");
}

#[tokio::test]
async fn test_dnssec_known_secure_domain() {
    // 跳过真实网络测试，除非显式启用
    if std::env::var("RUN_DNSSEC_TEST").is_err() {
        println!("Skipping DNSSEC test. Set RUN_DNSSEC_TEST=1 to enable.");
        return;
    }

    // 创建配置，启用 DNSSEC
    let config = create_server_config(true);

    // 创建上游管理器
    let upstream = UpstreamManager::new(&config).await.expect("Failed to create upstream manager");

    // 创建测试查询 - 使用已知支持DNSSEC的域名 cloudflare.com
    let query = create_test_query("cloudflare.com", RecordType::A, false);

    // 执行查询
    let response = upstream.resolve(&query).await.expect("DNS query failed");

    // 验证结果：
    // 1. AD 标志应为 true，因为域名安全且我们启用了验证
    // 2. RA 标志通常应为 true
    // 3. CD 标志应为 false，因为我们在查询中未设置它
    assert!(response.authentic_data(), "AD flag should be true for a known secure domain with DNSSEC enabled");
    assert!(response.recursion_available(), "RA flag should be true");
    assert!(!response.checking_disabled(), "CD flag should be false");
} 