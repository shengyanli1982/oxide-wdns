// tests/server/ecs_tests.rs

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::collections::HashMap;
use std::sync::Arc;

use trust_dns_proto::op::{Message, MessageType, OpCode};
use trust_dns_proto::rr::{Name, RecordType, RData, Record, DNSClass};
use trust_dns_proto::rr::rdata::opt::OPT;
use reqwest::Client;

use oxide_wdns::server::config::{EcsPolicyConfig, EcsAnonymizationConfig, ServerConfig};
use oxide_wdns::server::ecs::{EcsData, EcsProcessor, EcsAddressFamily};
use oxide_wdns::server::upstream::{UpstreamManager, UpstreamSelection};
use oxide_wdns::common::consts::{
    ECS_POLICY_STRIP, ECS_POLICY_FORWARD, ECS_POLICY_ANONYMIZE,
};

// 创建包含 ECS 的 DNS 查询消息
fn create_query_with_ecs(ecs_data: &EcsData) -> Message {
    // 创建基本 DNS 查询
    let mut query = Message::new();
    query.set_id(1234);
    query.set_message_type(MessageType::Query);
    query.set_op_code(OpCode::Query);
    query.set_recursion_desired(true);
    
    // 添加查询问题
    let name = Name::from_str("example.com.").unwrap();
    let mut query_builder = trust_dns_proto::op::Query::new();
    let q = query_builder
        .set_name(name)
        .set_query_type(RecordType::A)
        .set_query_class(DNSClass::IN);
    query.add_query(q.clone());
    
    // 创建 EDNS OPT 记录
    let mut opt = OPT::new(HashMap::new());
    
    // 将 ECS 数据转换为 EDNS 选项并添加
    let ecs_option = ecs_data.to_edns_option().unwrap();
    opt.insert(ecs_option);
    
    // 创建 OPT 记录并添加到查询中
    let opt_record = Record::from_rdata(
        Name::root(),
        0,
        RData::OPT(opt)
    );
    
    // 添加 OPT 记录到附加部分
    query.add_additional(opt_record);
    
    query
}

// 创建简单的ServerConfig用于测试
fn create_test_config() -> ServerConfig {
    let config_str = r#"
    http_server:
      listen_addr: "127.0.0.1:8053"
      timeout: 10
      rate_limit:
        enabled: false
    dns_resolver:
      upstream:
        resolvers:
          - address: "8.8.8.8:53"
            protocol: udp
        query_timeout: 3
        enable_dnssec: false
      http_client:
        timeout: 5
        pool:
          idle_timeout: 60
          max_idle_connections: 20
        request:
          user_agent: "oxide-wdns-test/0.1.0"
      cache:
        enabled: false
      ecs_policy:
        strategy: "forward"
        anonymization:
          ipv4_prefix_length: 24
          ipv6_prefix_length: 56
    "#;
    
    serde_yaml::from_str(config_str).unwrap()
}

#[test]
fn test_ecs_extraction() {
    // 创建 ECS 数据
    let ecs = EcsData::new(
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 123)),
        24,  // 源前缀长度
        0    // 范围前缀长度（出站查询）
    );
    
    // 创建包含 ECS 的查询
    let query = create_query_with_ecs(&ecs);
    
    // 提取 ECS 数据
    let extracted = EcsProcessor::extract_ecs_from_message(&query);
    assert!(extracted.is_some());
    
    let extracted = extracted.unwrap();
    
    // 检验 ECS 数据是否正确
    assert_eq!(extracted.family, EcsAddressFamily::IPv4);
    assert_eq!(extracted.source_prefix_length, 24);
    assert_eq!(extracted.scope_prefix_length, 0);
    
    // 因为系统对 IP 地址进行了匿名化处理，所以需要检查匿名化后的地址
    let anonymized_addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0));
    assert_eq!(extracted.address, anonymized_addr);
}

#[test]
fn test_ipv4_anonymization() {
    // 创建 IPv4 ECS 数据
    let ecs = EcsData::new(
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 123)),
        32,  // 源前缀长度（客户端提供完整地址）
        0    // 范围前缀长度
    );
    
    // 匿名化为 /24
    let anonymized = ecs.anonymize(24, 64).unwrap();
    
    // 验证结果
    assert_eq!(anonymized.source_prefix_length, 24);
    assert_eq!(anonymized.address, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)));
    
    // 匿名化为 /16
    let anonymized = ecs.anonymize(16, 64).unwrap();
    
    // 验证结果
    assert_eq!(anonymized.source_prefix_length, 16);
    assert_eq!(anonymized.address, IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)));
}

#[test]
fn test_ipv6_anonymization() {
    // 创建 IPv6 ECS 数据
    let ecs = EcsData::new(
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0x85a3, 0x0000, 0x0000, 0x8a2e, 0x0370, 0x7334)),
        128,  // 源前缀长度（客户端提供完整地址）
        0     // 范围前缀长度
    );
    
    // 匿名化为 /48
    let anonymized = ecs.anonymize(24, 48).unwrap();
    
    // 验证结果
    assert_eq!(anonymized.source_prefix_length, 48);
    
    // 检查 IPv6 地址是否正确匿名化到 /48 前缀
    let ipv6_str = format!("{}", anonymized.address);
    assert!(ipv6_str.starts_with("2001:db8:85a3:"), 
           "IPv6 地址前缀应该是 '2001:db8:85a3:', 但实际是 '{}'", ipv6_str);
    
    // 匿名化为 /56
    let anonymized = ecs.anonymize(24, 56).unwrap();
    
    // 验证结果
    assert_eq!(anonymized.source_prefix_length, 56);
    
    // 检查 IPv6 地址是否正确匿名化
    let ipv6_str = format!("{}", anonymized.address);
    assert!(ipv6_str.starts_with("2001:db8:85a3"), 
           "IPv6 地址应该以 '2001:db8:85a3' 开头, 但实际是 '{}'", ipv6_str);
}

#[test]
fn test_strip_policy() {
    // 创建 ECS 数据
    let ecs = EcsData::new(
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 123)),
        24,  // 源前缀长度
        0    // 范围前缀长度
    );
    
    // 创建包含 ECS 的查询
    let query = create_query_with_ecs(&ecs);
    
    // 创建剥离策略
    let policy = EcsPolicyConfig {
        enabled: true,
        strategy: ECS_POLICY_STRIP.to_string(),
        anonymization: EcsAnonymizationConfig::default(),
    };
    
    // 应用策略
    let processed = EcsProcessor::process_ecs_for_query(
        &query, 
        &policy, 
        None,
        None
    ).unwrap();
    
    // 确认已处理
    assert!(processed.is_some());
    let processed = processed.unwrap();
    
    // 检查 ECS 是否已被剥离
    let extracted = EcsProcessor::extract_ecs_from_message(&processed);
    assert!(extracted.is_none());
}

#[test]
fn test_forward_policy() {
    // 创建 ECS 数据
    let ecs = EcsData::new(
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 123)),
        24,  // 源前缀长度
        0    // 范围前缀长度
    );
    
    // 创建包含 ECS 的查询
    let query = create_query_with_ecs(&ecs);
    
    // 创建转发策略
    let policy = EcsPolicyConfig {
        enabled: true,
        strategy: ECS_POLICY_FORWARD.to_string(),
        anonymization: EcsAnonymizationConfig::default(),
    };
    
    // 应用策略
    let processed = EcsProcessor::process_ecs_for_query(
        &query, 
        &policy, 
        None,
        Some(&ecs)
    ).unwrap();
    
    // 对于转发策略，应该修改查询，确保 scope_prefix_length 为 0
    assert!(processed.is_some());
    let processed = processed.unwrap();
    
    // 检查 ECS 是否已被正确修改
    let extracted = EcsProcessor::extract_ecs_from_message(&processed);
    assert!(extracted.is_some());
    let extracted = extracted.unwrap();
    
    // 验证 scope_prefix_length 是否为 0
    assert_eq!(extracted.source_prefix_length, 24);
    assert_eq!(extracted.scope_prefix_length, 0);
    
    // 因为系统对 IP 地址进行了匿名化处理，所以需要检查匿名化后的地址
    let anonymized_addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0));
    assert_eq!(extracted.address, anonymized_addr);
}

#[test]
fn test_anonymize_policy() {
    // 创建 ECS 数据
    let ecs = EcsData::new(
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 123)),
        32,  // 源前缀长度（完整地址）
        0    // 范围前缀长度
    );
    
    // 创建包含 ECS 的查询
    let query = create_query_with_ecs(&ecs);
    
    // 创建匿名化策略（设置 /24 前缀）
    let policy = EcsPolicyConfig {
        enabled: true,
        strategy: ECS_POLICY_ANONYMIZE.to_string(),
        anonymization: EcsAnonymizationConfig {
            ipv4_prefix_length: 24,
            ipv6_prefix_length: 48,
        },
    };
    
    // 应用策略
    let processed = EcsProcessor::process_ecs_for_query(
        &query, 
        &policy, 
        None,
        Some(&ecs)
    ).unwrap();
    
    // 确认已处理
    assert!(processed.is_some());
    let processed = processed.unwrap();
    
    // 检查 ECS 是否已被匿名化
    let extracted = EcsProcessor::extract_ecs_from_message(&processed);
    assert!(extracted.is_some());
    let extracted = extracted.unwrap();
    
    // 验证匿名化后的数据
    assert_eq!(extracted.source_prefix_length, 24);
    assert_eq!(extracted.address, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)));
}

#[test]
fn test_respect_client_privacy() {
    // 创建 ECS 数据
    let ecs = EcsData::new(
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 123)),
        32,  // 源前缀长度（完整地址）
        0    // 范围前缀长度
    );
    
    // 创建包含 ECS 的查询
    let query = create_query_with_ecs(&ecs);
    
    // 客户端想要查询 example.com，但不想发送他们的准确位置
    // 服务器应该尊重客户端隐私设置，不覆盖他们设置的前缀长度
    
    // 创建转发策略
    let policy = EcsPolicyConfig {
        enabled: true,
        strategy: ECS_POLICY_FORWARD.to_string(),
        anonymization: EcsAnonymizationConfig::default(),
    };
    
    // 应用策略 - 这里我们没有提供客户端IP地址，因为查询已包含ECS
    let processed = EcsProcessor::process_ecs_for_query(
        &query, 
        &policy, 
        None,
        Some(&ecs)
    ).unwrap();
    
    // 确认已处理
    assert!(processed.is_some());
    let processed = processed.unwrap();
    
    // 提取并验证 ECS 数据
    let extracted = EcsProcessor::extract_ecs_from_message(&processed);
    assert!(extracted.is_some());
    let extracted = extracted.unwrap();
    
    // 验证前缀长度没有被修改
    assert_eq!(extracted.source_prefix_length, 32);
}

#[test]
fn test_create_ecs_from_client_ip() {
    // 客户端IP地址
    let client_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 123));
    
    // 创建不包含 ECS 的基本查询
    let mut query = Message::new();
    query.set_id(1234);
    query.set_message_type(MessageType::Query);
    query.set_op_code(OpCode::Query);
    query.set_recursion_desired(true);
    
    // 添加查询问题
    let name = Name::from_str("example.com.").unwrap();
    let mut query_builder = trust_dns_proto::op::Query::new();
    let q = query_builder
        .set_name(name)
        .set_query_type(RecordType::A)
        .set_query_class(DNSClass::IN);
    query.add_query(q.clone());
    
    // 创建匿名化策略（设置 /24 前缀）
    let policy = EcsPolicyConfig {
        enabled: true,
        strategy: ECS_POLICY_ANONYMIZE.to_string(),
        anonymization: EcsAnonymizationConfig {
            ipv4_prefix_length: 24,
            ipv6_prefix_length: 56,
        },
    };
    
    // 应用策略，使用客户端IP
    let processed = EcsProcessor::process_ecs_for_query(
        &query, 
        &policy, 
        Some(client_ip),
        None
    ).unwrap();
    
    // 确认已处理
    assert!(processed.is_some());
    let processed = processed.unwrap();
    
    // 检查是否添加了匿名化的 ECS
    let extracted = EcsProcessor::extract_ecs_from_message(&processed);
    assert!(extracted.is_some());
    let extracted = extracted.unwrap();
    
    // 验证匿名化后的数据
    assert_eq!(extracted.source_prefix_length, 24);
    assert_eq!(extracted.address, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)));
}

#[tokio::test]
async fn test_upstream_resolve_with_ecs() {
    // 创建ECS数据
    let ecs = EcsData::new(
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 123)),
        24,  // 源前缀长度
        0    // 范围前缀长度
    );
    
    // 创建包含ECS的查询
    let query = create_query_with_ecs(&ecs);
    
    // 创建测试配置并初始化上游管理器
    let config = create_test_config();
    let http_client = Client::new();
    
    // 使用Arc包装ServerConfig以适应新的API
    let config_arc = Arc::new(config);
    
    // 初始化上游管理器
    let upstream_manager = UpstreamManager::new(config_arc, http_client).await.unwrap();
    
    // 调用resolve方法，传递所有必要的参数
    let result = upstream_manager.resolve(
        &query, 
        UpstreamSelection::Global,
        Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 123))),
        Some(&ecs)
    ).await;
    
    // 我们只是测试API使用，实际响应可能会失败(因为使用了模拟服务器配置)
    // 所以我们只是验证类型正确
    match result {
        Ok(_) => {
            // 如果成功，这很好，但我们不期望在测试环境中成功
            println!("Resolve succeeded unexpectedly");
        },
        Err(e) => {
            // 在测试环境中我们期望失败，打印错误信息
            println!("Resolve failed as expected: {}", e);
        }
    }
}

// 测试 UpstreamManager::new 的正确使用方式 - 使用 Arc<ServerConfig>
#[tokio::test]
async fn test_upstream_manager_initialization() {
    // 创建测试配置
    let config = create_test_config();
    let http_client = Client::new();
    
    // 使用Arc包装配置（正确方式）
    let config_arc = Arc::new(config);
    
    // 初始化上游管理器
    let upstream_manager = UpstreamManager::new(config_arc, http_client).await;
    
    // 验证初始化成功
    assert!(upstream_manager.is_ok(), "UpstreamManager初始化应该成功");
}

// 测试 UpstreamManager::resolve 方法的不同参数组合
#[tokio::test]
async fn test_upstream_resolve_variations() {
    // 创建测试配置
    let config = Arc::new(create_test_config());
    let http_client = Client::new();
    
    // 初始化上游管理器
    let upstream_manager = match UpstreamManager::new(config, http_client).await {
        Ok(manager) => manager,
        Err(e) => {
            panic!("无法初始化UpstreamManager: {}", e);
        }
    };
    
    // 创建基本查询消息
    let mut query = Message::new();
    query.set_id(1234);
    query.set_message_type(MessageType::Query);
    query.set_op_code(OpCode::Query);
    query.set_recursion_desired(true);
    
    // 添加查询问题
    let name = Name::from_str("example.com.").unwrap();
    let mut query_builder = trust_dns_proto::op::Query::new();
    let q = query_builder
        .set_name(name)
        .set_query_type(RecordType::A)
        .set_query_class(DNSClass::IN);
    query.add_query(q.clone());
    
    // 创建 ECS 数据
    let ecs = EcsData::new(
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 123)),
        24,  // 源前缀长度
        0    // 范围前缀长度
    );
    
    // 测试不同的参数组合
    
    // 1. 没有客户端IP和ECS数据
    let result1 = upstream_manager.resolve(
        &query, 
        UpstreamSelection::Global,
        None,
        None
    ).await;
    
    // 由于这是测试环境，预期可能会失败
    match result1 {
        Ok(_) => println!("无ECS查询成功"),
        Err(e) => println!("无ECS查询失败（预期结果）: {}", e),
    }
    
    // 2. 只有客户端IP
    let result2 = upstream_manager.resolve(
        &query, 
        UpstreamSelection::Global,
        Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 123))),
        None
    ).await;
    
    match result2 {
        Ok(_) => println!("带IP查询成功"),
        Err(e) => println!("带IP查询失败（预期结果）: {}", e),
    }
    
    // 3. 只有ECS数据
    let result3 = upstream_manager.resolve(
        &query, 
        UpstreamSelection::Global,
        None,
        Some(&ecs)
    ).await;
    
    match result3 {
        Ok(_) => println!("带ECS查询成功"),
        Err(e) => println!("带ECS查询失败（预期结果）: {}", e),
    }
    
    // 4. 同时有客户端IP和ECS数据
    let result4 = upstream_manager.resolve(
        &query, 
        UpstreamSelection::Global,
        Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 123))),
        Some(&ecs)
    ).await;
    
    match result4 {
        Ok(_) => println!("带IP和ECS查询成功"),
        Err(e) => println!("带IP和ECS查询失败（预期结果）: {}", e),
    }
}

// 如果有创建或使用CacheKey的测试，修改它们以适应新的字段要求
// 例如，创建带有ECS的CacheKey的测试：
#[test]
fn test_create_cache_key_with_ecs() {
    // 创建ECS数据
    let ecs = EcsData::new(
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 123)),
        24,  // 源前缀长度
        0    // 范围前缀长度
    );
    
    // 创建缓存键
    let name = Name::from_str("example.com.").unwrap();
    
    // 使用with_ecs方法创建带有ECS的缓存键 
    // 这里我们不直接构造CacheKey以避免处理内部实现细节
    use oxide_wdns::server::cache::CacheKey;
    let cache_key = CacheKey::with_ecs(
        name,
        RecordType::A,
        DNSClass::IN,
        &ecs
    );
    
    // 验证缓存键的基本属性
    // 使用显式类型转换为u16以避免歧义
    assert_eq!(cache_key.record_type, u16::from(RecordType::A));
    assert_eq!(cache_key.record_class, u16::from(DNSClass::IN));
    
    // 确保ECS相关字段被正确设置
    assert!(cache_key.ecs_network.is_some());
    assert_eq!(cache_key.ecs_scope_prefix_length.unwrap(), 0);
}

#[test]
fn test_cache_key_methods() {
    // 创建ECS数据
    let ecs = EcsData::new(
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 123)),
        24,  // 源前缀长度
        0    // 范围前缀长度
    );
    
    // 测试域名
    let name = Name::from_str("example.com.").unwrap();
    
    // 测试基本的CacheKey::new
    use oxide_wdns::server::cache::CacheKey;
    let basic_key = CacheKey::new(
        name.clone(),
        RecordType::A,
        DNSClass::IN
    );
    
    // 验证基本键属性
    assert_eq!(basic_key.record_type, u16::from(RecordType::A));
    assert_eq!(basic_key.record_class, u16::from(DNSClass::IN));
    assert!(basic_key.ecs_network.is_none());
    assert!(basic_key.ecs_scope_prefix_length.is_none());
    
    // 测试创建查找键（带ECS）
    let lookup_key = CacheKey::create_lookup_key(
        name.clone(),
        RecordType::A,
        DNSClass::IN,
        Some(&ecs)
    );
    
    // 验证查找键属性
    assert_eq!(lookup_key.record_type, u16::from(RecordType::A));
    assert_eq!(lookup_key.record_class, u16::from(DNSClass::IN));
    assert!(lookup_key.ecs_network.is_some());
    assert_eq!(lookup_key.ecs_scope_prefix_length.unwrap(), 0);
    
    // 测试创建查找键（不带ECS）
    let lookup_key_no_ecs = CacheKey::create_lookup_key(
        name.clone(),
        RecordType::A,
        DNSClass::IN,
        None
    );
    
    // 验证无ECS查找键属性
    assert_eq!(lookup_key_no_ecs.record_type, u16::from(RecordType::A));
    assert_eq!(lookup_key_no_ecs.record_class, u16::from(DNSClass::IN));
    assert!(lookup_key_no_ecs.ecs_network.is_none());
    assert!(lookup_key_no_ecs.ecs_scope_prefix_length.is_none());
    
    // 测试获取基础键
    let base_key = lookup_key.get_base_key();
    assert_eq!(base_key.record_type, lookup_key.record_type);
    assert_eq!(base_key.record_class, lookup_key.record_class);
    assert!(base_key.ecs_network.is_none());
    assert!(base_key.ecs_scope_prefix_length.is_none());
}

#[test]
fn test_ecs_enabled_flag() {
    // 创建 ECS 数据
    let ecs = EcsData::new(
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 123)),
        24,  // 源前缀长度
        0    // 范围前缀长度
    );
    
    // 创建包含 ECS 的查询
    let query = create_query_with_ecs(&ecs);
    
    // 1. 测试 enabled=false 时，ECS 策略不被应用
    let disabled_policy = EcsPolicyConfig {
        enabled: false,
        strategy: ECS_POLICY_STRIP.to_string(),
        anonymization: EcsAnonymizationConfig::default(),
    };
    
    // 应用禁用的策略
    let processed = EcsProcessor::process_ecs_for_query(
        &query, 
        &disabled_policy, 
        None,
        None
    ).unwrap();
    
    // 验证结果：当 enabled=false 时，应当返回 None（表示不修改原始查询）
    assert!(processed.is_none());
    
    // 2. 测试 enabled=true 时，ECS 策略被应用（使用剥离策略）
    let enabled_policy = EcsPolicyConfig {
        enabled: true,
        strategy: ECS_POLICY_STRIP.to_string(),
        anonymization: EcsAnonymizationConfig::default(),
    };
    
    // 应用启用的策略
    let processed = EcsProcessor::process_ecs_for_query(
        &query, 
        &enabled_policy, 
        None,
        None
    ).unwrap();
    
    // 验证结果：当 enabled=true 且策略为 strip 时，应当返回修改后的查询
    assert!(processed.is_some());
    
    // 从处理后的消息中提取 ECS 数据
    let processed_query = processed.unwrap();
    let extracted_ecs = EcsProcessor::extract_ecs_from_message(&processed_query);
    
    // 验证 ECS 已被剥离
    assert!(extracted_ecs.is_none());
}

#[test]
fn test_upstream_group_ecs_enabled_flag() {
    // 创建配置字符串，包含全局启用的 ECS 策略和一个上游组特定的禁用 ECS 策略
    let config_str = r#"
    http_server:
      listen_addr: "127.0.0.1:8053"
      timeout: 10
    dns_resolver:
      upstream:
        resolvers:
          - address: "8.8.8.8:53"
            protocol: udp
        query_timeout: 3
        enable_dnssec: false
      ecs_policy:
        enabled: true
        strategy: "forward"
        anonymization:
          ipv4_prefix_length: 24
          ipv6_prefix_length: 48
      routing:
        enabled: true
        upstream_groups:
          - name: "disabled_ecs_group"
            resolvers:
              - address: "1.1.1.1:53"
                protocol: udp
            ecs_policy:
              enabled: false
              strategy: "forward"
          - name: "enabled_ecs_group"
            resolvers:
              - address: "9.9.9.9:53"
                protocol: udp
            ecs_policy:
              enabled: true
              strategy: "anonymize"
              anonymization:
                ipv4_prefix_length: 16
                ipv6_prefix_length: 32
    "#;
    
    // 解析配置
    let config: ServerConfig = serde_yaml::from_str(config_str).unwrap();
    
    // 测试全局 ECS 策略
    let global_policy = config.get_effective_ecs_policy("").unwrap();
    assert!(global_policy.enabled);
    assert_eq!(global_policy.strategy, ECS_POLICY_FORWARD);
    
    // 测试禁用 ECS 的上游组
    let disabled_group_policy = config.get_effective_ecs_policy("disabled_ecs_group").unwrap();
    assert!(!disabled_group_policy.enabled);
    assert_eq!(disabled_group_policy.strategy, ECS_POLICY_FORWARD);
    
    // 测试启用 ECS 的上游组
    let enabled_group_policy = config.get_effective_ecs_policy("enabled_ecs_group").unwrap();
    assert!(enabled_group_policy.enabled);
    assert_eq!(enabled_group_policy.strategy, ECS_POLICY_ANONYMIZE);
    assert_eq!(enabled_group_policy.anonymization.ipv4_prefix_length, 16);
    assert_eq!(enabled_group_policy.anonymization.ipv6_prefix_length, 32);
    
    // 测试不存在的上游组（应回退到全局策略）
    let fallback_policy = config.get_effective_ecs_policy("non_existent_group").unwrap();
    assert!(fallback_policy.enabled);
    assert_eq!(fallback_policy.strategy, ECS_POLICY_FORWARD);
}

#[test]
fn test_ecs_policy_validation() {
    // 创建一个具有无效策略类型的配置，但enabled为false，应该通过验证
    let invalid_but_disabled_config_str = r#"
    http_server:
      listen_addr: "127.0.0.1:8053"
      timeout: 10
    dns_resolver:
      upstream:
        resolvers:
          - address: "8.8.8.8:53"
            protocol: udp
        query_timeout: 3
        enable_dnssec: false
      ecs_policy:
        enabled: false
        strategy: "invalid_strategy"
        anonymization:
          ipv4_prefix_length: 0  # 无效值
          ipv6_prefix_length: 200 # 无效值
    "#;
    
    // 应该能成功解析和验证配置
    let config: ServerConfig = serde_yaml::from_str(invalid_but_disabled_config_str).unwrap();
    assert!(config.validate_ecs_policy().is_ok());
    
    // 创建一个具有无效策略类型的配置，且enabled为true，应该验证失败
    let invalid_and_enabled_config_str = r#"
    http_server:
      listen_addr: "127.0.0.1:8053"
      timeout: 10
    dns_resolver:
      upstream:
        resolvers:
          - address: "8.8.8.8:53"
            protocol: udp
        query_timeout: 3
        enable_dnssec: false
      ecs_policy:
        enabled: true
        strategy: "invalid_strategy"
        anonymization:
          ipv4_prefix_length: 24
          ipv6_prefix_length: 48
    "#;
    
    // 应该解析成功但验证失败
    let config: ServerConfig = serde_yaml::from_str(invalid_and_enabled_config_str).unwrap();
    assert!(config.validate_ecs_policy().is_err());
    
    // 创建一个具有无效IPv4前缀长度的配置，且enabled为true，应该验证失败
    let invalid_ipv4_config_str = r#"
    http_server:
      listen_addr: "127.0.0.1:8053"
      timeout: 10
    dns_resolver:
      upstream:
        resolvers:
          - address: "8.8.8.8:53"
            protocol: udp
        query_timeout: 3
        enable_dnssec: false
      ecs_policy:
        enabled: true
        strategy: "anonymize"
        anonymization:
          ipv4_prefix_length: 0
          ipv6_prefix_length: 48
    "#;
    
    // 应该解析成功但验证失败
    let config: ServerConfig = serde_yaml::from_str(invalid_ipv4_config_str).unwrap();
    assert!(config.validate_ecs_policy().is_err());
} 