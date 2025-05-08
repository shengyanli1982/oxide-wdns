// tests/server/ecs_tests.rs

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use trust_dns_proto::op::{Message, MessageType, OpCode, Header};
use trust_dns_proto::rr::{Name, RecordType, RData, Record, DNSClass};
use trust_dns_proto::rr::rdata::opt::{EdnsOption, OPT};

use oxide_wdns::server::config::{EcsPolicyConfig, EcsAnonymizationConfig};
use oxide_wdns::server::ecs::{EcsData, EcsProcessor, EcsAddressFamily};
use oxide_wdns::common::consts::{
    ECS_POLICY_STRIP, ECS_POLICY_FORWARD, ECS_POLICY_ANONYMIZE,
    EDNS_CLIENT_SUBNET_OPTION_CODE,
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
    let q = trust_dns_proto::op::Query::new()
        .set_name(name)
        .set_query_type(RecordType::A)
        .set_query_class(DNSClass::IN);
    query.add_query(q);
    
    // 创建 EDNS OPT 记录
    let mut opt = OPT::new();
    
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
    assert_eq!(extracted.address, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 123)));
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
    assert_eq!(
        anonymized.address, 
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0x85a3, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000))
    );
    
    // 匿名化为 /56
    let anonymized = ecs.anonymize(24, 56).unwrap();
    
    // 验证结果
    assert_eq!(anonymized.source_prefix_length, 56);
    assert_eq!(
        anonymized.address, 
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0x85a3, 0x0000, 0x0000, 0x8a00, 0x0000, 0x0000))
    );
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
    assert_eq!(extracted.address, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 123)));
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
    // 创建 ECS 数据，源前缀长度为 0（客户端不希望其子网信息被用于地理位置优化）
    let ecs = EcsData::new(
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 123)),
        0,  // 源前缀长度
        0   // 范围前缀长度
    );
    
    // 创建包含 ECS 的查询
    let query = create_query_with_ecs(&ecs);
    
    // 对每种策略进行测试，都应该尊重客户端隐私（剥离 ECS）
    
    // 测试转发策略
    let policy = EcsPolicyConfig {
        strategy: ECS_POLICY_FORWARD.to_string(),
        anonymization: EcsAnonymizationConfig::default(),
    };
    
    let processed = EcsProcessor::process_ecs_for_query(
        &query, 
        &policy, 
        None, 
        Some(&ecs)
    ).unwrap();
    assert!(processed.is_some());
    let processed = processed.unwrap();
    let extracted = EcsProcessor::extract_ecs_from_message(&processed);
    assert!(extracted.is_none()); // ECS 应该被剥离
    
    // 测试匿名化策略
    let policy = EcsPolicyConfig {
        strategy: ECS_POLICY_ANONYMIZE.to_string(),
        anonymization: EcsAnonymizationConfig::default(),
    };
    
    let processed = EcsProcessor::process_ecs_for_query(
        &query, 
        &policy, 
        None,
        Some(&ecs)
    ).unwrap();
    assert!(processed.is_some());
    let processed = processed.unwrap();
    let extracted = EcsProcessor::extract_ecs_from_message(&processed);
    assert!(extracted.is_none()); // ECS 应该被剥离
}

#[test]
fn test_create_ecs_from_client_ip() {
    // 创建不包含 ECS 的查询
    let mut query = Message::new();
    query.set_id(1234);
    query.set_message_type(MessageType::Query);
    query.set_op_code(OpCode::Query);
    query.set_recursion_desired(true);
    
    // 添加查询问题
    let name = Name::from_str("example.com.").unwrap();
    let q = trust_dns_proto::op::Query::new()
        .set_name(name)
        .set_query_type(RecordType::A)
        .set_query_class(DNSClass::IN);
    query.add_query(q);
    
    // 创建客户端 IP
    let client_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 123));
    
    // 创建转发策略
    let policy = EcsPolicyConfig {
        strategy: ECS_POLICY_FORWARD.to_string(),
        anonymization: EcsAnonymizationConfig {
            ipv4_prefix_length: 24,
            ipv6_prefix_length: 48,
        },
    };
    
    // 应用策略
    let processed = EcsProcessor::process_ecs_for_query(
        &query, 
        &policy, 
        Some(client_ip), 
        None
    ).unwrap();
    
    // 确认已处理
    assert!(processed.is_some());
    let processed = processed.unwrap();
    
    // 检查是否已添加 ECS
    let extracted = EcsProcessor::extract_ecs_from_message(&processed);
    assert!(extracted.is_some());
    let extracted = extracted.unwrap();
    
    // 验证添加的 ECS 数据
    assert_eq!(extracted.family, EcsAddressFamily::IPv4);
    assert_eq!(extracted.source_prefix_length, 24);
    assert_eq!(extracted.scope_prefix_length, 0);
    assert_eq!(extracted.address, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 123)));
    
    // 创建匿名化策略
    let policy = EcsPolicyConfig {
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
        Some(client_ip), 
        None
    ).unwrap();
    
    // 确认已处理
    assert!(processed.is_some());
    let processed = processed.unwrap();
    
    // 检查是否已添加匿名化的 ECS
    let extracted = EcsProcessor::extract_ecs_from_message(&processed);
    assert!(extracted.is_some());
    let extracted = extracted.unwrap();
    
    // 验证添加的匿名化 ECS 数据
    assert_eq!(extracted.family, EcsAddressFamily::IPv4);
    assert_eq!(extracted.source_prefix_length, 24);
    assert_eq!(extracted.scope_prefix_length, 0);
    assert_eq!(extracted.address, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)));
} 