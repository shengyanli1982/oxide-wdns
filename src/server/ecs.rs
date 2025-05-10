use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use trust_dns_proto::op::{Message, MessageType};
use trust_dns_proto::rr::{RData, Record, RecordType};
use trust_dns_proto::rr::rdata::opt::{EdnsCode, EdnsOption, OPT};
use tracing::{warn};
use crate::common::consts::{
    ECS_POLICY_STRIP, ECS_POLICY_FORWARD, ECS_POLICY_ANONYMIZE,
    EDNS_CLIENT_SUBNET_OPTION_CODE,
};
use crate::server::config::EcsPolicyConfig;
use crate::server::error::{Result, ServerError};
use crate::server::metrics::METRICS;
use std::collections::HashMap;

// EDNS 客户端子网地址协议族，遵循 RFC 7871
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcsAddressFamily {
    // IPv4 协议族 (值为 1)
    IPv4 = 1,
    // IPv6 协议族 (值为 2)
    IPv6 = 2,
}

impl From<IpAddr> for EcsAddressFamily {
    fn from(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(_) => EcsAddressFamily::IPv4,
            IpAddr::V6(_) => EcsAddressFamily::IPv6,
        }
    }
}

// EDNS 客户端子网信息
#[derive(Debug, Clone)]
pub struct EcsData {
    // 地址族 (IPv4/IPv6)
    pub family: EcsAddressFamily,
    // 源前缀长度 (客户端 IP 的有效位数)
    pub source_prefix_length: u8,
    // 范围前缀长度 (服务器认为对响应有效的前缀位数)
    pub scope_prefix_length: u8,
    // IP 地址 (仅包含前 source_prefix_length 位有效)
    pub address: IpAddr,
}

impl EcsData {
    // 创建新的 ECS 数据
    pub fn new(address: IpAddr, source_prefix_length: u8, scope_prefix_length: u8) -> Self {
        Self {
            family: EcsAddressFamily::from(address),
            source_prefix_length,
            scope_prefix_length,
            address,
        }
    }
    
    // 匿名化 ECS 数据
    pub fn anonymize(&self, ipv4_prefix_length: u8, ipv6_prefix_length: u8) -> Result<Self> {
        // 基于地址类型选择合适的前缀长度，并进行匿名化
        match self.address {
            // 处理 IPv4 地址
            IpAddr::V4(ipv4) => {
                // 选择较小的前缀长度作为新的源前缀长度
                let new_prefix = u8::min(self.source_prefix_length, ipv4_prefix_length);
                if new_prefix == 0 {
                    return Err(ServerError::Upstream("Invalid IPv4 prefix length: 0".to_string()));
                }
                
                // 匿名化 IPv4 地址，将主机部分置零
                let anonymized = anonymize_ipv4(ipv4, new_prefix);
                
                // 创建匿名化后的 ECS 数据，scope_prefix_length 设为 0
                Ok(Self {
                    family: EcsAddressFamily::IPv4,
                    source_prefix_length: new_prefix,
                    scope_prefix_length: 0,  // 出站查询时 scope 必须为 0
                    address: IpAddr::V4(anonymized),
                })
            },
            // 处理 IPv6 地址
            IpAddr::V6(ipv6) => {
                // 选择较小的前缀长度作为新的源前缀长度
                let new_prefix = u8::min(self.source_prefix_length, ipv6_prefix_length);
                if new_prefix == 0 {
                    return Err(ServerError::Upstream("Invalid IPv6 prefix length: 0".to_string()));
                }
                
                // 匿名化 IPv6 地址，将主机部分置零
                let anonymized = anonymize_ipv6(ipv6, new_prefix);
                
                // 创建匿名化后的 ECS 数据，scope_prefix_length 设为 0
                Ok(Self {
                    family: EcsAddressFamily::IPv6,
                    source_prefix_length: new_prefix,
                    scope_prefix_length: 0,  // 出站查询时 scope 必须为 0
                    address: IpAddr::V6(anonymized),
                })
            }
        }
    }
    
    // 将 ECS 数据转换为 EDNS Option
    pub fn to_edns_option(&self) -> Result<EdnsOption> {
        // 构建 EDNS 客户端子网选项
        // 格式: FAMILY(2) + SOURCE PREFIX-LENGTH(1) + SCOPE PREFIX-LENGTH(1) + ADDRESS(变长)
        
        // 预先计算需要的字节数
        let address_bytes_needed = match self.address {
            IpAddr::V4(_) => (self.source_prefix_length as usize + 7) / 8,
            IpAddr::V6(_) => (self.source_prefix_length as usize + 7) / 8,
        };
        
        // 预分配合适的容量: 4字节固定头 + 地址字节
        let mut wire_format = Vec::with_capacity(4 + address_bytes_needed);
        
        // 添加地址族 (2 字节)
        wire_format.extend_from_slice(&(self.family as u16).to_be_bytes());
        
        // 添加源前缀长度 (1 字节)
        wire_format.push(self.source_prefix_length);
        
        // 添加范围前缀长度 (1 字节)
        wire_format.push(self.scope_prefix_length);
        
        // 添加地址数据 (仅包含必要的字节)
        match self.address {
            IpAddr::V4(ipv4) => {
                // 已经计算出所需的字节数，直接使用
                wire_format.extend_from_slice(&ipv4.octets()[..address_bytes_needed]);
            },
            IpAddr::V6(ipv6) => {
                // 已经计算出所需的字节数，直接使用
                wire_format.extend_from_slice(&ipv6.octets()[..address_bytes_needed]);
            }
        }
        
        // 创建 EDNS Option
        Ok(EdnsOption::Unknown(
            EdnsCode::from(EDNS_CLIENT_SUBNET_OPTION_CODE).into(),
            wire_format
        ))
    }
    
    // 从 EDNS Option 解析 ECS 数据
    pub fn from_edns_option(option: &EdnsOption) -> Result<Self> {
        // 获取选项数据
        let data = match option {
            EdnsOption::Unknown(code, data) if *code == EDNS_CLIENT_SUBNET_OPTION_CODE => data,
            _ => return Err(ServerError::Upstream("Not an ECS EDNS option".to_string())),
        };
        
        // 数据必须至少包含 4 字节: FAMILY(2) + SOURCE PREFIX-LENGTH(1) + SCOPE PREFIX-LENGTH(1)
        if data.len() < 4 {
            return Err(ServerError::Upstream("ECS option data length insufficient".to_string()));
        }
        
        // 解析地址族 (大端序)
        let family = match u16::from_be_bytes([data[0], data[1]]) {
            1 => EcsAddressFamily::IPv4,
            2 => EcsAddressFamily::IPv6,
            f => return Err(ServerError::Upstream(format!("Unsupported ECS address family: {}", f))),
        };
        
        // 解析源前缀长度
        let source_prefix_length = data[2];
        
        // 验证源前缀长度
        match family {
            EcsAddressFamily::IPv4 if source_prefix_length > 32 => {
                return Err(ServerError::Upstream(format!(
                    "Invalid IPv4 source prefix length: {}", source_prefix_length
                )));
            },
            EcsAddressFamily::IPv6 if source_prefix_length > 128 => {
                return Err(ServerError::Upstream(format!(
                    "Invalid IPv6 source prefix length: {}", source_prefix_length
                )));
            },
            _ => {}
        }
        
        // 解析范围前缀长度
        let scope_prefix_length = data[3];
        
        // 计算地址字节数
        let address_bytes = &data[4..];
        let expected_bytes = (source_prefix_length as usize + 7) / 8;
        
        // 验证地址字节数
        if address_bytes.len() < expected_bytes {
            return Err(ServerError::Upstream(format!(
                "ECS address data length insufficient. Expected: {} bytes, Actual: {} bytes",
                expected_bytes,
                address_bytes.len()
            )));
        }
        
        // 解析地址
        let address = match family {
            EcsAddressFamily::IPv4 => {
                let mut ipv4_bytes = [0u8; 4];
                // 复制现有字节
                ipv4_bytes[..address_bytes.len().min(4)].copy_from_slice(&address_bytes[..address_bytes.len().min(4)]);
                IpAddr::V4(Ipv4Addr::from(ipv4_bytes))
            },
            EcsAddressFamily::IPv6 => {
                let mut ipv6_bytes = [0u8; 16];
                // 复制现有字节
                ipv6_bytes[..address_bytes.len().min(16)].copy_from_slice(&address_bytes[..address_bytes.len().min(16)]);
                IpAddr::V6(Ipv6Addr::from(ipv6_bytes))
            }
        };
        
        Ok(Self {
            family,
            source_prefix_length,
            scope_prefix_length,
            address,
        })
    }
}

// DNS 消息 ECS 处理 工具
pub struct EcsProcessor;

impl EcsProcessor {
    // 从 DNS 消息中提取 ECS 数据
    pub fn extract_ecs_from_message(message: &Message) -> Option<EcsData> {
        // 获取 OPT 记录
        if let Some(opt_record) = message.additionals()
            .iter()
            .find(|r| r.record_type() == RecordType::OPT) 
        {
            // 解析 OPT 记录
            if let Some(RData::OPT(ref opt_data)) = opt_record.data() {
                // 查找 ECS 选项
                for (code, option) in opt_data.as_ref() {
                    if *code == EdnsCode::from(EDNS_CLIENT_SUBNET_OPTION_CODE) {
                        // 尝试解析 ECS 数据
                        match EcsData::from_edns_option(option) {
                            Ok(ecs_data) => return Some(ecs_data),
                            Err(err) => {
                                warn!("Failed to parse ECS data: {}", err);
                                return None;
                            }
                        }
                    }
                }
            }
        }
        
        None
    }
    
    // 根据策略处理 DNS 查询中的 ECS
    pub fn process_ecs_for_query(
        query: &Message,
        policy: &EcsPolicyConfig,
        client_ip: Option<IpAddr>,
        client_ecs_from_query: Option<&EcsData>,
    ) -> Result<Option<Message>> {
        // 如果不是查询，直接返回
        if query.message_type() != MessageType::Query {
            return Ok(None);
        }
        
        // 如果ECS策略未启用，直接返回原始查询
        if !policy.enabled {
            return Ok(None);
        }
        
        // 获取原始查询中的 ECS 数据，优先使用传入的 client_ecs_from_query
        let ecs_data = if let Some(ecs) = client_ecs_from_query {
            Some(ecs.clone())
        } else {
            Self::extract_ecs_from_message(query)
        };

        // 创建一个辅助函数，按需克隆消息并应用ECS处理
        let process_and_clone = |ecs_op: fn(&mut Message) -> Result<()>| -> Result<Option<Message>> {
            let mut new_query = query.clone();
            ecs_op(&mut new_query)?;
            Ok(Some(new_query))
        };
        
        // 根据策略处理
        match policy.strategy.as_str() {
            // 剥离策略 - 移除 ECS 信息
            ECS_POLICY_STRIP => {
                // 如果没有 ECS 数据或没有 OPT 记录，原样返回
                if ecs_data.is_none() || !query.additionals().iter().any(|r| r.record_type() == RecordType::OPT) {
                    return Ok(None);
                }
                
                // 记录ECS剥离指标
                {
                    METRICS.ecs_processed_total().with_label_values(&["strip"]).inc();
                }
                
                process_and_clone(Self::remove_ecs_from_message)
            },
            
            // 转发策略 - 保持 ECS 不变或添加 ECS
            ECS_POLICY_FORWARD => {
                if let Some(ecs) = &ecs_data {
                    // 检查客户端是否不希望其子网信息被用于地理位置优化
                    if ecs.source_prefix_length == 0 {
                        // 记录ECS剥离指标（当客户端请求不使用ECS时）
                        {
                            METRICS.ecs_processed_total().with_label_values(&["strip"]).inc();
                        }
                        
                        return process_and_clone(Self::remove_ecs_from_message);
                    }
                    
                    // 对于转发策略，需要确保出站 ECS 请求中的 SCOPE PREFIX-LENGTH 为 0
                    let forward_ecs = EcsData::new(
                        ecs.address,
                        ecs.source_prefix_length,
                        0 // 确保出站 scope_prefix_length 为 0
                    );
                    
                    // 记录ECS转发指标
                    {
                        METRICS.ecs_processed_total().with_label_values(&["forward"]).inc();
                    }
                    
                    // 创建新的查询消息并更新ECS
                    let mut new_query = query.clone();
                    Self::update_ecs_in_message(&mut new_query, &forward_ecs)?;
                    return Ok(Some(new_query));
                } else if let Some(ip) = client_ip {
                    // 客户端请求中没有 ECS，但有 client_ip，需要基于 IP 创建新的 ECS
                    let prefix_length = match ip {
                        IpAddr::V4(_) => policy.anonymization.ipv4_prefix_length,
                        IpAddr::V6(_) => policy.anonymization.ipv6_prefix_length,
                    };
                    
                    // 创建新的 ECS 数据
                    let new_ecs = EcsData::new(ip, prefix_length, 0);
                    
                    // 记录ECS转发（添加）指标
                    {
                        METRICS.ecs_processed_total().with_label_values(&["forward_add"]).inc();
                    }
                    
                    // 创建新的查询消息并添加ECS
                    let mut new_query = query.clone();
                    Self::update_ecs_in_message(&mut new_query, &new_ecs)?;
                    return Ok(Some(new_query));
                }
                
                // 无 ECS 数据且无客户端 IP，原样返回
                Ok(None)
            },
            
            // 匿名化策略 - 对 ECS 进行匿名化或添加匿名化的 ECS
            ECS_POLICY_ANONYMIZE => {
                if let Some(ecs_data) = ecs_data {
                    // 检查客户端是否不希望其子网信息被用于地理位置优化
                    if ecs_data.source_prefix_length == 0 {
                        // 记录ECS剥离指标（当客户端请求不使用ECS时）
                        {
                            METRICS.ecs_processed_total().with_label_values(&["strip"]).inc();
                        }
                        
                        return process_and_clone(Self::remove_ecs_from_message);
                    }
                    
                    // 匿名化 ECS 数据
                    let anonymized_ecs = ecs_data.anonymize(
                        policy.anonymization.ipv4_prefix_length,
                        policy.anonymization.ipv6_prefix_length
                    )?;
                    
                    // 记录ECS匿名化指标
                    {
                        METRICS.ecs_processed_total().with_label_values(&["anonymize"]).inc();
                    }
                    
                    // 创建新的查询消息，包含匿名化后的 ECS
                    let mut new_query = query.clone();
                    Self::update_ecs_in_message(&mut new_query, &anonymized_ecs)?;
                    return Ok(Some(new_query));
                } else if let Some(ip) = client_ip {
                    // 客户端请求中没有 ECS，但有 client_ip，需要基于 IP 创建新的匿名化 ECS
                    let prefix_length = match ip {
                        IpAddr::V4(_) => policy.anonymization.ipv4_prefix_length,
                        IpAddr::V6(_) => policy.anonymization.ipv6_prefix_length,
                    };
                    
                    // 匿名化 IP 地址
                    let anonymized_ip = match ip {
                        IpAddr::V4(ipv4) => IpAddr::V4(anonymize_ipv4(ipv4, prefix_length)),
                        IpAddr::V6(ipv6) => IpAddr::V6(anonymize_ipv6(ipv6, prefix_length)),
                    };
                    
                    // 创建新的匿名化 ECS 数据
                    let anonymized_ecs = EcsData::new(anonymized_ip, prefix_length, 0);
                    
                    // 记录ECS匿名化（添加）指标
                    {
                        METRICS.ecs_processed_total().with_label_values(&["anonymize_add"]).inc();
                    }
                    
                    // 创建新的查询消息，添加匿名化的 ECS
                    let mut new_query = query.clone();
                    Self::update_ecs_in_message(&mut new_query, &anonymized_ecs)?;
                    return Ok(Some(new_query));
                }
                
                // 无 ECS 数据且无客户端 IP，原样返回
                Ok(None)
            },
            
            // 未知策略，默认剥离
            _ => {
                warn!("Unknown ECS policy: {}, using strip policy by default", policy.strategy);
                
                // 记录ECS剥离指标（未知策略）
                {
                    METRICS.ecs_processed_total().with_label_values(&["strip_unknown"]).inc();
                }
                
                process_and_clone(Self::remove_ecs_from_message)
            }
        }
    }
    
    // 从 DNS 消息中移除 ECS 信息
    pub fn remove_ecs_from_message(message: &mut Message) -> Result<()> {
        // 查找 OPT 记录索引
        let opt_index = message.additionals()
            .iter()
            .position(|r| r.record_type() == RecordType::OPT);
        
        // 如果没有 OPT 记录，直接返回
        if opt_index.is_none() {
            return Ok(());
        }
        
        let opt_index = opt_index.unwrap();
        
        // 获取原始 OPT 记录
        let opt_record = &message.additionals()[opt_index];
        
        // 解析 OPT 记录
        if let Some(RData::OPT(ref opt_data)) = opt_record.data() {
            // 检查是否包含ECS选项
            let has_ecs = opt_data.as_ref().iter().any(|(code, _)| {
                *code == EdnsCode::from(EDNS_CLIENT_SUBNET_OPTION_CODE)
            });
            
            // 如果没有ECS选项，直接返回，避免不必要的克隆和重建
            if !has_ecs {
                return Ok(());
            }
            
            // 过滤掉 ECS 选项
            let mut new_options = HashMap::new();
            for (code, option) in opt_data.as_ref() {
                if *code != EdnsCode::from(EDNS_CLIENT_SUBNET_OPTION_CODE) {
                    new_options.insert(*code, option.clone());
                }
            }
            
            // 创建新的 OPT 记录
            let new_opt = OPT::new(new_options);
            
            // 创建新的 OPT 记录
            let new_opt_record = Record::from_rdata(
                opt_record.name().clone(),
                opt_record.ttl(),
                RData::OPT(new_opt)
            );
            
            // 替换原有的 OPT 记录
            let mut additionals = message.additionals().to_vec();
            additionals[opt_index] = new_opt_record;
            
            // 更新消息
            let mut header = *message.header();
            header.set_additional_count(additionals.len() as u16);
            
            let mut new_message = Message::new();
            new_message.set_header(header);
            
            // 添加查询
            for query in message.queries() {
                new_message.add_query(query.clone());
            }
            
            // 添加其他内容
            for answer in message.answers() {
                new_message.add_answer(answer.clone());
            }
            
            for ns in message.name_servers() {
                new_message.add_name_server(ns.clone());
            }
            
            for additional in additionals {
                new_message.add_additional(additional);
            }
            
            *message = new_message;
        }
        
        Ok(())
    }
    
    // 更新 DNS 消息中的 ECS 信息
    pub fn update_ecs_in_message(message: &mut Message, ecs_data: &EcsData) -> Result<()> {
        // 将 ECS 数据转换为 EDNS 选项
        let ecs_option = ecs_data.to_edns_option()?;
        
        // 查找 OPT 记录索引
        let opt_index = message.additionals()
            .iter()
            .position(|r| r.record_type() == RecordType::OPT);
        
        let mut additionals = message.additionals().to_vec();
        
        // 如果存在 OPT 记录，更新它
        if let Some(opt_index) = opt_index {
            // 获取原始 OPT 记录
            let opt_record = &additionals[opt_index];
            
            // 解析 OPT 记录
            if let Some(RData::OPT(ref opt_data)) = opt_record.data() {
                // 计算过滤后的选项数量并预分配容量
                let existing_options = opt_data.as_ref();
                
                // 过滤掉原有的 ECS 选项，然后添加新的
                let mut new_options = HashMap::new();
                
                // 先收集所有非 ECS 选项
                for (code, option) in existing_options {
                    if *code != EdnsCode::from(EDNS_CLIENT_SUBNET_OPTION_CODE) {
                        new_options.insert(*code, option.clone());
                    }
                }
                
                // 获取ECS选项代码和数据
                let ecs_code = EdnsCode::from(EDNS_CLIENT_SUBNET_OPTION_CODE);
                
                // 添加新的 ECS 选项
                new_options.insert(ecs_code, ecs_option);
                
                let new_opt = OPT::new(new_options);
                
                // 创建新的 OPT 记录
                let new_opt_record = Record::from_rdata(
                    opt_record.name().clone(),
                    opt_record.ttl(),
                    RData::OPT(new_opt)
                );
                
                // 替换原有的 OPT 记录
                additionals[opt_index] = new_opt_record;
            }
        } else {
            // 如果不存在 OPT 记录，创建一个新的
            let mut new_options = HashMap::new();
            
            // 获取ECS选项代码和数据
            let ecs_code = EdnsCode::from(EDNS_CLIENT_SUBNET_OPTION_CODE);
            
            // 添加新的 ECS 选项
            new_options.insert(ecs_code, ecs_option);
            
            let new_opt = OPT::new(new_options);
            
            // 创建新的 OPT 记录
            let new_opt_record = Record::from_rdata(
                trust_dns_proto::rr::Name::root(),
                0,
                RData::OPT(new_opt)
            );
            
            // 添加到附加记录
            additionals.push(new_opt_record);
        }
        
        // 更新消息
        let mut header = *message.header();
        header.set_additional_count(additionals.len() as u16);
        
        let mut new_message = Message::new();
        new_message.set_header(header);
        
        // 添加查询
        for query in message.queries() {
            new_message.add_query(query.clone());
        }
        
        // 添加其他内容
        for answer in message.answers() {
            new_message.add_answer(answer.clone());
        }
        
        for ns in message.name_servers() {
            new_message.add_name_server(ns.clone());
        }
        
        for additional in additionals {
            new_message.add_additional(additional);
        }
        
        *message = new_message;
        
        Ok(())
    }
}

// 匿名化 IPv4 地址
fn anonymize_ipv4(ip: Ipv4Addr, prefix_length: u8) -> Ipv4Addr {
    if prefix_length >= 32 {
        return ip;
    }
    
    // 将 IPv4 地址转换为 u32
    let ip_u32 = u32::from(ip);
    
    // 创建掩码
    let mask = if prefix_length == 0 {
        0
    } else {
        !0u32 << (32 - prefix_length)
    };
    
    // 应用掩码
    let anonymized_u32 = ip_u32 & mask;
    
    // 转换回 IPv4Addr
    Ipv4Addr::from(anonymized_u32)
}

// 匿名化 IPv6 地址
fn anonymize_ipv6(ip: Ipv6Addr, prefix_length: u8) -> Ipv6Addr {
    if prefix_length >= 128 {
        return ip;
    }
    
    // 获取 IPv6 地址的八个 u16 段
    let segments = ip.segments();
    
    // 创建新的段数组
    let mut anonymized_segments = [0u16; 8];
    
    for i in 0..8 {
        let segment_start_bit = i * 16;
        
        if segment_start_bit >= prefix_length as usize {
            // 该段完全位于前缀之外，设为 0
            anonymized_segments[i] = 0;
        } else if segment_start_bit + 16 <= prefix_length as usize {
            // 该段完全位于前缀之内，保持不变
            anonymized_segments[i] = segments[i];
        } else {
            // 该段部分位于前缀之内，部分位于前缀之外
            let bits_to_keep = prefix_length as usize - segment_start_bit;
            let mask = !0u16 << (16 - bits_to_keep);
            anonymized_segments[i] = segments[i] & mask;
        }
    }
    
    // 创建新的 IPv6 地址
    Ipv6Addr::from(anonymized_segments)
}
