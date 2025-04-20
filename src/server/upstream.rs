// src/server/upstream.rs

use std::net::SocketAddr;
use trust_dns_proto::op::{Message, MessageType, OpCode};
use trust_dns_resolver::config::{
    NameServerConfig, Protocol, ResolverConfig, ResolverOpts,
};
use trust_dns_resolver::TokioAsyncResolver;
use tracing::{debug, info, warn};

use crate::common::error::{AppError, Result};
use crate::server::config::{ResolverProtocol, ServerConfig, UpstreamConfig};

/// 上游 DNS 解析管理器
pub struct UpstreamManager {
    /// 内部 TokioAsyncResolver
    resolver: TokioAsyncResolver,
    /// 上游配置
    _config: UpstreamConfig,
}

impl UpstreamManager {
    /// 创建新的上游解析管理器
    pub async fn new(config: &ServerConfig) -> Result<Self> {
        // 提取上游配置
        let upstream_config = config.upstream.clone();
        
        // 构建 trust-dns-resolver 配置
        let (resolver_config, resolver_opts) = Self::build_resolver_config(&upstream_config)?;
        
        // 创建异步解析器
        let resolver = TokioAsyncResolver::tokio(resolver_config, resolver_opts);
            
        info!(
            resolvers_count = upstream_config.resolvers.len(),
            dnssec_enabled = upstream_config.enable_dnssec,
            "Upstream resolver manager initialized"
        );
        
        Ok(Self {
            resolver,
            _config: upstream_config,
        })
    }
    
    /// 执行 DNS 查询
    pub async fn resolve(&self, query_message: &Message) -> Result<Message> {
        if query_message.message_type() != MessageType::Query {
            return Err(AppError::Upstream("Not a query message type".to_string()));
        }
        
        if query_message.op_code() != OpCode::Query {
            return Err(AppError::Upstream(format!(
                "Unsupported operation code: {:?}", 
                query_message.op_code()
            )));
        }
        
        // 获取第一个查询
        let query = match query_message.queries().first() {
            Some(q) => q,
            None => return Err(AppError::Upstream("No Query section in query message".to_string())),
        };
        
        debug!(   
            name = ?query.name(),
            type_value = ?query.query_type(),
            "Processing DNS query via upstream resolvers"
        );
        
        // 创建 lookup 函数
        let response = self.resolver
            .lookup(query.name().clone(), query.query_type())
            .await
            .map_err(|e| AppError::DnsResolve(e))?;
            
        // 构建响应消息
        let mut response_message = Message::new();
        response_message
            .set_id(query_message.id())
            .set_message_type(MessageType::Response)
            .set_op_code(query_message.op_code())
            .set_authoritative(false) // 我们不是权威服务器
            .set_recursion_desired(query_message.recursion_desired())
            .set_recursion_available(true) // 我们支持递归查询
            // 使用返回结果中的 DNSSEC 验证状态
            .set_authentic_data(response.as_lookup().authentic_data())
            .set_checking_disabled(query_message.checking_disabled());
            
        // 添加原始查询到响应
        for query in query_message.queries() {
            response_message.add_query(query.clone());
        }
        
        // 添加应答记录
        for record in response.record_iter() {
            response_message.add_answer(record.clone());
        }
        
        Ok(response_message)
    }
    
    /// 构建 trust-dns-resolver 配置
    fn build_resolver_config(
        config: &UpstreamConfig,
    ) -> Result<(ResolverConfig, ResolverOpts)> {
        let mut resolver_config = ResolverConfig::new();
        let mut resolver_opts = ResolverOpts::default();
        
        // 设置 DNSSEC
        resolver_opts.validate = config.enable_dnssec;
        
        // 设置查询超时
        resolver_opts.timeout = std::time::Duration::from_secs(config.query_timeout);
        
        // 添加上游解析器
        for resolver in &config.resolvers {
            match Self::create_name_server_config(resolver) {
                Ok(ns_config) => {
                    resolver_config.add_name_server(ns_config);
                    debug!(
                        address = ?resolver.address,
                        protocol = ?resolver.protocol,
                        "Added upstream resolver,"
                    );
                }
                Err(e) => {
                    warn!(
                        address = ?resolver.address,
                        protocol = ?resolver.protocol,
                        error = ?e,
                        "Invalid upstream resolver configuration - skipping,"
                    );
                }
            }
        }
        
        Ok((resolver_config, resolver_opts))
    }
    
    /// 从配置创建名称服务器配置
    fn create_name_server_config(
        resolver_config: &crate::server::config::ResolverConfig,
    ) -> Result<NameServerConfig> {
        match resolver_config.protocol {
            ResolverProtocol::Udp => {
                // 解析 UDP 地址 (IP:port)
                let socket_addr = Self::parse_socket_addr(&resolver_config.address)?;
                Ok(NameServerConfig {
                    socket_addr,
                    protocol: Protocol::Udp,
                    tls_dns_name: None,
                    trust_negative_responses: true,
                    bind_addr: None,
                })
            }
            ResolverProtocol::Tcp => {
                // 解析 TCP 地址 (IP:port)
                let socket_addr = Self::parse_socket_addr(&resolver_config.address)?;
                Ok(NameServerConfig {
                    socket_addr,
                    protocol: Protocol::Tcp,
                    tls_dns_name: None,
                    trust_negative_responses: true,
                    bind_addr: None,
                })
            }
            ResolverProtocol::Dot => {
                // 解析 DoT 地址 (IP:port) 和域名
                let parts: Vec<&str> = resolver_config.address.split('@').collect();
                if parts.len() != 2 {
                    return Err(AppError::Config(format!(
                        "Invalid DoT address format, should be 'domain@IP:port': {}",
                        resolver_config.address
                    )));
                }
                
                let dns_name = parts[0].to_string();
                let socket_addr = Self::parse_socket_addr(parts[1])?;
                
                Ok(NameServerConfig {
                    socket_addr,
                    protocol: Protocol::Tls,
                    tls_dns_name: Some(dns_name),
                    trust_negative_responses: true,
                    bind_addr: None,
                })
            }
            ResolverProtocol::Doh => {
                // 解析 DoH URL
                Ok(NameServerConfig {
                    socket_addr: SocketAddr::from(([0, 0, 0, 0], 443)), // 实际上不会使用
                    protocol: Protocol::Tls, // DoH暂不直接支持，使用TLS替代
                    tls_dns_name: Some(resolver_config.address.clone()),
                    trust_negative_responses: true,
                    bind_addr: None,
                })
            }
        }
    }
    
    /// 解析套接字地址
    fn parse_socket_addr(addr_str: &str) -> Result<SocketAddr> {
        addr_str.parse().map_err(|e| {
            AppError::Config(format!("Invalid socket address '{}': {}", addr_str, e))
        })
    }
} 
