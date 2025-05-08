// src/server/upstream.rs

use std::collections::HashMap;
use std::net::{SocketAddr, IpAddr};
use std::sync::Arc;

use reqwest::{Client, header};
use tracing::{debug, error, info, warn};
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::proto::op::{Message, MessageType, OpCode, ResponseCode};
use trust_dns_resolver::config::{
    NameServerConfig, Protocol, ResolverConfig, ResolverOpts,
};

use crate::server::config::{ServerConfig, UpstreamConfig, ResolverProtocol, EcsPolicyConfig};
use crate::server::error::{Result, ServerError};
use crate::server::ecs::{EcsProcessor, EcsData};
use crate::common::consts::CONTENT_TYPE_DNS_MESSAGE;

// 上游选择
#[derive(Debug, Clone)]
pub enum UpstreamSelection {
    // 使用特定上游组
    Group(String),
    // 使用全局默认上游
    Global,
}

// DoH查询客户端
struct DoHClient {
    // HTTP客户端
    client: Client,
    // DoH服务器URL
    url: String,
}

impl DoHClient {
    // 创建新的DoH客户端
    fn new(url: String, client: Client) -> Self {
        Self { client, url }
    }
    
    // 执行DoH查询
    async fn query(&self, dns_message: &Message) -> Result<Message> {
        // 将DNS消息转换为二进制格式
        let dns_wire = dns_message.to_vec()?;
        
        // 构建请求
        let response = self.client
            .post(&self.url)
            .header(header::CONTENT_TYPE, CONTENT_TYPE_DNS_MESSAGE)
            .header(header::ACCEPT, CONTENT_TYPE_DNS_MESSAGE)
            .body(dns_wire)
            .send()
            .await
            .map_err(|e| ServerError::Upstream(format!("DoH request failed: {}", e)))?;
        
        // 检查HTTP状态码
        if !response.status().is_success() {
            return Err(ServerError::Upstream(format!(
                "DoH server returned error status: {}", 
                response.status()
            )));
        }
        
        // 验证内容类型
        let content_type = response.headers()
            .get(header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");
            
        if content_type != CONTENT_TYPE_DNS_MESSAGE {
            return Err(ServerError::Upstream(format!(
                "DoH server returned invalid content type: {}", 
                content_type
            )));
        }
        
        // 读取响应体
        let response_bytes = response.bytes()
            .await
            .map_err(|e| ServerError::Upstream(format!("Failed to read DoH response: {}", e)))?;
            
        // 解析DNS消息
        Message::from_vec(&response_bytes)
            .map_err(|e| ServerError::Upstream(format!("Failed to parse DNS response: {}", e)))
    }
}

// 上游组解析配置
struct UpstreamGroupConfig {
    // 内部 TokioAsyncResolver
    resolver: TokioAsyncResolver,
    // DoH客户端
    doh_clients: Vec<Arc<DoHClient>>,
    // 上游配置 - 使用引用代替克隆整个配置
    config: Arc<UpstreamConfig>,
}

// 上游 DNS 解析管理器
pub struct UpstreamManager {
    // 全局上游配置
    global_config: UpstreamGroupConfig,
    // 上游组配置 (组名 -> 配置)
    group_configs: HashMap<String, UpstreamGroupConfig>,
    // 服务器配置（使用Arc代替完整clone）
    server_config: Arc<ServerConfig>,
}

impl UpstreamManager {
    // 创建新的上游解析管理器
    pub async fn new(config: Arc<ServerConfig>, http_client: Client) -> Result<Self> {
        // 创建全局上游配置，使用Arc引用避免clone
        let global_config = Self::create_upstream_group_config(&config, Arc::new(config.dns.upstream.clone()), http_client.clone())?;
        
        // 创建上游组配置映射
        let mut group_configs = HashMap::new();
        
        // 如果路由功能已启用
        if config.dns.routing.enabled {
            // 为每个上游组创建配置
            for group in &config.dns.routing.upstream_groups {
                // 获取此组的有效配置（继承与覆盖全局配置）
                let effective_config = Arc::new(config.get_effective_upstream_config(&group.name)?);
                
                // 创建上游组配置
                let group_config = Self::create_upstream_group_config(&config, effective_config.clone(), http_client.clone())?;
                
                // 添加到映射
                group_configs.insert(group.name.clone(), group_config);
                
                info!(
                    group_name = &group.name,
                    resolvers_count = effective_config.resolvers.len(),
                    dnssec_enabled = effective_config.enable_dnssec,
                    query_timeout = effective_config.query_timeout,
                    "Initialized upstream group"
                );
            }
        }
        
        info!(
            global_resolvers_count = config.dns.upstream.resolvers.len(),
            group_count = group_configs.len(),
            "Upstream resolver manager initialized"
        );
        
        Ok(Self {
            global_config,
            group_configs,
            server_config: config,
        })
    }
    
    // 创建上游组配置
    fn create_upstream_group_config(
        _config: &ServerConfig, 
        upstream_config: Arc<UpstreamConfig>, 
        http_client: Client
    ) -> Result<UpstreamGroupConfig> {
        // 构建 trust-dns-resolver 配置（用于非DoH协议）
        let (resolver_config, resolver_opts) = Self::build_resolver_config(&upstream_config)?;
        
        // 创建异步解析器
        let resolver = TokioAsyncResolver::tokio(resolver_config, resolver_opts);
        
        // 创建DoH客户端列表
        let mut doh_clients = Vec::new();
        
        for resolver_config in &upstream_config.resolvers {
            if resolver_config.protocol == ResolverProtocol::Doh {
                // 使用共享的 HTTP 客户端
                let client = DoHClient::new(resolver_config.address.clone(), http_client.clone());
                doh_clients.push(Arc::new(client));
                debug!(
                    url = ?resolver_config.address,
                    "Added DoH upstream resolver"
                );
            }
        }
        
        Ok(UpstreamGroupConfig {
            resolver,
            doh_clients,
            config: upstream_config,
        })
    }
    
    // 执行 DNS 查询
    pub async fn resolve(
        &self, 
        query_message: &Message, 
        selection: UpstreamSelection,
        client_ip: Option<IpAddr>,
        client_ecs: Option<&EcsData>
    ) -> Result<Message> {
        if query_message.message_type() != MessageType::Query {
            return Err(ServerError::Upstream("Not a query message type".to_string()));
        }
        
        if query_message.op_code() != OpCode::Query {
            return Err(ServerError::Upstream(format!(
                "Unsupported operation code: {:?}", 
                query_message.op_code()
            )));
        }
        
        // 获取第一个查询
        let query = match query_message.queries().first() {
            Some(q) => q,
            None => return Err(ServerError::Upstream("No Query section in query message".to_string())),
        };
        
        // 选择目标上游配置
        let (target_config, group_name) = match &selection {
            UpstreamSelection::Group(group_name) => {
                match self.group_configs.get(group_name) {
                    Some(config) => (config, group_name.as_str()),
                    None => return Err(ServerError::Upstream(format!("Unknown upstream group: {}", group_name))),
                }
            },
            UpstreamSelection::Global => (&self.global_config, ""),
        };
        
        // 获取 ECS 策略
        let ecs_policy = self.server_config.get_effective_ecs_policy(group_name)?;
        
        // 处理 ECS，根据策略和 client_ecs 参数修改查询
        let processed_query = match EcsProcessor::process_ecs_for_query(
            query_message, 
            &ecs_policy,
            client_ip,
            client_ecs
        )? {
            Some(new_query) => new_query,
            None => query_message.clone(), // 这里的克隆是必要的
        };
        
        // 记录查询信息
        debug!(
            name = %query.name(),
            type_value = ?query.query_type(),
            class = ?query.query_class(),
            dnssec_enabled = target_config.config.enable_dnssec,
            upstream_group = match &selection {
                UpstreamSelection::Group(g) => g.as_str(),
                UpstreamSelection::Global => "global",
            },
            "Resolving query"
        );
        
        // 执行查询
        let response = if !target_config.doh_clients.is_empty() {
            // 有 DoH 客户端，优先使用
            let client = &target_config.doh_clients[0]; // 简单选择第一个，后续可以实现更复杂的负载均衡
            client.query(&processed_query).await?
        } else {
            // 没有 DoH 客户端，使用标准解析器
            let query_bytes = processed_query.to_vec()?;
            let response_bytes = target_config.resolver.dns_query(
                &query_bytes
            ).await
                .map_err(|e| ServerError::Upstream(format!("DNS query failed: {}", e)))?;
            
            // 解析响应
            Message::from_vec(&response_bytes)
                .map_err(|e| ServerError::Upstream(format!("Failed to parse DNS response: {}", e)))?
        };
        
        // 返回响应
        Ok(response)
    }
    
    // 构建 trust-dns-resolver 配置
    fn build_resolver_config(
        config: &UpstreamConfig,
    ) -> Result<(ResolverConfig, ResolverOpts)> {
        // 创建解析器配置
        let mut resolver_config = ResolverConfig::new();
        
        // 添加解析器
        for resolver in &config.resolvers {
            match resolver.protocol {
                // UDP/TCP 协议
                ResolverProtocol::Udp | ResolverProtocol::Tcp => {
                    // 解析地址
                    let socket_addr = Self::parse_socket_addr(&resolver.address)?;
                    
                    // 添加解析器
                    let protocol = match resolver.protocol {
                        ResolverProtocol::Udp => Protocol::Udp,
                        ResolverProtocol::Tcp => Protocol::Tcp,
                        _ => unreachable!(),
                    };
                    
                    resolver_config.add_name_server(NameServerConfig {
                        socket_addr,
                        protocol,
                        tls_dns_name: None,
                        trust_negative_responses: true,
                        bind_addr: None,
                    });
                },
                
                // DoT 协议
                ResolverProtocol::Dot => {
                    // 解析 DoT 地址 (domain@ip:port)
                    let parts: Vec<&str> = resolver.address.split('@').collect();
                    if parts.len() != 2 {
                        return Err(ServerError::Config(format!(
                            "Invalid DoT address format, expected 'domain@ip:port': {}", 
                            resolver.address
                        )));
                    }
                    
                    let domain = parts[0].to_string();
                    let socket_addr = Self::parse_socket_addr(parts[1])?;
                    
                    resolver_config.add_name_server(NameServerConfig {
                        socket_addr,
                        protocol: Protocol::Tls,
                        tls_dns_name: Some(domain),
                        trust_negative_responses: true,
                        bind_addr: None,
                    });
                },
                
                // DoH 协议 - 不由 trust-dns-resolver 处理，而是由我们自己的 DoHClient 处理
                ResolverProtocol::Doh => {
                    // 什么都不做，DoH 由单独的 DoHClient 处理
                }
            }
        }
        
        // 创建解析器选项
        let mut resolver_opts = ResolverOpts::default();
        
        // 设置查询超时
        resolver_opts.timeout = std::time::Duration::from_secs(config.query_timeout);
        
        // 设置是否启用DNSSEC
        resolver_opts.validate = config.enable_dnssec;
        
        // 在此可以设置其他选项...
        
        Ok((resolver_config, resolver_opts))
    }

    // 解析 socket 地址
    fn parse_socket_addr(addr_str: &str) -> Result<SocketAddr> {
        addr_str.parse()
            .map_err(|e| ServerError::Config(format!(
                "Invalid socket address '{}': {}", 
                addr_str, e
            )))
    }
} 
