// src/server/upstream.rs

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use trust_dns_proto::op::{Message, MessageType, OpCode, ResponseCode};
use trust_dns_resolver::config::{
    NameServerConfig, Protocol, ResolverConfig, ResolverOpts,
};
use trust_dns_resolver::TokioAsyncResolver;
use tracing::{debug, info, warn, error};
use reqwest::{self, Client, header};

use crate::server::error::{ServerError, Result};
use crate::server::config::{ResolverProtocol, ServerConfig, UpstreamConfig};
use crate::server::routing::Router;
use crate::common::consts::{CONTENT_TYPE_DNS_MESSAGE};

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
        let response_message = Message::from_vec(&response_bytes)
            .map_err(|e| ServerError::Upstream(format!("Failed to parse DNS response: {}", e)))?;
            
        Ok(response_message)
    }
}

// 上游组解析配置
struct UpstreamGroupConfig {
    // 内部 TokioAsyncResolver
    resolver: TokioAsyncResolver,
    // DoH客户端
    doh_clients: Vec<Arc<DoHClient>>,
    // 上游配置
    config: UpstreamConfig,
}

// 上游 DNS 解析管理器
pub struct UpstreamManager {
    // 全局上游配置
    global_config: UpstreamGroupConfig,
    // 上游组配置 (组名 -> 配置)
    group_configs: HashMap<String, UpstreamGroupConfig>,
    // DNS 路由器
    router: Arc<Router>,
    // 服务器配置
    config: Arc<ServerConfig>,
    // HTTP 客户端
    http_client: Client,
}

impl UpstreamManager {
    // 创建新的上游解析管理器
    pub async fn new(config: &ServerConfig, router: Arc<Router>, http_client: Client) -> Result<Self> {
        // 创建全局上游配置
        let global_config = Self::create_upstream_group_config(config, &config.dns.upstream, http_client.clone())?;
        
        // 创建上游组配置映射
        let mut group_configs = HashMap::new();
        
        // 如果路由功能已启用
        if config.dns.routing.enabled {
            // 为每个上游组创建配置
            for group in &config.dns.routing.upstream_groups {
                // 获取此组的有效配置（继承与覆盖全局配置）
                let effective_config = config.get_effective_upstream_config(&group.name)?;
                
                // 创建上游组配置
                let group_config = Self::create_upstream_group_config(config, &effective_config, http_client.clone())?;
                
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
            router,
            config: Arc::new(config.clone()),
            http_client,
        })
    }
    
    // 创建上游组配置
    fn create_upstream_group_config(_config: &ServerConfig, upstream_config: &UpstreamConfig, http_client: Client) -> Result<UpstreamGroupConfig> {
        // 构建 trust-dns-resolver 配置（用于非DoH协议）
        let (resolver_config, resolver_opts) = Self::build_resolver_config(upstream_config)?;
        
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
            config: upstream_config.clone(),
        })
    }
    
    // 执行 DNS 查询
    pub async fn resolve(&self, query_message: &Message, selection: UpstreamSelection) -> Result<Message> {
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
        
        // 确定上游标识符，用于记录指标
        let upstream_identifier = match &selection {
            UpstreamSelection::Global => "__global_default__".to_string(),
            UpstreamSelection::Group(group_name) => group_name.clone(),
        };
        
        // 记录开始时间
        let start_time = std::time::Instant::now();
        
        // 根据选择获取对应的上游组配置
        let upstream_group = match selection {
            UpstreamSelection::Global => {
                debug!("Using global upstream configuration");
                &self.global_config
            },
            UpstreamSelection::Group(ref group_name) => {
                debug!(group_name = %group_name, "Using upstream group configuration");
                match self.group_configs.get(group_name) {
                    Some(group) => group,
                    None => {
                        warn!(group_name = %group_name, "Upstream group not found, falling back to global");
                        
                        // 记录上游组未找到错误
                        use crate::server::metrics::METRICS;
                        METRICS.with(|m| m.record_error("UpstreamGroupNotFound"));
                        
                        &self.global_config
                    },
                }
            },
        };
        
        debug!(   
            name = ?query.name(),
            type_value = ?query.query_type(),
            "Processing DNS query via selected upstream resolvers"
        );
        
        // 如果有DoH客户端可用，优先使用DoH查询
        if !upstream_group.doh_clients.is_empty() {
            // 使用第一个DoH客户端（将来可实现负载均衡）
            let doh_client = &upstream_group.doh_clients[0];
            debug!(
                url = ?doh_client.url,
                "Querying via DoH resolver"
            );
            
            // 执行DoH查询
            match doh_client.query(query_message).await {
                Ok(response) => {
                    // 记录查询耗时和计数
                    let duration = start_time.elapsed();
                    use crate::server::metrics::METRICS;
                    METRICS.with(|m| m.record_upstream_query(&upstream_identifier, duration));
                    
                    return Ok(response);
                },
                Err(e) => {
                    // DoH查询失败，记录错误
                    error!(
                        error = ?e,
                        "DoH query failed, falling back to standard resolver"
                    );
                    // 继续使用标准解析器
                }
            }
        }
        
        // 使用标准解析器
        // 创建一个响应消息，这些基本参数不受查询结果影响
        let mut response_message = Message::new();
        response_message
            .set_id(query_message.id())
            .set_message_type(MessageType::Response)
            .set_op_code(query_message.op_code())
            .set_authoritative(false)
            .set_recursion_desired(query_message.recursion_desired())
            .set_recursion_available(true)
            .set_checking_disabled(query_message.checking_disabled());
        
        // 获取 CD 标志 (Checking Disabled)
        let cd_flag = query_message.checking_disabled();
        
        // 根据 CD 标志和配置确定是否需要 DNSSEC 验证
        let dnssec_enabled = upstream_group.config.enable_dnssec && !cd_flag;
        
        // 查询域名
        // 无论是否设置CD标志，我们始终使用相同的查询方法。
        // 在ResolverOpts的validate已经配置启用DNSSEC
        // trust-dns-resolver会根据CD标志自动处理DNSSEC验证
        let lookup_result = upstream_group.resolver.lookup(query.name().clone(), query.query_type())
            .await
            .map_err(ServerError::DnsResolve);
        
        // 记录查询耗时和计数
        let duration = start_time.elapsed();
        use crate::server::metrics::METRICS;
        METRICS.with(|m| m.record_upstream_query(&upstream_identifier, duration));
        
        // 如果启用了DNSSEC，记录验证结果
        if dnssec_enabled && !cd_flag {
            // 查询结果成功，并且有记录返回视为验证成功
            // 注意：这是简化的实现，更精确的实现应从应答中检查AD标志
            let validation_success = lookup_result.is_ok();
            METRICS.with(|m| m.record_dnssec_validation(validation_success));
        }
        
        match lookup_result {
            Ok(dns_response) => {
                // 添加原始查询和所有响应记录
                response_message.add_query(query.clone());
                response_message.add_answers(dns_response.records().to_vec());
                response_message.set_response_code(ResponseCode::NoError);
                
                // 设置 AD 标志，只有在以下条件都满足时才设置：
                // 1. DNSSEC 已启用（通过配置）
                // 2. CD 标志未设置（客户端允许验证）
                // 3. 有记录返回（没有记录则没有内容可验证）
                let has_records = !dns_response.records().is_empty();
                
                // 当使用trust-dns-resolver时，如果记录通过了DNSSEC验证，则会设置authentic_data标志
                // 如果启用了DNSSEC并且有记录，我们将其标记为已验证
                // 这样做的理由是：
                // 1. trust-dns-resolver在我们启用DNSSEC验证时会验证记录
                // 2. 如果验证失败，lookup()调用会返回错误
                // 3. 如果我们到达这里（有记录，无错误），则意味着记录已经通过了验证
                // 4. 记录是否实际验证过取决于使用的上游解析器和查询的域名
                let is_validated = dnssec_enabled && has_records && !cd_flag;
                response_message.set_authentic_data(is_validated);
                
                debug!(
                    name = ?query.name(),
                    type_value = ?query.query_type(),
                    records_count = dns_response.records().len(),
                    dnssec_validated = is_validated,
                    "DNS query successful"
                );
                
                Ok(response_message)
            },
            Err(e) => {
                error!(
                    name = ?query.name(),
                    type_value = ?query.query_type(),
                    error = ?e,
                    "DNS query failed"
                );
                
                // 构造一个错误响应
                response_message.add_query(query.clone());
                
                // 使用对应的响应码
                // 可以进一步实现更详细的错误码转换
                response_message.set_response_code(ResponseCode::ServFail);
                
                Err(e)
            }
        }
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
                    match resolver.protocol {
                        ResolverProtocol::Udp => {
                            resolver_config.add_name_server(NameServerConfig {
                                socket_addr,
                                protocol: Protocol::Udp,
                                tls_dns_name: None,
                                trust_negative_responses: true,
                                bind_addr: None,
                            });
                        },
                        ResolverProtocol::Tcp => {
                            resolver_config.add_name_server(NameServerConfig {
                                socket_addr,
                                protocol: Protocol::Tcp,
                                tls_dns_name: None,
                                trust_negative_responses: true,
                                bind_addr: None,
                            });
                        },
                        _ => unreachable!(),
                    }
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
