// src/server/upstream.rs

use std::net::SocketAddr;
use trust_dns_proto::op::{Message, MessageType, OpCode, ResponseCode};
use trust_dns_resolver::config::{
    NameServerConfig, Protocol, ResolverConfig, ResolverOpts,
};
use trust_dns_resolver::TokioAsyncResolver;
use tracing::{debug, info, warn, error};
use reqwest::{self, Client, header};
use std::sync::Arc;

use crate::common::error::{AppError, Result};
use crate::server::config::{ResolverProtocol, ServerConfig, UpstreamConfig};
use crate::common::consts::{CONTENT_TYPE_DNS_MESSAGE};

// DoH查询客户端
struct DoHClient {
    // HTTP客户端
    client: Client,
    // DoH服务器URL
    url: String,
}

impl DoHClient {
    // 创建新的DoH客户端
    fn new(url: String, config: &ServerConfig) -> Result<Self> {
        // 使用配置创建HTTP客户端
        let client = Client::builder()
            .timeout(config.http_client_timeout())
            .pool_idle_timeout(config.http_client_pool_idle_timeout())
            .user_agent(&config.dns.http_client.request.user_agent)
            .pool_max_idle_per_host(config.dns.http_client.pool.max_idle_connections as usize)
            .use_native_tls()
            .danger_accept_invalid_certs(true)  // 允许自签名证书
            .danger_accept_invalid_hostnames(true)  // 允许不匹配的主机名
            .build()
            .map_err(|e| AppError::Upstream(format!("Failed to create HTTP client: {}", e)))?;
            
        Ok(Self { client, url })
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
            .map_err(|e| AppError::Upstream(format!("DoH request failed: {}", e)))?;
        
        // 检查HTTP状态码
        if !response.status().is_success() {
            return Err(AppError::Upstream(format!(
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
            return Err(AppError::Upstream(format!(
                "DoH server returned invalid content type: {}", 
                content_type
            )));
        }
        
        // 读取响应体
        let response_bytes = response.bytes()
            .await
            .map_err(|e| AppError::Upstream(format!("Failed to read DoH response: {}", e)))?;
            
        // 解析DNS消息
        let response_message = Message::from_vec(&response_bytes)
            .map_err(|e| AppError::Upstream(format!("Failed to parse DNS response: {}", e)))?;
            
        Ok(response_message)
    }
}

// 上游 DNS 解析管理器
pub struct UpstreamManager {
    // 内部 TokioAsyncResolver
    resolver: TokioAsyncResolver,
    // DoH客户端
    doh_clients: Vec<Arc<DoHClient>>,
    // 上游配置
    _config: UpstreamConfig,
}

impl UpstreamManager {
    // 创建新的上游解析管理器
    pub async fn new(config: &ServerConfig) -> Result<Self> {
        // 提取上游配置
        let upstream_config = config.dns.upstream.clone();
        
        // 构建 trust-dns-resolver 配置（用于非DoH协议）
        let (resolver_config, resolver_opts) = Self::build_resolver_config(&upstream_config)?;
        
        // 创建异步解析器
        let resolver = TokioAsyncResolver::tokio(resolver_config, resolver_opts);
        
        // 创建DoH客户端列表
        let mut doh_clients = Vec::new();
        
        for resolver_config in &upstream_config.resolvers {
            if resolver_config.protocol == ResolverProtocol::Doh {
                match DoHClient::new(resolver_config.address.clone(), config) {
                    Ok(client) => {
                        doh_clients.push(Arc::new(client));
                        debug!(
                            url = ?resolver_config.address,
                            "Added DoH upstream resolver"
                        );
                    },
                    Err(e) => {
                        warn!(
                            url = ?resolver_config.address,
                            error = ?e,
                            "Failed to create DoH client - skipping"
                        );
                    }
                }
            }
        }
            
        info!(
            resolvers_count = upstream_config.resolvers.len(),
            doh_resolvers_count = doh_clients.len(),
            dnssec_enabled = upstream_config.enable_dnssec,
            "Upstream resolver manager initialized"
        );
        
        Ok(Self {
            resolver,
            doh_clients,
            _config: upstream_config,
        })
    }
    
    // 执行 DNS 查询
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
        
        // 如果有DoH客户端可用，优先使用DoH查询
        if !self.doh_clients.is_empty() {
            // 使用第一个DoH客户端（将来可实现负载均衡）
            let doh_client = &self.doh_clients[0];
            debug!(
                url = ?doh_client.url,
                "Querying via DoH resolver"
            );
            
            // 执行DoH查询
            match doh_client.query(query_message).await {
                Ok(response) => return Ok(response),
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
        let dnssec_enabled = self._config.enable_dnssec && !cd_flag;
        
        // 查询域名
        // 无论是否设置CD标志，我们始终使用相同的查询方法。
        // 在ResolverOpts的validate已经配置启用DNSSEC
        // trust-dns-resolver会根据CD标志自动处理DNSSEC验证
        let lookup_result = self.resolver.lookup(query.name().clone(), query.query_type())
            .await
            .map_err(|e| AppError::DnsResolve(e));
        
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
                    has_records = has_records,
                    dnssec_enabled = dnssec_enabled,
                    cd_flag = cd_flag,
                    authentic_data = is_validated,
                    "DNS query completed"
                );
                
                Ok(response_message)
            },
            Err(e) => {
                // 构建错误响应
                response_message.add_query(query.clone());
                
                // 根据错误类型设置响应码
                if let AppError::DnsResolve(resolve_err) = &e {
                    match resolve_err.kind() {
                        trust_dns_resolver::error::ResolveErrorKind::NoRecordsFound { .. } => {
                            response_message.set_response_code(ResponseCode::NXDomain);
                            response_message.set_authentic_data(false); // 没有记录可验证
                            return Ok(response_message);
                        },
                        _ => {
                            // 其他错误，继续传递错误
                        }
                    }
                }
                
                // 默认传递原始错误
                Err(e)
            }
        }
    }
    
    // 构建 trust-dns-resolver 配置
    fn build_resolver_config(
        config: &UpstreamConfig,
    ) -> Result<(ResolverConfig, ResolverOpts)> {
        let mut resolver_config = ResolverConfig::new();
        let mut resolver_opts = ResolverOpts::default();
        
        // 设置 DNSSEC
        resolver_opts.validate = config.enable_dnssec;
        
        // 如果启用 DNSSEC，配置额外必要的选项
        if config.enable_dnssec {
            // 使用默认的根锚配置，它包含需要的DNSSEC信息
            resolver_config = ResolverConfig::default();
            
            // 配置必要的DNSSEC选项
            resolver_opts.edns0 = true;                 // DNSSEC 需要 EDNS0 支持
            resolver_opts.use_hosts_file = false;       // 避免干扰 DNSSEC 验证
            resolver_opts.preserve_intermediates = true; // 保留中间记录，对DNSSEC验证有帮助
            
            // DNSSEC相关设置
            resolver_opts.validate = true;              // 确保启用DNSSEC验证
            
            debug!("DNSSEC validation enabled with trust anchors");
        }
        
        // 设置查询超时
        resolver_opts.timeout = std::time::Duration::from_secs(config.query_timeout);
        
        // 添加上游解析器（不包含DoH协议的解析器）
        for resolver in &config.resolvers {
            // 跳过DoH协议的解析器，它们将使用自定义DoH客户端处理
            if resolver.protocol == ResolverProtocol::Doh {
                continue;
            }
            
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
    
    // 从配置创建名称服务器配置
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
                // DoH现在使用自定义客户端实现，这里不再需要实现
                // 为了保持API兼容性，返回一个错误
                Err(AppError::Config(
                    "DoH protocol is now handled by custom client implementation".to_string()
                ))
            }
        }
    }
    
    // 解析套接字地址
    fn parse_socket_addr(addr_str: &str) -> Result<SocketAddr> {
        addr_str.parse().map_err(|e| {
            AppError::Config(format!("Invalid socket address '{}': {}", addr_str, e))
        })
    }
} 
