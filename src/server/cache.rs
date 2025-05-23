// src/server/cache.rs

use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::fs::{File, create_dir_all};
use std::path::Path;
use std::io::{BufReader, BufWriter};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use moka::future::Cache;
use hickory_proto::op::{Message};
use hickory_proto::rr::{DNSClass, Name, RecordType};
use tokio::sync::RwLock;
use tokio::time::{interval, Instant};
use tracing::{debug, warn, error, info};
use serde::{Serialize, Deserialize};
use tokio::task;
use crate::server::error::{Result, ServerError};
use crate::server::config::{CacheConfig, PersistenceCacheConfig};
use crate::server::ecs::{EcsData};
use crate::common::consts::{CACHE_FILE_MAGIC, CACHE_FILE_VERSION};
use crate::server::metrics::METRICS;

// 缓存操作标签常量
const CACHE_OP_HIT: &str = "hit";
const CACHE_OP_MISS: &str = "miss";
const CACHE_OP_INSERT: &str = "insert";
const CACHE_OP_CLEAR: &str = "clear";

// 持久化操作标签常量
const PERSIST_OP_LOAD: &str = "load";
const PERSIST_OP_LOAD_FAILED: &str = "load_failed";
const PERSIST_OP_SAVE: &str = "save";
const PERSIST_OP_SAVE_FAILED: &str = "save_failed";
const PERSIST_OP_SHUTDOWN_SAVE: &str = "shutdown_save";
const PERSIST_OP_SHUTDOWN_SAVE_FAILED: &str = "shutdown_save_failed";
const PERSIST_OP_SHUTDOWN_SAVE_TIMEOUT: &str = "shutdown_save_timeout";

// 可序列化的缓存条目用于持久化
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistableCacheEntry {
    // 原始消息的二进制表示
    message_bytes: Vec<u8>,
    // 过期时间（Unix 时间戳，秒）
    expires_at: u64,
    // 存储时间戳（秒）
    stored_at: u64,
    // 访问次数
    access_count: u64,
    // 最后访问时间（Unix 时间戳，秒）
    last_accessed: u64,
}

// 可序列化的缓存键用于持久化
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
struct PersistableCacheKey {
    // 查询名
    name: String,
    // 查询类型
    record_type: u16,
    // 查询类
    record_class: u16,
    // ECS 网络地址（可选）
    ecs_network: Option<String>,
    // ECS 作用域前缀长度（可选）
    ecs_scope_prefix_length: Option<u8>,
}

// 持久化文件版本信息
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheFileHeader {
    // 标识，用于确认这是一个缓存文件
    magic: String,
    // 版本号，用于检测格式变化
    version: u64,
    // 保存时间戳
    timestamp: u64,
    // 条目数
    entry_count: usize,
}

// 保存到磁盘的缓存项
struct CacheItemForPersistence {
    // 缓存键
    key: CacheKey,
    // 缓存条目
    entry: CacheEntry,
    // 访问次数（从原子计数器提前读取）
    access_count: u64,
    // 最后访问时间（从原子计数器提前读取）
    last_accessed: u64,
}

// 缓存条目
#[derive(Debug, Clone)]
pub struct CacheEntry {
    // DNS 响应消息，使用Arc包装减少克隆成本
    pub message: Arc<Message>,
    // 过期时间（Unix 时间戳，秒）
    pub expires_at: u64,
    // 访问次数，使用原子类型实现无锁更新
    pub access_count: Arc<AtomicU64>,
    // 最后访问时间（Unix 时间戳，秒），使用原子类型实现无锁更新
    pub last_accessed: Arc<AtomicU64>,
    // ECS 数据（可选）
    pub ecs_data: Option<EcsData>,
}

// DNS 响应缓存
pub struct DnsCache {
    // 内部 Moka LRU 缓存
    cache: Cache<CacheKey, CacheEntry>,
    // 缓存配置
    config: CacheConfig,
    // 周期性保存任务取消标记
    periodic_save_cancel: Option<Arc<RwLock<bool>>>,
    // 周期性缓存条目计数任务取消标记
    metrics_task_cancel: Option<Arc<RwLock<bool>>>,
}

// 缓存键
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    // 查询名，使用 Arc 包装减少克隆成本
    pub name: Arc<String>,
    // 查询类型
    pub record_type: u16,
    // 查询类
    pub record_class: u16,
    // ECS 网络地址（可选）
    pub ecs_network: Option<Arc<String>>,
    // ECS 作用域前缀长度（可选）
    pub ecs_scope_prefix_length: Option<u8>,
}

impl CacheKey {
    // 创建新的缓存键
    pub fn new(name: Name, record_type: RecordType, record_class: DNSClass) -> Self {
        // 直接从Name获取内部的utf8字符串，避免to_string()的间接转换开销
        let name_str = name.to_utf8();
        Self {
            name: Arc::new(name_str),
            record_type: record_type.into(),
            record_class: record_class.into(),
            ecs_network: None,
            ecs_scope_prefix_length: None,
        }
    }
    
    // 创建带 ECS 信息的缓存键
    pub fn with_ecs(
        name: Name, 
        record_type: RecordType, 
        record_class: DNSClass,
        ecs_data: &EcsData
    ) -> Self {
        // 预先格式化ECS网络地址，避免重复计算
        // 使用预先估计的容量初始化字符串，避免多次重新分配
        let name_str = name.to_utf8();
        
        // 提前计算网络字符串的大致长度 (IP + '/' + prefix数字)
        let ecs_str_len = ecs_data.address.to_string().len() + 1 + 3;
        let mut network_str = String::with_capacity(ecs_str_len);
        network_str.push_str(&ecs_data.address.to_string());
        network_str.push('/');
        network_str.push_str(&ecs_data.scope_prefix_length.to_string());
        
        Self {
            name: Arc::new(name_str),
            record_type: record_type.into(),
            record_class: record_class.into(),
            ecs_network: Some(Arc::new(network_str)),
            ecs_scope_prefix_length: Some(ecs_data.scope_prefix_length),
        }
    }
    
    // 创建缓存查找键，用于匹配客户端查询
    pub fn create_lookup_key(
        name: Name, 
        record_type: RecordType, 
        record_class: DNSClass,
        client_ecs: Option<&EcsData>
    ) -> Self {
        if let Some(ecs) = client_ecs {
            Self::with_ecs(name, record_type, record_class, ecs)
        } else {
            Self::new(name, record_type, record_class)
        }
    }
    
    // 获取基础键（不包含 ECS 信息）
    pub fn get_base_key(&self) -> Self {
        Self {
            name: Arc::clone(&self.name),
            record_type: self.record_type,
            record_class: self.record_class,
            ecs_network: None,
            ecs_scope_prefix_length: None,
        }
    }
    
    // 判断此键是否与客户端查询匹配（ECS 感知）
    pub fn matches_client_query(&self, query_key: &Self) -> bool {
        // 基本字段必须匹配
        if self.name != query_key.name || 
           self.record_type != query_key.record_type || 
           self.record_class != query_key.record_class {
            return false;
        }
        
        // 处理 ECS 匹配逻辑
        match (&self.ecs_network, &self.ecs_scope_prefix_length, &query_key.ecs_network) {
            // 如果缓存条目没有 ECS 数据（全局应答）
            (None, _, _) => true,
            
            // 如果缓存条目有 ECS 数据，但客户端查询没有
            (Some(_), _, None) => {
                // 只有当范围前缀长度为 0 的时候才匹配（表示适用于所有网络）
                self.ecs_scope_prefix_length == Some(0)
            },
            
            // 如果缓存条目有 ECS 数据，客户端查询也有
            (Some(cached_net_str), Some(cached_scope_prefix), Some(client_net_str)) => {
                // 尝试一次性从字符串中解析所有必要信息
                if let Some((cached_ip, _cached_prefix)) = Self::parse_network_string(cached_net_str) {
                    if let Some((client_ip, client_prefix)) = Self::parse_network_string(client_net_str) {
                        // 进行双向检查
                        
                        // 1. 检查客户端前缀长度是否大于等于缓存范围前缀长度
                        //    (客户端查询的网络范围应该比缓存的作用域更具体或相同)
                        let prefix_check = client_prefix >= *cached_scope_prefix;
                        
                        // 2. 检查客户端网络是否落在缓存作用域内
                        let network_check = self.is_network_contained(
                            client_ip, client_prefix,
                            cached_ip, *cached_scope_prefix
                        );
                        
                        return prefix_check && network_check;
                    }
                }
                
                // 解析失败，使用简化的字符串前缀匹配（退化为原始逻辑）
                debug!("ECS network matching parse failed, using simplified matching: cache={}, query={}", 
                       cached_net_str, client_net_str);
                       
                client_net_str.starts_with(&cached_net_str[..cached_net_str.find('/').unwrap_or(cached_net_str.len())])
            },
            
            // 其他情况不匹配
            _ => false,
        }
    }
    
    // 将网络字符串解析为IP地址和前缀长度
    fn parse_network_string(net_str: &str) -> Option<(IpAddr, u8)> {
        let parts: Vec<&str> = net_str.split('/').collect();
        if parts.len() != 2 {
            return None;
        }
        
        if let Ok(ip) = parts[0].parse::<IpAddr>() {
            if let Ok(prefix) = parts[1].parse::<u8>() {
                return Some((ip, prefix));
            }
        }
        
        None
    }
    
    // 检查一个网络是否包含在另一个网络中
    // client_net 是否包含在 cached_net 中
    fn is_network_contained(
        &self,
        client_ip: IpAddr,
        client_prefix: u8,
        cached_ip: IpAddr,
        cached_scope_prefix: u8
    ) -> bool {
        match (client_ip, cached_ip) {
            // 只有相同类型的 IP 地址才能比较
            (IpAddr::V4(client_ipv4), IpAddr::V4(cached_ipv4)) => {
                // 截断到 cached_scope_prefix 位之后比较
                Self::are_ipv4_networks_equal(
                    client_ipv4, cached_scope_prefix.min(client_prefix),
                    cached_ipv4, cached_scope_prefix
                )
            },
            (IpAddr::V6(client_ipv6), IpAddr::V6(cached_ipv6)) => {
                // 截断到 cached_scope_prefix 位之后比较
                Self::are_ipv6_networks_equal(
                    client_ipv6, cached_scope_prefix.min(client_prefix),
                    cached_ipv6, cached_scope_prefix
                )
            },
            // 不同类型的 IP 地址不匹配
            _ => false,
        }
    }
    
    // 比较两个 IPv4 地址的网络部分是否相等
    fn are_ipv4_networks_equal(ip1: Ipv4Addr, prefix1: u8, ip2: Ipv4Addr, prefix2: u8) -> bool {
        if prefix1 != prefix2 {
            return false;
        }
        
        if prefix1 == 0 {
            return true; // 全局网络总是匹配
        }
        
        // 转换为 u32 并应用掩码
        let ip1_u32 = u32::from(ip1);
        let ip2_u32 = u32::from(ip2);
        
        let mask = if prefix1 >= 32 {
            !0u32 // 所有位都为1
        } else {
            !0u32 << (32 - prefix1)
        };
        
        (ip1_u32 & mask) == (ip2_u32 & mask)
    }
    
    // 比较两个 IPv6 地址的网络部分是否相等
    fn are_ipv6_networks_equal(ip1: Ipv6Addr, prefix1: u8, ip2: Ipv6Addr, prefix2: u8) -> bool {
        if prefix1 != prefix2 {
            return false;
        }
        
        if prefix1 == 0 {
            return true; // 全局网络总是匹配
        }
        
        // 转换为 [u8; 16] 数组并逐字节比较
        let ip1_bytes = ip1.octets();
        let ip2_bytes = ip2.octets();
        
        // 计算需要比较的完整字节数
        let full_bytes = (prefix1 / 8) as usize;
        
        // 比较完整字节
        for i in 0..full_bytes {
            if ip1_bytes[i] != ip2_bytes[i] {
                return false;
            }
        }
        
        // 处理部分字节（如果前缀长度不是8的整数倍）
        let remaining_bits = prefix1 % 8;
        if remaining_bits > 0 && full_bytes < 16 {
            let mask = !0u8 << (8 - remaining_bits);
            if (ip1_bytes[full_bytes] & mask) != (ip2_bytes[full_bytes] & mask) {
                return false;
            }
        }
        
        true
    }
}

impl DnsCache {
    // 创建新的 DNS 缓存
    pub fn new(config: CacheConfig) -> Self {
        // 创建 Moka 缓存，设置最大容量
        let cache = Cache::builder()
            .max_capacity(config.size as u64)
            .time_to_idle(std::time::Duration::from_secs(300)) // 5分钟内未使用的条目将被移除
            .build();
        
        let mut dns_cache = DnsCache { 
            cache, 
            config: config.clone(), 
            periodic_save_cancel: None,
            metrics_task_cancel: None,
        };
        
        // 记录缓存初始状态指标
        METRICS.cache_capacity().set(config.size as i64);
        METRICS.cache_entries().set(0);
        
        // 如果启用了持久化缓存且配置了启动时加载
        if dns_cache.config.persistence.enabled && dns_cache.config.persistence.load_on_startup {
            let config_clone = dns_cache.config.clone();
            let cache_clone = dns_cache.cache.clone();
            
            // 记录加载开始时间
            let load_start = Instant::now();
            
            // 使用阻塞任务加载缓存文件（这是在启动时一次性操作）
            match task::block_in_place(move || {
                Self::load_cache_from_file(&config_clone.persistence)
            }) {
                Ok((keys, entries)) => {
                    // 记录加载持续时间
                    let load_duration = load_start.elapsed();
                    METRICS.cache_persist_operations_total().with_label_values(&[PERSIST_OP_LOAD]).inc();
                    METRICS.cache_persist_duration_seconds().with_label_values(&[PERSIST_OP_LOAD]).observe(load_duration.as_secs_f64());
                    
                    // 将加载的条目导入到缓存
                    let load_fut = async move {
                        let entry_count = entries.len();
                        
                        for (i, (key, entry)) in keys.into_iter().zip(entries.into_iter()).enumerate() {
                            cache_clone.insert(key, entry).await;
                            
                            // 更新缓存条目计数指标
                            if (i + 1) % 1000 == 0 {
                                METRICS.cache_entries().set((i + 1) as i64);
                            }
                            
                            if i > 0 && i % 1000 == 0 {
                                debug!("Loaded {} cache entries so far", i);
                            }
                        }
                        
                        METRICS.cache_entries().set(entry_count as i64);
                        METRICS.cache_operations_total().with_label_values(&[CACHE_OP_INSERT]).inc_by(entry_count as u64);
                        
                        info!("Successfully loaded all cache entries from disk");
                    };
                    
                    // 在后台执行缓存加载
                    tokio::spawn(load_fut);
                }
                Err(e) => {
                    warn!("Failed to load cache from file: {}", e);
                    METRICS.cache_persist_operations_total().with_label_values(&[PERSIST_OP_LOAD_FAILED]).inc();
                }
            }
        }
        
        // 如果启用了持久化缓存并启用了周期性保存
        if dns_cache.config.persistence.enabled && dns_cache.config.persistence.periodic.enabled {
            let config_clone = dns_cache.config.clone();
            let cache_clone = dns_cache.cache.clone();
            let cancel_flag = Arc::new(RwLock::new(false));
            let cancel_flag_clone = cancel_flag.clone();
            
            // 启动周期性保存任务
            tokio::spawn(async move {
                let interval_duration = std::time::Duration::from_secs(
                    config_clone.persistence.periodic.interval_secs
                );
                let mut interval_timer = interval(interval_duration);
                
                // 首次调用 tick() 会立即返回，我们在这里消耗掉它
                // 这样可以确保第一次实际的保存操作会在一个完整的时间间隔之后发生
                interval_timer.tick().await;

                loop {
                    // 等待下一个时间间隔
                    interval_timer.tick().await;
                    
                    // 检查是否应该取消任务
                    if *cancel_flag.read().await {
                        debug!("Periodic cache save task cancelled");
                        break;
                    }
                    
                    // 记录保存开始时间
                    let save_start = Instant::now();
                    
                    match Self::save_cache_to_file(&config_clone.persistence, &cache_clone).await {
                        Ok(saved_count) => {
                            // 记录保存持续时间
                            let save_duration = save_start.elapsed();
                            METRICS.cache_persist_operations_total().with_label_values(&[PERSIST_OP_SAVE]).inc();
                            METRICS.cache_persist_duration_seconds().with_label_values(&[PERSIST_OP_SAVE]).observe(save_duration.as_secs_f64());
                            
                            info!("Periodic cache save completed, {} entries saved", saved_count);
                        }
                        Err(e) => {
                            METRICS.cache_persist_operations_total().with_label_values(&[PERSIST_OP_SAVE_FAILED]).inc();
                            
                            error!("Failed to save cache periodically: {}", e);
                        }
                    }
                }
            });
            
            dns_cache.periodic_save_cancel = Some(cancel_flag_clone);
        }
        
        // 启动周期性缓存条目计数任务
        let metrics_cancel_flag = Arc::new(RwLock::new(false));
        let metrics_cancel_flag_clone = metrics_cancel_flag.clone();
        
        // 克隆缓存对象以避免移动问题
        let cache_clone = dns_cache.cache.clone();
        
        tokio::spawn(async move {
            let interval_duration = std::time::Duration::from_secs(15); // 15秒间隔
            let mut interval_timer = interval(interval_duration);
            
            loop {
                // 等待下一个时间间隔
                interval_timer.tick().await;
                
                // 检查是否应该取消任务
                if *metrics_cancel_flag.read().await {
                    debug!("Periodic cache metrics task cancelled");
                    break;
                }
                
                // 获取缓存条目数并更新指标
                cache_clone.run_pending_tasks().await;
                let cache_size = cache_clone.entry_count();
                METRICS.cache_entries().set(cache_size as i64);
            }
        });
        
        dns_cache.metrics_task_cancel = Some(metrics_cancel_flag_clone);
        
        dns_cache
    }
    
    // 获取当前系统时间（秒）
    #[inline]
    fn get_system_time_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
    
    // 基于客户端 ECS 信息查找缓存条目
    pub async fn get_with_ecs(&self, key: &CacheKey, _client_ecs: Option<&EcsData>) -> Option<Message> {
        // 检查缓存是否启用
        if !self.is_enabled() {
            return None;
        }
        
        // 先检查是否有完全匹配的缓存（包括ECS信息）
        if let Some(entry) = self.cache.get(key).await {
            // 增加访问计数
            entry.access_count.fetch_add(1, Ordering::Relaxed);
            // 更新最后访问时间
            entry.last_accessed.store(Self::get_system_time_secs(), Ordering::Relaxed);
            
            // 检查是否过期
            if Self::get_system_time_secs() <= entry.expires_at {
                // 缓存命中，记录指标
                METRICS
                    .cache_operations_total()
                    .with_label_values(&[CACHE_OP_HIT])
                    .inc();
                    
                debug!("Cache hit for key: {:?}", key);
                return Some(entry.message.as_ref().clone());
            }
        }
        
        // 如果有ECS信息，尝试找基础缓存（无ECS）
        if key.ecs_network.is_some() {
            let base_key = key.get_base_key();
            if let Some(base_entry) = self.cache.get(&base_key).await {
                // 增加访问计数
                base_entry.access_count.fetch_add(1, Ordering::Relaxed);
                // 更新最后访问时间
                base_entry.last_accessed.store(Self::get_system_time_secs(), Ordering::Relaxed);
                
                // 检查是否过期
                if Self::get_system_time_secs() <= base_entry.expires_at {
                    // 尝试使用基础缓存（无ECS）匹配
                    // 只有当消息中没有ECS选项时才使用
                    if base_entry.ecs_data.is_none() {
                        // 缓存命中，记录指标
                        METRICS
                            .cache_operations_total()
                            .with_label_values(&[CACHE_OP_HIT])
                            .inc();
                        
                        debug!("Cache hit for base key (non-ECS): {:?}", base_key);
                        return Some(base_entry.message.as_ref().clone());
                    }
                }
            }
        }
        
        // 缓存未命中
        {
            METRICS.cache_operations_total()
                .with_label_values(&[CACHE_OP_MISS])
                .inc();
        }
        None
    }
    
    // 查找缓存条目
    pub async fn get(&self, key: &CacheKey) -> Option<Message> {
        // 直接调用 get_with_ecs，不带 ECS 信息
        self.get_with_ecs(key, None).await
    }
    
    // 存储缓存条目，支持 ECS
    pub async fn put_with_ecs(&self, key: &CacheKey, message: &Message, ttl: u32, client_ecs: Option<&EcsData>) -> Result<()> {
        // 如果缓存禁用，直接返回
        if !self.is_enabled() {
            return Ok(());
        }
        
        // 当前时间（秒）
        let now = Self::get_system_time_secs();
        
        // 计算过期时间
        let expires_at = now + ttl as u64;
        
        // 创建缓存条目（尽量减少克隆操作）
        let entry = CacheEntry {
            message: Arc::new(message.clone()),
            expires_at,
            access_count: Arc::new(AtomicU64::new(1)),
            last_accessed: Arc::new(AtomicU64::new(now)),
            ecs_data: client_ecs.cloned(),
        };
        
        // 记录缓存插入
        {
            METRICS.cache_operations_total()
                .with_label_values(&[CACHE_OP_INSERT])
                .inc();
        }
        
        // 插入到缓存
        self.cache.insert(key.clone(), entry).await;
        
        Ok(())
    }
    
    // 存储缓存条目
    pub async fn put(&self, key: &CacheKey, message: &Message, ttl: u32) -> Result<()> {
        // 直接调用 put_with_ecs，不带 ECS 信息
        self.put_with_ecs(key, message, ttl, None).await
    }
    
    // 使用自动 TTL 存储缓存条目
    pub async fn put_with_auto_ttl(&self, key: &CacheKey, message: &Message) -> Result<()> {
        let ttl = self.calculate_ttl(message);
        
        // 记录缓存TTL分布
        METRICS.cache_ttl_seconds()
            .with_label_values(&[])
            .observe(ttl as f64);
            
        self.put(key, message, ttl).await
    }
    
    // 使用自动 TTL 存储缓存条目，支持 ECS
    pub async fn put_with_auto_ttl_and_ecs(&self, key: &CacheKey, message: &Message, client_ecs: Option<&EcsData>) -> Result<()> {
        let ttl = self.calculate_ttl(message);
        
        // 记录缓存TTL分布
        METRICS.cache_ttl_seconds()
            .with_label_values(&[])
            .observe(ttl as f64);
            
        self.put_with_ecs(key, message, ttl, client_ecs).await
    }
    
    // 计算缓存条目的 TTL
    pub fn calculate_ttl(&self, message: &Message) -> u32 {
        let mut min_ttl = self.config.ttl.max;
        
        // 遍历所有记录，找出最小的 TTL
        for record in message.answers() {
            // 跳过 OPT 记录
            if record.record_type() == RecordType::OPT {
                continue;
            }
            
            let ttl = record.ttl();
            if ttl < min_ttl {
                min_ttl = ttl;
            }
        }
        
        // 如果没有找到任何记录，使用最小 TTL
        if message.answer_count() == 0 {
            min_ttl = self.config.ttl.min;
        }
        
        // 应用配置的最小/最大 TTL 限制
        min_ttl = min_ttl.max(self.config.ttl.min).min(self.config.ttl.max);
        
        min_ttl
    }
    
    // 获取负缓存TTL
    pub fn negative_ttl(&self) -> u32 {
        self.config.ttl.negative
    }
    
    // 检查缓存是否启用
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }
    
    // 清除所有缓存条目
    pub async fn clear(&self) {
        self.cache.invalidate_all();
        debug!("DNS cache cleared - all entries removed");
        
        // 记录缓存清空
        METRICS.cache_entries().set(0);
        METRICS.cache_operations_total().with_label_values(&[CACHE_OP_CLEAR]).inc();
    }
    
    // 获取当前缓存条目数
    pub async fn len(&self) -> u64 {
        self.cache.run_pending_tasks().await;
        // 要获得准确的条目数，需要运行待处理的任务
        let count = self.cache.entry_count();
        
        // 更新缓存条目计数指标
        METRICS.cache_entries().set(count as i64);
        
        count
    }
    
    // 检查缓存是否为空
    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }
    
    // 保存缓存到文件
    pub async fn save_to_file(&self) -> Result<usize> {
        if !self.config.persistence.enabled {
            return Ok(0);
        }
        
        // 记录保存开始时间
        let save_start = Instant::now();
        
        let result = Self::save_cache_to_file(&self.config.persistence, &self.cache).await;
        
        // 记录保存完成
        match &result {
            Ok(_) => {
                let save_duration = save_start.elapsed();
                METRICS.cache_persist_operations_total().with_label_values(&[PERSIST_OP_SAVE]).inc();
                METRICS.cache_persist_duration_seconds().with_label_values(&[PERSIST_OP_SAVE]).observe(save_duration.as_secs_f64());
            }
            Err(_) => {
                METRICS.cache_persist_operations_total().with_label_values(&[PERSIST_OP_SAVE_FAILED]).inc();
            }
        }
        
        result
    }
    
    // 实际执行缓存保存的内部方法
    async fn save_cache_to_file(
        config: &PersistenceCacheConfig, 
        cache: &Cache<CacheKey, CacheEntry>
    ) -> Result<usize> {
        // 确保目录存在
        if let Some(parent) = Path::new(&config.path).parent() {
            if !parent.exists() {
                if let Err(e) = create_dir_all(parent) {
                    return Err(ServerError::Io(e));
                }
            }
        }
        
        // 使用临时文件路径
        let temp_path = format!("{}.tmp", config.path);
        let cache_path = config.path.clone();
        
        // 获取当前时间戳
        let now = Self::get_system_time_secs();
        
        // 收集所有非过期的缓存项
        let mut all_items = Vec::new();
        
        // 使用快照方式获取所有缓存条目
        let iter = cache.iter();
        for (key, entry) in iter {
            if entry.expires_at > now {  // 只保存未过期的条目
                // 预先获取计数器的值，避免后续多次原子读取
                let access_count = entry.access_count.load(Ordering::Relaxed);
                let last_accessed = entry.last_accessed.load(Ordering::Relaxed);
                
                all_items.push(CacheItemForPersistence {
                    key: (*key).clone(),
                    entry,
                    access_count,
                    last_accessed
                });
            }
        }
        
        // 按访问频率和最近访问时间排序（优先保存最常用和最近使用的条目）
        all_items.sort_by(|a, b| {
            // 先比较访问次数（降序）
            b.access_count.cmp(&a.access_count)
                // 如果访问次数相同，再比较最近访问时间（降序）
                .then_with(|| b.last_accessed.cmp(&a.last_accessed))
        });
        
        // 应用最大保存条目限制
        let save_count = if config.max_items_to_save > 0 {
            config.max_items_to_save.min(all_items.len())
        } else {
            all_items.len()
        };
        
        // 截取需要保存的条目
        if save_count < all_items.len() {
            all_items.truncate(save_count);
        }
        
        // 复制临时路径
        let temp_path_clone = temp_path.clone();
        
        // 在后台线程中执行IO操作
        let saved_count = task::spawn_blocking(move || -> Result<usize> {
            // 准备序列化数据
            let mut persistable_keys = Vec::with_capacity(all_items.len());
            let mut persistable_entries = Vec::with_capacity(all_items.len());
            
            for item in all_items {
                // 将消息序列化为字节
                let message_bytes = match item.entry.message.to_vec() {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        warn!("Failed to serialize message: {}", e);
                        continue;
                    }
                };
                
                // 从缓存键创建可序列化键，需要解引用 Arc 包装的字符串
                let persistable_key = PersistableCacheKey {
                    name: (*item.key.name).clone(),
                    record_type: item.key.record_type,
                    record_class: item.key.record_class,
                    ecs_network: item.key.ecs_network.as_ref().map(|s| (**s).clone()),
                    ecs_scope_prefix_length: item.key.ecs_scope_prefix_length,
                };
                
                let persistable_entry = PersistableCacheEntry {
                    message_bytes,
                    expires_at: item.entry.expires_at,
                    stored_at: now,
                    access_count: item.access_count,
                    last_accessed: item.last_accessed,
                };
                
                persistable_keys.push(persistable_key);
                persistable_entries.push(persistable_entry);
            }
            
            // 打开临时文件用于写入
            let file = File::create(&temp_path_clone)
                .map_err(ServerError::Io)?;
            let mut writer = BufWriter::new(file);
            
            // 写入文件头
            let header = CacheFileHeader {
                magic: CACHE_FILE_MAGIC.to_string(),
                version: CACHE_FILE_VERSION,
                timestamp: now,
                entry_count: persistable_keys.len(),
            };
            
            bincode::serialize_into(&mut writer, &header)
                .map_err(|e| ServerError::Other(format!("Failed to serialize cache header: {}", e)))?;
            
            let entry_count = persistable_entries.len();
            
            bincode::serialize_into(&mut writer, &(persistable_keys, persistable_entries))
                .map_err(|e| ServerError::Other(format!("Failed to serialize cache data: {}", e)))?;
            
            // 确保所有数据都已写入磁盘
            writer.flush().map_err(ServerError::Io)?;
            drop(writer); // 明确 drop writer 以关闭文件，虽然在作用域结束时也会发生

            // 原子地重命名临时文件
            std::fs::rename(&temp_path_clone, &cache_path)
                .map_err(ServerError::Io)?;
            
            Ok(entry_count)
        }).await.map_err(|e| ServerError::Other(format!("Failed to save cache: {}", e)))??;
        
        debug!("Cache saved to file: {}, {} entries", config.path, saved_count);
        Ok(saved_count)
    }
    
    // 从文件加载缓存
    fn load_cache_from_file(
        config: &PersistenceCacheConfig
    ) -> Result<(Vec<CacheKey>, Vec<CacheEntry>)> {
        let path = Path::new(&config.path);
        if !path.exists() {
            debug!("Cache file does not exist: {}", config.path);
            return Ok((Vec::new(), Vec::new()));
        }
        
        // 打开文件
        let file = match File::open(path) {
            Ok(f) => f,
            Err(e) => {
                return Err(ServerError::Io(e));
            }
        };
        
        let mut reader = BufReader::new(file);
        
        // 读取并验证文件头
        let header: CacheFileHeader = match bincode::deserialize_from(&mut reader) {
            Ok(h) => h,
            Err(e) => {
                return Err(ServerError::Other(format!("Failed to deserialize cache header: {}", e)));
            }
        };
        
        // 验证魔数和版本
        if header.magic != CACHE_FILE_MAGIC {
            return Err(ServerError::Other("Invalid cache file format".to_string()));
        }
        
        if header.version != CACHE_FILE_VERSION {
            return Err(ServerError::Other(format!(
                "Unsupported cache file version: {}, expected: {}", 
                header.version, CACHE_FILE_VERSION
            )));
        }
        
        // 获取当前时间
        let now = Self::get_system_time_secs();
        
        // 读取所有缓存条目
        let (persistable_keys, persistable_entries): (
            Vec<PersistableCacheKey>, 
            Vec<PersistableCacheEntry>
        ) = match bincode::deserialize_from(&mut reader) {
            Ok(data) => data,
            Err(e) => {
                return Err(ServerError::Other(format!("Failed to deserialize cache data: {}", e)));
            }
        };
        
        // 转换为内部格式
        let mut keys = Vec::with_capacity(persistable_keys.len());
        let mut entries = Vec::with_capacity(persistable_entries.len());
        
        for (persistable_key, persistable_entry) in persistable_keys.into_iter()
            .zip(persistable_entries.into_iter()) 
        {
            // 检查是否过期
            if config.skip_expired_on_load && persistable_entry.expires_at <= now {
                continue;
            }
            
            // 反序列化消息
            let message = match Message::from_vec(&persistable_entry.message_bytes) {
                Ok(m) => m,
                Err(e) => {
                    warn!("Failed to deserialize message: {}", e);
                    continue;
                }
            };
            
            // 创建缓存键和条目
            let key = CacheKey {
                name: Arc::new(persistable_key.name),
                record_type: persistable_key.record_type,
                record_class: persistable_key.record_class,
                ecs_network: persistable_key.ecs_network.map(Arc::new),
                ecs_scope_prefix_length: persistable_key.ecs_scope_prefix_length,
            };
            
            let entry = CacheEntry {
                message: Arc::new(message),
                expires_at: persistable_entry.expires_at,
                access_count: Arc::new(AtomicU64::new(persistable_entry.access_count)),
                last_accessed: Arc::new(AtomicU64::new(persistable_entry.last_accessed)),
                ecs_data: None,
            };
            
            keys.push(key);
            entries.push(entry);
        }
        
        info!(
            "Loaded {} entries from cache file (out of {} total, {} filtered out)",
            keys.len(),
            header.entry_count,
            header.entry_count - keys.len()
        );
        
        Ok((keys, entries))
    }
    
    // 关闭缓存，执行清理操作
    pub async fn shutdown(&self) -> Result<()> {
        // 取消周期性保存任务
        if let Some(cancel_flag) = &self.periodic_save_cancel {
            let mut flag = cancel_flag.write().await;
            *flag = true;
        }
        
        // 取消周期性缓存条目计数任务
        if let Some(cancel_flag) = &self.metrics_task_cancel {
            let mut flag = cancel_flag.write().await;
            *flag = true;
        }
        
        // 如果持久化缓存功能已启用，保存缓存到文件
        if self.config.persistence.enabled {
            // 使用配置的超时时间
            let timeout_secs = self.config.persistence.shutdown_save_timeout_secs;
            let timeout_duration = std::time::Duration::from_secs(timeout_secs);
            
            // 记录保存开始时间
            let save_start = Instant::now();
            
            match tokio::time::timeout(
                timeout_duration,
                self.save_to_file()
            ).await {
                Ok(result) => {
                    match result {
                        Ok(count) => {
                            let save_duration = save_start.elapsed();
                            METRICS.cache_persist_operations_total().with_label_values(&[PERSIST_OP_SHUTDOWN_SAVE]).inc();
                            METRICS.cache_persist_duration_seconds().with_label_values(&[PERSIST_OP_SHUTDOWN_SAVE]).observe(save_duration.as_secs_f64());
                            
                            info!("Cache saved to file on shutdown, {} entries", count);
                        }
                        Err(e) => {
                            METRICS.cache_persist_operations_total().with_label_values(&[PERSIST_OP_SHUTDOWN_SAVE_FAILED]).inc();
                            
                            error!("Failed to save cache on shutdown: {}", e);
                        }
                    }
                }
                Err(_) => {
                    METRICS.cache_persist_operations_total().with_label_values(&[PERSIST_OP_SHUTDOWN_SAVE_TIMEOUT]).inc();
                    
                    error!("Cache save operation timed out after {} seconds during shutdown", timeout_secs);
                }
            }
        }
        
        Ok(())
    }
}

impl From<&Message> for CacheKey {
    fn from(message: &Message) -> Self {
        // 仅使用第一个查询作为缓存键
        if let Some(query) = message.queries().first() {
            CacheKey {
                name: Arc::new(query.name().to_string()),
                record_type: query.query_type().into(),
                record_class: query.query_class().into(),
                ecs_network: None,
                ecs_scope_prefix_length: None,
            }
        } else {
            // 创建一个空键，实际上不应该发生
            CacheKey {
                name: Arc::new(String::new()),
                record_type: 0,
                record_class: 0,
                ecs_network: None,
                ecs_scope_prefix_length: None,
            }
        }
    }
} 
