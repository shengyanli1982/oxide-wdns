// src/server/cache.rs

use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::fs::{File, create_dir_all};
use std::path::Path;
use std::io::{BufReader, BufWriter};
use std::io::Write;
use moka::future::Cache;
use trust_dns_proto::op::{Message, ResponseCode};
use trust_dns_proto::rr::{DNSClass, Name, RecordType};
use tokio::sync::RwLock;
use tokio::time::interval;
use tracing::{debug, trace, warn, error, info};
use serde::{Serialize, Deserialize};
use tokio::task;
use crate::server::error::{Result, ServerError};
use crate::server::config::{CacheConfig, PersistenceCacheConfig};
use crate::common::consts::{CACHE_FILE_MAGIC, CACHE_FILE_VERSION};

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
}

// DNS 响应缓存
pub struct DnsCache {
    // 内部 Moka LRU 缓存
    cache: Cache<CacheKey, CacheEntry>,
    // 缓存配置
    config: CacheConfig,
    // 周期性保存任务取消标记
    periodic_save_cancel: Option<Arc<RwLock<bool>>>,
}

// 缓存键
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    // 查询名
    pub name: String,
    // 查询类型
    pub record_type: u16,
    // 查询类
    pub record_class: u16,
}

impl CacheKey {
    // 创建新的缓存键
    pub fn new(name: Name, record_type: RecordType, record_class: DNSClass) -> Self {
        Self {
            name: name.to_string(),
            record_type: record_type.into(),
            record_class: record_class.into(),
        }
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
        };
        
        // 如果启用了持久化缓存且配置了启动时加载
        if dns_cache.config.persistence.enabled && dns_cache.config.persistence.load_on_startup {
            let config_clone = dns_cache.config.clone();
            let cache_clone = dns_cache.cache.clone();
            // 使用阻塞任务加载缓存文件（这是在启动时一次性操作）
            match task::block_in_place(move || {
                Self::load_cache_from_file(&config_clone.persistence)
            }) {
                Ok((keys, entries)) => {
                    // 将加载的条目导入到缓存
                    let load_fut = async move {
                        for (i, (key, entry)) in keys.into_iter().zip(entries.into_iter()).enumerate() {
                            cache_clone.insert(key, entry).await;
                            if i > 0 && i % 1000 == 0 {
                                debug!("Loaded {} cache entries so far", i);
                            }
                        }
                        info!("Successfully loaded all cache entries from disk");
                    };
                    
                    // 在后台执行缓存加载
                    tokio::spawn(load_fut);
                }
                Err(e) => {
                    warn!("Failed to load cache from file: {}", e);
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
                
                loop {
                    interval_timer.tick().await;
                    
                    // 检查是否应该取消任务
                    if *cancel_flag.read().await {
                        debug!("Periodic cache save task cancelled");
                        break;
                    }
                    
                    match Self::save_cache_to_file(&config_clone.persistence, &cache_clone).await {
                        Ok(saved_count) => {
                            info!("Periodic cache save completed, {} entries saved", saved_count);
                        }
                        Err(e) => {
                            error!("Failed to save cache periodically: {}", e);
                        }
                    }
                }
            });
            
            dns_cache.periodic_save_cancel = Some(cancel_flag_clone);
        }
        
        dns_cache
    }
    
    // 查找缓存条目
    pub async fn get(&self, key: &CacheKey) -> Option<Message> {
        if !self.config.enabled {
            return None;
        }
        
        // 尝试从缓存获取条目
        if let Some(entry) = self.cache.get(key).await {
            // 检查条目是否过期
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
                
            if now < entry.expires_at {
                // 原子地更新访问统计，无需重新插入缓存
                entry.access_count.fetch_add(1, Ordering::Relaxed);
                entry.last_accessed.store(now, Ordering::Relaxed);
                
                trace!(
                    name = ?key.name,
                    type_value = ?key.record_type,
                    expires_in_secs = entry.expires_at - now,
                    "Cache hit for DNS record"
                );
                
                // 克隆响应消息并更新 TTL
                let mut response = (*entry.message).clone();
                
                // 更新响应中的 TTL，使其反映剩余的生存时间
                let remaining_ttl = (entry.expires_at - now) as u32;
                for record in response.answers_mut() {
                    if record.record_type() != RecordType::OPT {
                        record.set_ttl(remaining_ttl);
                    }
                }
                
                return Some(response);
            } else {
                // 惰性删除过期条目
                self.cache.remove(key).await;
                trace!(
                    name = ?key.name,
                    type_value = ?key.record_type,
                    "Expired cache entry removed"
                );
            }
        }
        
        None
    }
    
    // 将 DNS 响应消息存入缓存，指定TTL
    pub async fn put(&self, key: &CacheKey, message: &Message, ttl: u32) -> Result<()> {
        // 如果缓存被禁用，直接返回
        if !self.config.enabled {
            return Ok(());
        }
        
        // 检查缓存大小
        let current_size = self.cache.entry_count();
        if current_size >= self.config.size as u64 {
            warn!(
                current_size = current_size,
                max_size = self.config.size,
                "Cache is full, consider increasing the cache size"
            );
        }
        
        // 创建缓存条目
        let entry = CacheEntry {
            message: Arc::new(message.clone()),
            expires_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                + ttl as u64,
            access_count: Arc::new(AtomicU64::new(1)),
            last_accessed: Arc::new(AtomicU64::new(SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs())),
        };
        
        // 存入缓存
        self.cache.insert(key.clone(), entry).await;
        
        debug!(
            name = ?key.name,
            type_value = ?key.record_type,
            ttl_seconds = ttl,
            response_code = ?message.response_code(),
            "DNS response added to cache"
        );
        
        Ok(())
    }
    
    // 将 DNS 响应消息存入缓存（计算最佳TTL）
    pub async fn put_with_auto_ttl(&self, key: &CacheKey, message: &Message) -> Result<()> {
        // 如果缓存被禁用，直接返回
        if !self.config.enabled {
            return Ok(());
        }
        
        // 检查响应码
        if message.response_code() != ResponseCode::NoError {
            // 对于非成功响应，使用负缓存TTL
            if message.response_code() == ResponseCode::NXDomain {
                let ttl = self.config.ttl.negative;
                self.put(key, message, ttl).await?;
            }
            return Ok(());
        }
        
        // 计算最佳TTL
        let ttl = self.calculate_ttl(message);
        self.put(key, message, ttl).await?;
        
        Ok(())
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
    }
    
    // 获取当前缓存条目数
    pub async fn len(&self) -> u64 {
        self.cache.run_pending_tasks().await;
        // 要获得准确的条目数，需要运行待处理的任务
        self.cache.entry_count()
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
        
        Self::save_cache_to_file(&self.config.persistence, &self.cache).await
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
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        // 提取所有缓存项
        let mut all_items = Vec::new();
        
        // 使用快照方式获取所有缓存条目
        let mut iter = cache.iter();
        while let Some((key, entry)) = iter.next() {
            if entry.expires_at > now {  // 只保存未过期的条目
                all_items.push((key, entry));
            }
        }
        
        // 按访问频率和最近访问时间排序（优先保存最常用和最近使用的条目）
        all_items.sort_by(|a, b| {
            // 先比较访问次数（降序）
            b.1.access_count.load(Ordering::Relaxed).cmp(&a.1.access_count.load(Ordering::Relaxed))
                // 如果访问次数相同，再比较最近访问时间（降序）
                .then_with(|| b.1.last_accessed.load(Ordering::Relaxed).cmp(&a.1.last_accessed.load(Ordering::Relaxed)))
        });
        
        // 应用最大保存条目限制
        let save_count = if config.max_items_to_save > 0 {
            config.max_items_to_save.min(all_items.len())
        } else {
            all_items.len()
        };
        
        // 取排序后最重要的N个条目
        let selected_items = &all_items[0..save_count];
        
        // 提取键和条目
        let mut keys = Vec::new();
        let mut entries = Vec::new();
        
        for (key, entry) in selected_items {
            keys.push(key.clone());
            entries.push(entry.clone());
        }
        
        // 复制临时路径
        let temp_path_clone = temp_path.clone();
        
        // 在后台线程中执行IO操作
        let saved_count = task::spawn_blocking(move || -> Result<usize> {
            // 准备序列化数据
            let mut persistable_keys = Vec::with_capacity(keys.len());
            let mut persistable_entries = Vec::with_capacity(entries.len());
            
            for (key, entry) in keys.into_iter().zip(entries.into_iter()) {
                // 将消息序列化为字节
                let message_bytes = match entry.message.to_vec() {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        warn!("Failed to serialize message: {}", e);
                        continue;
                    }
                };
                
                let persistable_key = PersistableCacheKey {
                    name: key.name.clone(),
                    record_type: key.record_type,
                    record_class: key.record_class,
                };
                
                let persistable_entry = PersistableCacheEntry {
                    message_bytes,
                    expires_at: entry.expires_at,
                    stored_at: now,
                    access_count: entry.access_count.load(Ordering::Relaxed),
                    last_accessed: entry.last_accessed.load(Ordering::Relaxed),
                };
                
                persistable_keys.push(persistable_key);
                persistable_entries.push(persistable_entry);
            }
            
            // 打开临时文件用于写入
            let file = File::create(&temp_path_clone)
                .map_err(|e| ServerError::Io(e))?;
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
            writer.flush().map_err(|e| ServerError::Io(e))?;
            drop(writer); // 明确 drop writer 以关闭文件，虽然在作用域结束时也会发生

            // 原子地重命名临时文件
            std::fs::rename(&temp_path_clone, &cache_path)
                .map_err(|e| ServerError::Io(e))?;
            
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
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
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
                name: persistable_key.name,
                record_type: persistable_key.record_type,
                record_class: persistable_key.record_class,
            };
            
            let entry = CacheEntry {
                message: Arc::new(message),
                expires_at: persistable_entry.expires_at,
                access_count: Arc::new(AtomicU64::new(persistable_entry.access_count)),
                last_accessed: Arc::new(AtomicU64::new(persistable_entry.last_accessed)),
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
        
        // 如果持久化缓存功能已启用，保存缓存到文件
        if self.config.persistence.enabled {
            // 使用配置的超时时间
            let timeout_secs = self.config.persistence.shutdown_save_timeout_secs;
            let timeout_duration = std::time::Duration::from_secs(timeout_secs);
            
            match tokio::time::timeout(
                timeout_duration,
                self.save_to_file()
            ).await {
                Ok(result) => {
                    match result {
                        Ok(count) => {
                            info!("Cache saved to file on shutdown, {} entries", count);
                        }
                        Err(e) => {
                            error!("Failed to save cache on shutdown: {}", e);
                        }
                    }
                }
                Err(_) => {
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
                name: query.name().to_string(),
                record_type: query.query_type().into(),
                record_class: query.query_class().into(),
            }
        } else {
            // 创建一个空键，实际上不应该发生
            CacheKey {
                name: String::new(),
                record_type: 0,
                record_class: 0,
            }
        }
    }
} 
