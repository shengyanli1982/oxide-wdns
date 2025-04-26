// src/server/cache.rs

use std::time::{SystemTime, UNIX_EPOCH};
use moka::future::Cache;
use trust_dns_proto::op::{Message, ResponseCode};
use trust_dns_proto::rr::RecordType;
use tracing::{debug, trace, warn};
use crate::common::error::Result;
use crate::server::config::CacheConfig;

// 缓存条目
#[derive(Debug, Clone)]
pub struct CacheEntry {
    // DNS 响应消息
    pub message: Message,
    // 过期时间（Unix 时间戳，秒）
    pub expires_at: u64,
}

// DNS 响应缓存
pub struct DnsCache {
    // 内部 Moka LRU 缓存
    cache: Cache<CacheKey, CacheEntry>,
    // 缓存配置
    config: CacheConfig,
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

impl DnsCache {
    // 创建新的 DNS 缓存
    pub fn new(config: CacheConfig) -> Self {
        // 创建 Moka 缓存，设置最大容量
        let cache = Cache::builder()
            .max_capacity(config.size as u64)
            .time_to_idle(std::time::Duration::from_secs(300)) // 5分钟内未使用的条目将被移除
            .build();
        
        DnsCache { cache, config }
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
                trace!(
                    name = ?key.name,
                    type_value = ?key.record_type,
                    expires_in_secs = entry.expires_at - now,
                    "Cache hit for DNS record"
                );
                
                // 克隆响应消息并更新 TTL
                let mut response = entry.message.clone();
                
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
    
    // 将 DNS 响应消息存入缓存
    pub async fn put(&self, key: CacheKey, message: Message) -> Result<()> {
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
        
        // 检查响应码
        if message.response_code() != ResponseCode::NoError {
            // 对于非成功响应，使用负缓存TTL
            if message.response_code() == ResponseCode::NXDomain {
                let ttl = self.config.ttl.negative;
                
                // 创建缓存条目
                let entry = CacheEntry {
                    message: message.clone(),
                    expires_at: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs()
                        + ttl as u64,
                };
                
                // 存入缓存
                let key_clone = key.clone();
                self.cache.insert(key, entry).await;
                
                debug!(
                    name = ?key_clone.name,
                    type_value = ?key_clone.record_type,
                    ttl_seconds = ttl,
                    "Negative DNS response added to cache"
                );
            }
            return Ok(());
        }
        
        // 计算 TTL
        let ttl = self.calculate_ttl(&message)?;
        
        // 创建缓存条目
        let entry = CacheEntry {
            message: message.clone(),
            expires_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                + ttl as u64,
        };
        
        // 存入缓存
        let key_clone = key.clone();
        self.cache.insert(key, entry).await;
        
        debug!(
            name = ?key_clone.name,
            type_value = ?key_clone.record_type,
            ttl_seconds = ttl,
            "DNS response added to cache"
        );
        
        Ok(())
    }
    
    // 计算缓存条目的 TTL
    fn calculate_ttl(&self, message: &Message) -> Result<u32> {
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
        
        // 如果没有找到任何记录，使用最大 TTL
        if message.answer_count() == 0 {
            min_ttl = self.config.ttl.min;
        }
        
        // 应用配置的最小/最大 TTL 限制
        min_ttl = min_ttl.max(self.config.ttl.min).min(self.config.ttl.max);
        
        Ok(min_ttl)
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
