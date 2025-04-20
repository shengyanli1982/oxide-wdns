// src/server/cache.rs

use std::time::{SystemTime, UNIX_EPOCH};
use moka::future::Cache;
use trust_dns_proto::op::{Message, ResponseCode};
use trust_dns_proto::rr::RecordType;
use tracing::{debug, trace};
use crate::common::error::Result;
use crate::server::config::CacheConfig;

/// 缓存条目
#[derive(Debug, Clone)]
pub struct CacheEntry {
    /// DNS 响应消息
    pub message: Message,
    /// 过期时间（Unix 时间戳，秒）
    pub expires_at: u64,
}

/// DNS 响应缓存
pub struct DnsCache {
    /// 内部 Moka LRU 缓存
    cache: Cache<CacheKey, CacheEntry>,
    /// 缓存配置
    config: CacheConfig,
}

/// 缓存键
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    /// 查询名
    pub name: String,
    /// 查询类型
    pub record_type: u16,
    /// 查询类
    pub record_class: u16,
}

impl DnsCache {
    /// 创建新的 DNS 缓存
    pub fn new(config: CacheConfig) -> Self {
        // 创建 Moka 缓存，设置最大容量
        let cache = Cache::new(config.size as u64);
        
        DnsCache { cache, config }
    }
    
    /// 查找缓存条目
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
                return Some(entry.message);
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
    
    /// 将 DNS 响应消息存入缓存
    pub async fn put(&self, key: CacheKey, message: Message) -> Result<()> {
        // 检查响应码
        if message.response_code() != ResponseCode::NoError {
            return Ok(());
        }
        
        // 计算 TTL
        let ttl = self.calculate_ttl(&message)?;
        
        // 创建缓存条目
        let entry = CacheEntry {
            message: message.clone(),
            expires_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
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
    
    /// 计算缓存条目的 TTL
    fn calculate_ttl(&self, message: &Message) -> Result<u32> {
        let mut min_ttl = self.config.max_ttl;
        
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
        
        // 应用配置的最小/最大 TTL 限制
        min_ttl = min_ttl.max(self.config.min_ttl).min(self.config.max_ttl);
        
        Ok(min_ttl)
    }
    
    /// 清除所有缓存条目
    pub async fn clear(&self) {
        self.cache.invalidate_all();
        debug!("DNS cache cleared - all entries removed");
    }
    
    /// 获取当前缓存条目数
    pub async fn len(&self) -> u64 {
        self.cache.entry_count()
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
