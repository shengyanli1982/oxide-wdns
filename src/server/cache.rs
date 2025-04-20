// src/server/cache.rs

use moka::future::Cache;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use trust_dns_proto::op::Message;
use trust_dns_proto::rr::Record;
use tracing::{debug, trace};

use crate::common::error::{AppError, Result};
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
                trace!(?key, expires_in = entry.expires_at - now, "缓存命中");
                return Some(entry.message);
            } else {
                // 惰性删除过期条目
                self.cache.remove(key).await;
                trace!(?key, "缓存条目已过期");
            }
        }
        
        None
    }
    
    /// 将响应存入缓存
    pub async fn put(&self, key: CacheKey, message: Message) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }
        
        // 计算 TTL
        let ttl = self.calculate_ttl(&message)?;
        if ttl == 0 {
            // 不缓存 TTL 为 0 的响应
            return Ok(());
        }
        
        // 计算过期时间
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| AppError::Cache(format!("系统时钟错误: {}", e)))?
            .as_secs();
            
        let expires_at = now + u64::from(ttl);
        
        // 创建缓存条目
        let entry = CacheEntry {
            message,
            expires_at,
        };
        
        // 存入缓存
        self.cache.insert(key.clone(), entry).await;
        debug!(?key, ttl, "添加缓存条目");
        
        Ok(())
    }
    
    /// 从 DNS 响应中计算有效的 TTL
    fn calculate_ttl(&self, message: &Message) -> Result<u32> {
        // 对于 NXDOMAIN 和其他错误响应，使用负缓存 TTL
        if !message.response_code().is_success() {
            return Ok(self.config.negative_ttl);
        }
        
        // 找出所有记录中的最小 TTL
        let mut min_ttl = u32::MAX;
        
        // 检查 Answer 部分
        for record in message.answers() {
            min_ttl = min_ttl.min(record.ttl());
        }
        
        // 检查 Authority 部分
        for record in message.name_servers() {
            min_ttl = min_ttl.min(record.ttl());
        }
        
        // 检查 Additional 部分
        for record in message.additionals() {
            // 跳过 OPT 记录
            if record.record_type().is_opt() {
                continue;
            }
            min_ttl = min_ttl.min(record.ttl());
        }
        
        // 如果没有找到任何记录，使用默认的最小 TTL
        if min_ttl == u32::MAX {
            min_ttl = self.config.min_ttl;
        }
        
        // 应用配置的最小/最大 TTL 限制
        min_ttl = min_ttl.max(self.config.min_ttl).min(self.config.max_ttl);
        
        Ok(min_ttl)
    }
    
    /// 清除所有缓存条目
    pub async fn clear(&self) {
        self.cache.invalidate_all().await;
        debug!("清除所有缓存条目");
    }
    
    /// 获取当前缓存条目数
    pub async fn len(&self) -> u64 {
        self.cache.entry_count().await
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