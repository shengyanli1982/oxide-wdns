// tests/server/cache_tests.rs

#[cfg(test)]
mod tests {
    use oxide_wdns::server::cache::{DnsCache, CacheKey};
    use oxide_wdns::server::config::{CacheConfig, TtlConfig};
    use std::time::Duration;
    use tokio::time::sleep;
    use trust_dns_proto::op::{Message, ResponseCode};
    use trust_dns_proto::rr::{Record, Name, RecordType, RData};

    // === 辅助函数 ===
    
    /// 创建测试用的缓存实例
    fn create_test_cache(size: usize, min_ttl: u32, max_ttl: u32, negative_ttl: u32) -> DnsCache {
        let config = CacheConfig {
            enabled: true,
            size,
            ttl: TtlConfig {
                min: min_ttl,
                max: max_ttl,
                negative: negative_ttl,
            },
        };
        DnsCache::new(config)
    }
    
    /// 创建测试用的缓存键
    fn create_cache_key(name: &str, record_type: u16) -> CacheKey {
        CacheKey {
            name: name.to_string(),
            record_type,
            record_class: 1, // IN 类
        }
    }
    
    /// 创建测试用的DNS响应消息
    fn create_test_message(name: &str, record_type: RecordType, ttl: u32, ip: Option<&str>) -> Message {
        let domain = Name::from_ascii(name).unwrap();
        let mut message = Message::new();
        
        // 设置消息头
        message
            .set_response_code(if ip.is_some() { ResponseCode::NoError } else { ResponseCode::NXDomain })
            .set_message_type(trust_dns_proto::op::MessageType::Response)
            .set_id(1234);
            
        // 添加查询部分
        let query = trust_dns_proto::op::Query::query(domain.clone(), record_type);
        message.add_query(query);
        
        // 如果提供了IP，添加应答记录
        if let Some(ip_str) = ip {
            let rdata = match record_type {
                RecordType::A => {
                    let addr = ip_str.parse().unwrap();
                    RData::A(addr)
                },
                RecordType::AAAA => {
                    let addr = ip_str.parse().unwrap();
                    RData::AAAA(addr)
                },
                _ => panic!("Unsupported record type for test"),
            };
            
            let record = Record::from_rdata(domain, ttl, rdata);
            message.add_answer(record);
        }
        
        message
    }

    #[tokio::test]
    async fn test_cache_store_and_retrieve() {
        // 测试：成功存储一个 DNS 记录并能立即检索到它。
        // 1. 创建缓存实例。
        let cache = create_test_cache(100, 60, 3600, 60);
        
        // 2. 创建一条测试 DNS 记录。
        let key = create_cache_key("example.com", 1); // A记录类型
        let message = create_test_message("example.com", RecordType::A, 300, Some("192.0.2.1"));
        
        // 3. 将记录存入缓存。
        cache.put(key.clone(), message.clone()).await.unwrap();
        
        // 4. 从缓存中检索该记录。
        let retrieved = cache.get(&key).await;
        
        // 5. 断言：检索到的记录与存入的记录相同。
        assert!(retrieved.is_some(), "Record should exist in the cache");
        let retrieved = retrieved.unwrap();
        
        // 检查基本属性
        assert_eq!(retrieved.response_code(), message.response_code());
        assert_eq!(retrieved.answers().len(), message.answers().len());
        
        // 检查答案部分
        if let Some(original_record) = message.answers().first() {
            if let Some(retrieved_record) = retrieved.answers().first() {
                assert_eq!(retrieved_record.name().to_string(), original_record.name().to_string());
                assert_eq!(retrieved_record.record_type(), original_record.record_type());
                assert_eq!(retrieved_record.data(), original_record.data());
                // TTL可能会不同，因为缓存可能调整了TTL值
            }
        }
    }

    #[tokio::test]
    async fn test_cache_miss() {
        // 测试：尝试检索一个不存在于缓存中的记录。
        // 1. 创建缓存实例。
        let cache = create_test_cache(100, 60, 3600, 60);
        
        // 2. 尝试检索一个未存入的域名。
        let key = create_cache_key("nonexistent.example.com", 1);
        let result = cache.get(&key).await;
        
        // 3. 断言：返回 None 或表示未命中的结果。
        assert!(result.is_none(), "Non-existent record should return None");
    }

    #[tokio::test]
    async fn test_cache_ttl_expiration() {
        // 测试：验证缓存条目在 TTL 过期后是否被正确移除或标记为过期。
        // 1. 创建缓存实例，设置较短的 TTL。
        let cache = create_test_cache(100, 1, 2, 1); // 最短1秒，最长2秒的TTL
        
        // 2. 存入一条记录，TTL设为1秒
        let key = create_cache_key("short-lived.example.com", 1);
        let message = create_test_message("short-lived.example.com", RecordType::A, 1, Some("192.0.2.2"));
        cache.put(key.clone(), message).await.unwrap();
        
        // 验证刚存入的记录可以被检索到
        assert!(cache.get(&key).await.is_some(), "The record just inserted should be retrievable");
        
        // 3. 等待超过TTL的时间
        sleep(Duration::from_secs(2)).await;
        
        // 4. 尝试检索该记录
        let result = cache.get(&key).await;
        
        // 5. 断言：记录不再有效或返回None
        assert!(result.is_none(), "Expired record should return None");
    }

    #[tokio::test]
    async fn test_cache_capacity_limit_lru() {
        // 测试：当缓存达到容量上限时，最近最少使用 (LRU) 的条目是否被正确淘汰。
        // 注意：由于moka缓存对LRU的实现可能会有一些不同于传统LRU的特性，
        // 所以在这个测试中，我们主要确保：
        // 1. 当缓存满时，新增记录会导致某些旧记录被淘汰
        // 2. 我们明确访问过的记录（频繁使用的）应该优先保留
        
        // 1. 创建容量为 N 的缓存实例。
        let capacity = 2; // 使用更小的容量，使逻辑更清晰
        let cache = create_test_cache(capacity, 60, 3600, 60);
        
        // 2. 依次存入 N 条不同的记录
        for i in 0..capacity {
            let domain = format!("test{}.example.com", i);
            let key = create_cache_key(&domain, 1);
            let message = create_test_message(&domain, RecordType::A, 300, Some("192.0.2.1"));
            cache.put(key, message).await.unwrap();
        }
        
        // 频繁访问第一条记录，使其成为最近使用的
        let frequent_key = create_cache_key("test0.example.com", 1);
        for _ in 0..3 {
            let _ = cache.get(&frequent_key).await;
        }
        
        // 睡眠一小段时间，确保缓存有时间更新使用频率
        sleep(Duration::from_millis(100)).await;
        
        // 3. 存入第 N+1 条记录，应该会淘汰某条记录，但不应该是最频繁使用的记录
        let new_domain = "testnew.example.com";
        let new_key = create_cache_key(new_domain, 1);
        let new_message = create_test_message(new_domain, RecordType::A, 300, Some("192.0.2.3"));
        cache.put(new_key.clone(), new_message).await.unwrap();
        
        // 检查频繁使用的记录和新存入的记录是否存在
        let frequent_result = cache.get(&frequent_key).await;
        let newest_result = cache.get(&new_key).await;
        
        // 断言：这些记录应该仍然存在
        assert!(frequent_result.is_some(), "Frequently accessed record should still exist");
        assert!(newest_result.is_some(), "The newest record should exist");
        
        // 检查缓存大小是否维持在容量限制内
        assert!(cache.len().await <= capacity as u64, "Cache size should not exceed capacity limit");
    }

    #[tokio::test]
    async fn test_cache_update_entry() {
        // 测试：用新的记录更新缓存中已存在的同名记录。
        // 1. 创建缓存实例。
        let cache = create_test_cache(100, 60, 3600, 60);
        
        // 2. 存入记录 A (域名 X)。
        let key = create_cache_key("update-test.example.com", 1);
        let old_ip = "192.0.2.4";
        let message_a = create_test_message("update-test.example.com", RecordType::A, 300, Some(old_ip));
        cache.put(key.clone(), message_a).await.unwrap();
        
        // 3. 存入记录 B (域名 X，但IP地址不同)。
        let new_ip = "192.0.2.5";
        let message_b = create_test_message("update-test.example.com", RecordType::A, 300, Some(new_ip));
        cache.put(key.clone(), message_b).await.unwrap();
        
        // 4. 检索域名 X 的记录。
        let retrieved = cache.get(&key).await.unwrap();
        
        // 5. 断言：检索到的是记录 B。
        let record = retrieved.answers().first().unwrap();
        if let Some(RData::A(addr)) = record.data() {
            assert_eq!(addr.to_string(), new_ip, "Cache should return updated IP address");
        } else {
            panic!("Should return A record data");
        }
    }

    #[tokio::test]
    async fn test_cache_clear() {
        // 测试：清空缓存功能。
        // 1. 创建缓存实例并存入一些记录。
        let cache = create_test_cache(100, 60, 3600, 60);
        
        // 存入几条记录
        for i in 0..3 {
            let domain = format!("clear-test{}.example.com", i);
            let key = create_cache_key(&domain, 1);
            let message = create_test_message(&domain, RecordType::A, 300, Some("192.0.2.6"));
            cache.put(key, message).await.unwrap();
        }
        
        // 确认缓存中有记录
        let test_key = create_cache_key("clear-test0.example.com", 1);
        assert!(cache.get(&test_key).await.is_some(), "There should be records in the cache");
        
        // 2. 调用清空缓存的方法。
        cache.clear().await;
        
        // 3. 尝试检索之前存入的任何记录。
        let result = cache.get(&test_key).await;
        
        // 4. 断言：所有记录都返回 None。
        assert!(result.is_none(), "There should be no records after clearing the cache");
        
        // 5. 断言缓存大小为 0。
        assert_eq!(cache.len().await, 0, "Cache size should be 0 after clearing");
    }

    #[tokio::test]
    async fn test_cache_entry_ttl_respects_record_ttl() {
        // 测试：缓存条目的 TTL 是否优先尊重记录本身的 TTL (如果记录提供了 TTL)。
        // 1. 创建缓存实例，设置默认 TTL_default。
        let min_ttl = 2;  // 最小TTL为2秒
        let max_ttl = 10; // 最大TTL为10秒
        let cache = create_test_cache(100, min_ttl, max_ttl, 5);
        
        // 2. 创建记录 A，其 TTL_A = 最小TTL
        let key = create_cache_key("ttl-test.example.com", 1);
        let message = create_test_message("ttl-test.example.com", RecordType::A, min_ttl, Some("192.0.2.7"));
        
        // 3. 存入记录 A。
        cache.put(key.clone(), message).await.unwrap();
        
        // 立即检查记录是否存在
        assert!(cache.get(&key).await.is_some(), "The record should be in the cache");
        
        // 4. 等待超过最小TTL但小于最大TTL的时间
        sleep(Duration::from_secs(3)).await; // 等待3秒，超过最小TTL(2秒)
        
        // 5. 检索记录 A。
        let result = cache.get(&key).await;
        
        // 6. 断言：记录 A 已过期。
        assert!(result.is_none(), "The record should have expired");
    }

    #[tokio::test]
    async fn test_cache_disabled() {
        // 测试：当缓存被禁用时，get和put操作的行为
        // 创建缓存配置，禁用缓存
        let config = CacheConfig {
            enabled: false,
            size: 100,
            ttl: TtlConfig {
                min: 60,
                max: 3600,
                negative: 60,
            },
        };
        let cache = DnsCache::new(config);
        
        // 尝试存入一条记录
        let key = create_cache_key("disabled-test.example.com", 1);
        let message = create_test_message("disabled-test.example.com", RecordType::A, 300, Some("192.0.2.8"));
        
        // 存入记录不应该报错，但也不会实际存储
        cache.put(key.clone(), message).await.unwrap();
        
        // 尝试检索该记录，应该返回None
        let result = cache.get(&key).await;
        assert!(result.is_none(), "Should always return None when cache is disabled");
    }

    #[tokio::test]
    async fn test_negative_caching() {
        // 测试：缓存是否正确处理否定响应（NXDOMAIN）
        let negative_ttl = 2; // 否定缓存TTL为2秒
        let cache = create_test_cache(100, 60, 3600, negative_ttl);
        
        // 创建一个NXDOMAIN响应
        let key = create_cache_key("nonexistent.example.org", 1);
        let message = create_test_message("nonexistent.example.org", RecordType::A, 300, None); // 不提供IP表示NXDOMAIN
        
        // 存入否定响应
        cache.put(key.clone(), message).await.unwrap();
        
        // 立即检索，应该能找到否定缓存条目
        let result = cache.get(&key).await;
        assert!(result.is_some(), "Negative response should be cached");
        assert_eq!(result.unwrap().response_code(), ResponseCode::NXDomain);
        
        // 等待超过否定缓存TTL的时间
        sleep(Duration::from_secs(3)).await;
        
        // 再次检索，应该返回None（过期）
        let result = cache.get(&key).await;
        assert!(result.is_none(), "Expired negative cache entry should return None");
    }
} 