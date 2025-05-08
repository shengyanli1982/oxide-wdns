// tests/server/signal_tests.rs

#[cfg(test)]
mod tests {
    use std::time::Duration;
    use std::sync::Arc;
    use std::path::Path;
    use tokio::sync::oneshot;
    use tokio_graceful_shutdown::{Toplevel, SubsystemHandle};
    use tracing::{debug, info};
    use oxide_wdns::server::config::{
        ServerConfig, DnsResolverConfig, HttpServerConfig, CacheConfig,
        UpstreamConfig, ResolverConfig, ResolverProtocol, PersistenceCacheConfig
    };
    use oxide_wdns::server::DoHServer;
    use oxide_wdns::server::cache::{DnsCache, CacheKey};
    use trust_dns_proto::op::{Message, MessageType, OpCode, ResponseCode};
    use trust_dns_proto::rr::{Name, Record, RecordType, RData, DNSClass};
    use anyhow::Result;
    use tempfile::tempdir;

    // 初始化日志系统，用于测试
    fn init_test_logging() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter("debug")
            .try_init();
    }

    // 创建测试配置
    fn create_test_config() -> ServerConfig {
        // 创建一个用于测试的最小配置
        let http = HttpServerConfig::default();
        
        // 创建一个简单的上游配置，使用一个公共 DNS 解析器
        let resolver = ResolverConfig {
            address: "8.8.8.8:53".to_string(),
            protocol: ResolverProtocol::Udp,
        };
        
        let upstream = UpstreamConfig {
            resolvers: vec![resolver],
            enable_dnssec: false,
            query_timeout: 5,
        };
        
        let cache = CacheConfig::default();
        
        let dns = DnsResolverConfig {
            upstream,
            http_client: Default::default(),
            cache,
            routing: Default::default(),
            ecs_policy: Default::default(),
        };
        
        ServerConfig { http, dns }
    }

    // 模拟 owdns_server_subsystem 函数
    async fn mock_owdns_subsystem(
        subsys: SubsystemHandle,
        _config: ServerConfig,
        doh_server: Arc<DoHServer>,
        shutdown_signal: oneshot::Sender<()>,
    ) -> Result<()> {
        info!("Mock OWDNS server started");

        // 构建应用组件但不实际绑定端口
        let (_app_router, dns_cache, _dns_metrics, cache_metrics_handle) =
            doh_server.build_application_components().await?;

        // 等待关闭信号
        tokio::select! {
            _ = subsys.on_shutdown_requested() => {
                info!("Shutdown requested, stopping mock OWDNS server...");
                // 发送信号表示子系统收到关闭请求
                let _ = shutdown_signal.send(());
            }
        };

        // 停止缓存指标任务
        cache_metrics_handle.abort();
        debug!("Cache metrics task aborted.");

        // 关闭 DNS 缓存
        if let Err(e) = dns_cache.shutdown().await {
            info!("Failed to shutdown DNS cache: {}", e);
        } else {
            info!("DNS cache shutdown successfully.");
        }

        info!("Mock OWDNS server shutdown completed");
        Ok(())
    }

    // 测试关闭信号处理
    #[tokio::test]
    async fn test_graceful_shutdown_signal_handling() {
        init_test_logging();
        info!("Starting test: test_graceful_shutdown_signal_handling");

        // 创建测试配置和服务器实例
        let config = create_test_config();
        let doh_server = Arc::new(DoHServer::new(config.clone()));

        // 创建一个通道，用于验证关闭信号是否被处理
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
        
        // 创建一个通道用于模拟发送CTRL+C信号
        let (signal_tx, signal_rx) = oneshot::channel::<()>();
        
        // 使用tokio::spawn启动一个任务，在收到信号后模拟CTRL+C
        tokio::spawn(async move {
            if (signal_rx.await).is_ok() {
                // 模拟CTRL+C信号 - 发送一个信号到当前进程
                info!("模拟发送CTRL+C信号");
                
                #[cfg(target_family = "unix")]
                {
                    use nix::sys::signal::{kill, Signal};
                    use nix::unistd::Pid;
                    let _ = kill(Pid::this(), Signal::SIGINT);
                }
                
                #[cfg(target_family = "windows")]
                {
                    // Windows系统下使用windows-sys发送CTRL+C信号
                    use windows_sys::Win32::System::Console;
                    
                    unsafe {
                        let result = Console::GenerateConsoleCtrlEvent(
                            Console::CTRL_C_EVENT,
                            0
                        );
                        if result == 0 {
                            info!("Failed to send CTRL+C event");
                        }
                    }
                }
            }
        });
        
        // 创建顶级控制器，管理服务器子系统
        let toplevel_handle = tokio::spawn(async move {
            Toplevel::new(move |s| {
                let tx = shutdown_tx;
                let server_clone = doh_server.clone();
                let config_clone = config.clone();
                async move {
                    if let Err(e) = mock_owdns_subsystem(s, config_clone, server_clone, tx).await {
                        info!("Mock OWDNS server subsystem error: {:#}", e);
                    }
                }
            })
            .catch_signals()
            .handle_shutdown_requests(Duration::from_secs(1))
            .await
        });
        
        // 等待服务启动
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        // 发送信号以触发CTRL+C
        let _ = signal_tx.send(());
        
        // 等待顶级控制器完成
        let toplevel_result = match tokio::time::timeout(Duration::from_secs(5), toplevel_handle).await {
            Ok(result) => result.expect("Toplevel task panicked"),
            Err(_) => {
                panic!("Toplevel controller timed out");
            }
        };
        
        // 验证顶级控制器是否正常退出
        assert!(toplevel_result.is_ok(), "Toplevel controller should exit successfully");
        
        // 验证关闭信号是否被接收
        match shutdown_rx.try_recv() {
            Ok(_) => info!("Shutdown signal was properly received"),
            Err(_) => panic!("Shutdown signal was not received"),
        }
        
        info!("Test finished: test_graceful_shutdown_signal_handling");
    }

    // 创建测试 DNS 响应消息
    fn create_test_dns_message(domain: &str, ip: &str) -> Message {
        let mut message = Message::new();
        message.set_message_type(MessageType::Response);
        message.set_op_code(OpCode::Query);
        message.set_response_code(ResponseCode::NoError);
        
        // 创建查询部分
        let name = Name::from_ascii(domain).unwrap();
        let mut query = trust_dns_proto::op::Query::new();
        query.set_name(name.clone());
        query.set_query_type(RecordType::A);
        query.set_query_class(DNSClass::IN);
        message.add_query(query);
        
        // 创建 A 记录
        let mut record = Record::new();
        record.set_name(name);
        record.set_ttl(300); // 5分钟 TTL
        record.set_record_type(RecordType::A);
        record.set_dns_class(DNSClass::IN);
        record.set_data(Some(RData::A(ip.parse().unwrap())));
        
        // 添加到 answers 部分
        message.add_answer(record);
        message
    }

    // 测试缓存在关闭时是否保存到磁盘
    #[tokio::test(flavor = "multi_thread")]
    async fn test_cache_save_on_shutdown() {
        init_test_logging();
        info!("Starting test: test_cache_save_on_shutdown");

        // 创建临时目录用于缓存文件
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let cache_path = temp_dir.path().join("test_cache.bin");
        let cache_path_str = cache_path.to_str().unwrap().to_string();
        
        // 创建带有持久化配置的测试配置
        let mut config = create_test_config();
        
        // 启用缓存和持久化
        config.dns.cache.enabled = true;
        
        // 设置持久化配置
        config.dns.cache.persistence = PersistenceCacheConfig {
            enabled: true,
            path: cache_path_str.clone(),
            load_on_startup: true,
            max_items_to_save: 1000,
            skip_expired_on_load: true,
            shutdown_save_timeout_secs: 5,
            periodic: Default::default(),
        };

        // 创建自定义 DnsCache 并填充一些测试数据
        let dns_cache = Arc::new(DnsCache::new(config.dns.cache.clone()));
        
        // 添加一些测试数据到缓存
        let test_domains = vec![
            ("example.com", "93.184.216.34"),
            ("test.example.org", "192.0.2.1"),
            ("api.example.net", "198.51.100.1"),
        ];
        
        for (domain, ip) in &test_domains {
            let message = create_test_dns_message(domain, ip);
            let key = CacheKey::from(&message);
            dns_cache.put_with_auto_ttl(&key, &message).await.expect("Failed to put item in cache");
        }
        
        // 验证缓存中的项目数
        let cache_size = dns_cache.len().await;
        assert_eq!(cache_size, test_domains.len() as u64, "Cache should contain {} items", test_domains.len());
        
        // 触发关闭并保存缓存
        dns_cache.shutdown().await.expect("Failed to shutdown cache");
        
        // 验证缓存文件是否存在
        assert!(Path::new(&cache_path_str).exists(), "Cache file should exist after shutdown");
        
        // 创建新的缓存实例，加载缓存文件
        let new_cache = Arc::new(DnsCache::new(config.dns.cache.clone()));
        
        // 增加等待时间，确保缓存完全加载完成
        tokio::time::sleep(Duration::from_secs(1)).await;
        
        // 验证新缓存中的项目数量
        let new_cache_size = new_cache.len().await;
        assert_eq!(new_cache_size, test_domains.len() as u64, "Loaded cache should contain {} items", test_domains.len());
        
        // 验证可以从新缓存中检索数据
        for (domain, _) in &test_domains {
            let name = Name::from_ascii(domain).unwrap();
            let key = CacheKey::new(name, RecordType::A, DNSClass::IN);
            let result = new_cache.get(&key).await;
            assert!(result.is_some(), "Should be able to retrieve '{}' from loaded cache", domain);
        }
        
        info!("Test finished: test_cache_save_on_shutdown");
    }
} 