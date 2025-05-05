// tests/server/routing_tests.rs

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::path::PathBuf;
    use std::fs::File;
    use std::io::Write;
    use std::time::Duration;
    
    use reqwest::Client;
    use tempfile::TempDir;
    use tokio::time::sleep;
    use tracing::info;
    use trust_dns_proto::op::{Message, MessageType, OpCode};
    use trust_dns_proto::rr::{Name, RecordType};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    use wiremock::matchers::{method, path};
    
    use oxide_wdns::server::config::ServerConfig;
    use oxide_wdns::server::routing::{Router, RouteDecision, MatchType};
    use oxide_wdns::common::consts::{CONTENT_TYPE_DNS_MESSAGE, BLACKHOLE_UPSTREAM_GROUP_NAME};
    
    // === 辅助函数 ===
    
    // 创建临时配置文件
    fn create_temp_config_file(content: &str) -> (TempDir, PathBuf) {
        let temp_dir = TempDir::new().expect("Failed to create temporary directory");
        let file_path = temp_dir.path().join("test_routing.yml");
        
        let mut file = File::create(&file_path).expect("Failed to create temporary config file");
        file.write_all(content.as_bytes()).expect("Failed to write config content");
        
        (temp_dir, file_path)
    }
    
    // 创建DNS查询消息
    fn create_test_query(domain: &str, record_type: RecordType) -> Message {
        let name = Name::from_ascii(domain).unwrap();
        let mut query = Message::new();
        query.set_id(1234)
             .set_message_type(MessageType::Query)
             .set_op_code(OpCode::Query)
             .add_query(trust_dns_proto::op::Query::query(name, record_type));
        query
    }
    
    // 创建模拟服务器，返回自定义域名列表
    async fn setup_domain_list_server(domain_list: &str) -> MockServer {
        let mock_server = MockServer::start().await;
        
        Mock::given(method("GET"))
            .and(path("/domains.txt"))
            .respond_with(ResponseTemplate::new(200)
                .set_body_string(domain_list))
            .mount(&mock_server)
            .await;
            
        mock_server
    }
    
    #[tokio::test]
    async fn test_routing_exact_match() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_routing_exact_match");
        
        // 创建包含精确匹配规则的配置
        let config_content = r#"
        dns_resolver:
          routing:
            enabled: true
            upstream_groups:
              - name: "special_group"
                resolvers:
                  - address: "9.9.9.9:53"
                    protocol: udp
            rules:
              - match:
                  type: exact
                  values: ["example.com", "special.test"]
                upstream_group: "special_group"
              - match:
                  type: exact
                  values: ["blocked.test"]
                upstream_group: "__blackhole__"
        "#;
        
        // 创建临时配置文件
        let (_temp_dir, config_path) = create_temp_config_file(config_content);
        
        // 加载配置
        let config = ServerConfig::from_file(&config_path).unwrap();
        
        // 创建Router
        let router = Router::new(config.dns.routing.clone(), Some(Client::new())).await.unwrap();
        
        // 测试匹配特定上游组的域名
        let decision = router.match_domain("example.com").await;
        assert!(matches!(decision, RouteDecision::UseGroup(name) if name == "special_group"), 
                "example.com should match to special_group");
        
        // 测试匹配黑洞组的域名
        let decision = router.match_domain("blocked.test").await;
        assert!(matches!(decision, RouteDecision::Blackhole), 
                "blocked.test should be blackholed");
        
        // 测试不匹配任何规则的域名
        let decision = router.match_domain("random.example.org").await;
        assert!(matches!(decision, RouteDecision::UseGlobal), 
                "random.example.org should use global upstream");
        
        info!("Test completed: test_routing_exact_match");
    }
    
    #[tokio::test]
    async fn test_routing_regex_match() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_routing_regex_match");
        
        // 创建包含正则匹配规则的配置
        let config_content = r#"
        dns_resolver:
          routing:
            enabled: true
            upstream_groups:
              - name: "cn_group"
                resolvers:
                  - address: "114.114.114.114:53"
                    protocol: udp
            rules:
              - match:
                  type: regex
                  values: [".*\\.cn$", ".*\\.com\\.cn$"]
                upstream_group: "cn_group"
        "#;
        
        // 创建临时配置文件
        let (_temp_dir, config_path) = create_temp_config_file(config_content);
        
        // 加载配置
        let config = ServerConfig::from_file(&config_path).unwrap();
        
        // 创建Router
        let router = Router::new(config.dns.routing.clone(), Some(Client::new())).await.unwrap();
        
        // 测试匹配.cn域名
        let decision = router.match_domain("example.cn").await;
        assert!(matches!(decision, RouteDecision::UseGroup(name) if name == "cn_group"), 
                "example.cn should match to cn_group");
        
        // 测试匹配.com.cn域名
        let decision = router.match_domain("example.com.cn").await;
        assert!(matches!(decision, RouteDecision::UseGroup(name) if name == "cn_group"), 
                "example.com.cn should match to cn_group");
        
        // 测试不匹配的域名
        let decision = router.match_domain("example.com").await;
        assert!(matches!(decision, RouteDecision::UseGlobal), 
                "example.com should not match any rules");
        
        info!("Test completed: test_routing_regex_match");
    }
    
    #[tokio::test]
    async fn test_routing_wildcard_match() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_routing_wildcard_match");
        
        // 创建包含通配符匹配规则的配置
        let config_content = r#"
        dns_resolver:
          routing:
            enabled: true
            upstream_groups:
              - name: "eu_group"
                resolvers:
                  - address: "8.8.4.4:53"
                    protocol: udp
            rules:
              - match:
                  type: wildcard
                  values: ["*.eu", "*.co.uk"]
                upstream_group: "eu_group"
        "#;
        
        // 创建临时配置文件
        let (_temp_dir, config_path) = create_temp_config_file(config_content);
        
        // 加载配置
        let config = ServerConfig::from_file(&config_path).unwrap();
        
        // 创建Router
        let router = Router::new(config.dns.routing.clone(), Some(Client::new())).await.unwrap();
        
        // 测试匹配 *.eu 域名
        let decision = router.match_domain("example.eu").await;
        assert!(matches!(decision, RouteDecision::UseGroup(name) if name == "eu_group"), 
                "example.eu should match to eu_group");
        
        // 测试匹配 *.co.uk 域名
        let decision = router.match_domain("example.co.uk").await;
        assert!(matches!(decision, RouteDecision::UseGroup(name) if name == "eu_group"), 
                "example.co.uk should match to eu_group");
        
        // 测试不匹配的域名
        let decision = router.match_domain("example.com").await;
        assert!(matches!(decision, RouteDecision::UseGlobal), 
                "example.com should not match any rules");
        
        info!("Test completed: test_routing_wildcard_match");
    }
    
    #[tokio::test]
    async fn test_routing_file_match() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_routing_file_match");
        
        // 创建一个包含域名列表的临时文件
        let temp_dir = TempDir::new().expect("Failed to create temporary directory");
        let domains_file_path = temp_dir.path().join("domains.txt");
        
        let domains_content = r#"
# 这是注释行
ad-server1.com
ad-server2.com
# 这也是注释
malware.example.net
wildcard:*.malicious.com
regex:evil\d+\.example\.org
"#;
        
        let mut file = File::create(&domains_file_path).expect("Failed to create domains file");
        file.write_all(domains_content.as_bytes()).expect("Failed to write domains content");
        
        // 创建包含文件匹配规则的配置
        let config_content = format!(r#"
        dns_resolver:
          routing:
            enabled: true
            rules:
              - match:
                  type: file
                  path: "{}"
                upstream_group: "__blackhole__"
        "#, domains_file_path.to_str().unwrap().replace("\\", "\\\\"));
        
        // 创建临时配置文件
        let (_temp_dir2, config_path) = create_temp_config_file(&config_content);
        
        // 加载配置
        let config = ServerConfig::from_file(&config_path).unwrap();
        
        // 创建Router
        let router = Router::new(config.dns.routing.clone(), Some(Client::new())).await.unwrap();
        
        // 等待文件加载完成
        sleep(Duration::from_millis(100)).await;
        
        // 测试匹配精确域名
        let decision = router.match_domain("ad-server1.com").await;
        assert!(matches!(decision, RouteDecision::Blackhole), 
                "ad-server1.com should be blackholed");
        
        // 测试匹配通配符域名
        let decision = router.match_domain("sub.malicious.com").await;
        assert!(matches!(decision, RouteDecision::Blackhole), 
                "sub.malicious.com should be blackholed");
        
        // 测试匹配正则域名
        let decision = router.match_domain("evil123.example.org").await;
        assert!(matches!(decision, RouteDecision::Blackhole), 
                "evil123.example.org should be blackholed");
        
        // 测试不匹配的域名
        let decision = router.match_domain("normal-site.com").await;
        assert!(matches!(decision, RouteDecision::UseGlobal), 
                "normal-site.com should not be blackholed");
        
        info!("Test completed: test_routing_file_match");
    }
    
    #[tokio::test]
    async fn test_routing_url_match() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_routing_url_match");
        
        // 创建域名列表内容并设置模拟HTTP服务器
        let domains_content = r#"
# Ad servers to block
adserver.example.com
tracker.example.net

# Malware domains
wildcard:*.malware.test
regex:evil\d+\.example\.biz
"#;
        
        let mock_server = setup_domain_list_server(domains_content).await;
        
        // 创建包含URL匹配规则的配置
        let config_content = format!(r#"
        dns_resolver:
          routing:
            enabled: true
            upstream_groups:
              - name: "secure_dns"
                resolvers:
                  - address: "9.9.9.9:53"
                    protocol: udp
            rules:
              - match:
                  type: url
                  url: "{}/domains.txt"
                upstream_group: "__blackhole__"
        "#, mock_server.uri());
        
        // 创建临时配置文件
        let (_temp_dir, config_path) = create_temp_config_file(&config_content);
        
        // 加载配置
        let config = ServerConfig::from_file(&config_path).unwrap();
        
        // 创建Router
        let router = Router::new(config.dns.routing.clone(), Some(Client::new())).await.unwrap();
        
        // 等待URL规则加载完成
        sleep(Duration::from_millis(500)).await;
        
        // 测试匹配精确域名
        let decision = router.match_domain("adserver.example.com").await;
        assert!(matches!(decision, RouteDecision::Blackhole), 
                "adserver.example.com should be blackholed");
        
        // 测试匹配通配符域名
        let decision = router.match_domain("test.malware.test").await;
        assert!(matches!(decision, RouteDecision::Blackhole), 
                "test.malware.test should be blackholed");
        
        // 测试匹配正则域名
        let decision = router.match_domain("evil123.example.biz").await;
        assert!(matches!(decision, RouteDecision::Blackhole), 
                "evil123.example.biz should be blackholed");
        
        // 测试不匹配的域名
        let decision = router.match_domain("example.com").await;
        assert!(matches!(decision, RouteDecision::UseGlobal), 
                "example.com should not be blackholed");
        
        info!("Test completed: test_routing_url_match");
    }
    
    #[tokio::test]
    async fn test_routing_default_upstream_group() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_routing_default_upstream_group");
        
        // 创建包含默认上游组的配置
        let config_content = r#"
        dns_resolver:
          routing:
            enabled: true
            upstream_groups:
              - name: "default_group"
                resolvers:
                  - address: "1.1.1.1:53"
                    protocol: udp
              - name: "special_group"
                resolvers:
                  - address: "8.8.8.8:53"
                    protocol: udp
            default_upstream_group: "default_group"
            rules:
              - match:
                  type: exact
                  values: ["special.example.com"]
                upstream_group: "special_group"
        "#;
        
        // 创建临时配置文件
        let (_temp_dir, config_path) = create_temp_config_file(config_content);
        
        // 加载配置
        let config = ServerConfig::from_file(&config_path).unwrap();
        
        // 创建Router
        let router = Router::new(config.dns.routing.clone(), Some(Client::new())).await.unwrap();
        
        // 测试匹配特定规则的域名
        let decision = router.match_domain("special.example.com").await;
        assert!(matches!(decision, RouteDecision::UseGroup(name) if name == "special_group"), 
                "special.example.com should match to special_group");
        
        // 测试使用默认上游组的域名
        let decision = router.match_domain("unmatched.example.com").await;
        assert!(matches!(decision, RouteDecision::UseGroup(name) if name == "default_group"), 
                "unmatched.example.com should use default upstream group default_group");
        
        info!("Test completed: test_routing_default_upstream_group");
    }
    
    #[tokio::test]
    async fn test_routing_disabled() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_routing_disabled");
        
        // 创建禁用路由功能的配置
        let config_content = r#"
        dns_resolver:
          routing:
            enabled: false
            upstream_groups:
              - name: "special_group"
                resolvers:
                  - address: "9.9.9.9:53"
                    protocol: udp
            rules:
              - match:
                  type: exact
                  values: ["example.com"]
                upstream_group: "special_group"
        "#;
        
        // 创建临时配置文件
        let (_temp_dir, config_path) = create_temp_config_file(config_content);
        
        // 加载配置
        let config = ServerConfig::from_file(&config_path).unwrap();
        
        // 创建Router
        let router = Router::new(config.dns.routing.clone(), Some(Client::new())).await.unwrap();
        
        // 测试所有域名都使用全局上游(因为路由功能已禁用)
        let decision = router.match_domain("example.com").await;
        assert!(matches!(decision, RouteDecision::UseGlobal), 
                "When routing is disabled, all domains should use global upstream");
        
        info!("Test completed: test_routing_disabled");
    }
    
    #[tokio::test]
    async fn test_routing_rule_order_priority() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_routing_rule_order_priority");
        
        // 创建包含多个规则的配置，测试规则优先级
        let config_content = r#"
        dns_resolver:
          routing:
            enabled: true
            upstream_groups:
              - name: "group1"
                resolvers:
                  - address: "1.1.1.1:53"
                    protocol: udp
              - name: "group2" 
                resolvers:
                  - address: "8.8.8.8:53"
                    protocol: udp
            rules:
              - match:
                  type: exact
                  values: ["test.example.com"]
                upstream_group: "group1"
              - match:
                  type: wildcard
                  values: ["*.example.com"]
                upstream_group: "group2"
        "#;
        
        // 创建临时配置文件
        let (_temp_dir, config_path) = create_temp_config_file(config_content);
        
        // 加载配置
        let config = ServerConfig::from_file(&config_path).unwrap();
        
        // 创建Router
        let router = Router::new(config.dns.routing.clone(), Some(Client::new())).await.unwrap();
        
        // 测试精确匹配规则优先级高于通配符规则
        let decision = router.match_domain("test.example.com").await;
        assert!(matches!(decision, RouteDecision::UseGroup(name) if name == "group1"), 
                "test.example.com should match exact rule first, using group1");
        
        // 测试通配符规则匹配
        let decision = router.match_domain("other.example.com").await;
        assert!(matches!(decision, RouteDecision::UseGroup(name) if name == "group2"), 
                "other.example.com should match wildcard rule, using group2");
        
        info!("Test completed: test_routing_rule_order_priority");
    }
} 