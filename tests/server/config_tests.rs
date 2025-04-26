// tests/server/config_tests.rs

#[cfg(test)]
mod tests {
    use oxide_wdns::server::config::{ServerConfig, ResolverProtocol};
    use oxide_wdns::common::consts::DEFAULT_CACHE_SIZE;
    use std::path::PathBuf;
    use std::fs::File;
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tempfile::TempDir;

    // === 辅助函数 ===
    fn create_temp_config_file(content: &str) -> (TempDir, PathBuf) {
        // 创建临时目录
        let temp_dir = TempDir::new().expect("无法创建临时目录");
        
        // 创建唯一文件名
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("获取时间戳失败")
            .as_millis();
        let file_name = format!("test_config_{}.yml", timestamp);
        let file_path = temp_dir.path().join(file_name);
        
        // 创建并写入文件
        let mut file = File::create(&file_path).expect("无法创建临时配置文件");
        file.write_all(content.as_bytes()).expect("无法写入配置内容");
        
        // 返回文件路径和临时目录（用于自动清理）
        (temp_dir, file_path)
    }

    #[test]
    fn test_config_load_valid_minimal() {
        // 测试：加载一个只包含必需字段的有效配置文件。
        // 1. 定义最小有效配置内容的字符串。
        let minimal_config = r#"
# 最小配置
http_server:
  listen_addr: "127.0.0.1:8053"
dns_resolver:
  upstream:
    resolvers:
      - address: "8.8.8.8:53"
        protocol: udp
"#;

        // 2. 创建一个包含该内容的临时配置文件。
        let (_temp_dir, config_path) = create_temp_config_file(minimal_config);
        
        // 3. 调用 ServerConfig::from_file 函数加载该文件。
        let config_result = ServerConfig::from_file(&config_path);
        
        // 4. 断言：成功返回 `Ok(ServerConfig)`。
        assert!(config_result.is_ok(), "加载有效的最小配置应该成功");
        
        // 5. 断言：ServerConfig 结构体中的字段值与预期一致。
        let config = config_result.unwrap();
        assert_eq!(config.http.listen_addr.to_string(), "127.0.0.1:8053");
        assert_eq!(config.dns.upstream.resolvers.len(), 1);
        assert_eq!(config.dns.upstream.resolvers[0].address, "8.8.8.8:53");
        assert_eq!(config.dns.upstream.resolvers[0].protocol, ResolverProtocol::Udp);
    }

    #[test]
    fn test_config_load_valid_full() {
        // 测试：加载一个包含所有可选字段的有效配置文件。
        // 1. 定义包含所有字段的有效配置内容的字符串。
        let full_config = r#"
# 完整配置
http_server:
  listen_addr: "127.0.0.1:8053"
  timeout: 30
  rate_limit:
    enabled: true
    per_ip_rate: 100
    per_ip_concurrent: 10

dns_resolver:
  upstream:
    resolvers:
      - address: "8.8.8.8:53"
        protocol: udp
      - address: "1.1.1.1:53"
        protocol: tcp
      - address: "9.9.9.9:853"
        protocol: dot
      - address: "https://dns.google/dns-query"
        protocol: doh
    enable_dnssec: true
    query_timeout: 5
  
  http_client:
    timeout: 10
    pool:
      idle_timeout: 60
      max_idle_connections: 20
    request:
      user_agent: "Oxide-WDNS/0.1.0"
      ip_header_names:
        - "X-Forwarded-For"
        - "X-Real-IP"
  
  cache:
    enabled: true
    size: 10000
    ttl:
      min: 60
      max: 86400
      negative: 300
"#;

        // 2. 创建临时配置文件。
        let (_temp_dir, config_path) = create_temp_config_file(full_config);
        
        // 3. 加载配置。
        let config_result = ServerConfig::from_file(&config_path);
        
        // 4. 断言：成功返回 `Ok(ServerConfig)`。
        assert!(config_result.is_ok(), "加载有效的完整配置应该成功");
        
        // 5. 断言：所有字段的值都正确加载。
        let config = config_result.unwrap();
        
        // HTTP服务器配置
        assert_eq!(config.http.listen_addr.to_string(), "127.0.0.1:8053");
        assert_eq!(config.http.timeout, 30);
        assert!(config.http.rate_limit.enabled);
        assert_eq!(config.http.rate_limit.per_ip_rate, 100);
        assert_eq!(config.http.rate_limit.per_ip_concurrent, 10);
        
        // 上游DNS配置
        assert_eq!(config.dns.upstream.resolvers.len(), 4);
        assert_eq!(config.dns.upstream.resolvers[0].address, "8.8.8.8:53");
        assert_eq!(config.dns.upstream.resolvers[0].protocol, ResolverProtocol::Udp);
        assert_eq!(config.dns.upstream.resolvers[1].address, "1.1.1.1:53");
        assert_eq!(config.dns.upstream.resolvers[1].protocol, ResolverProtocol::Tcp);
        assert_eq!(config.dns.upstream.resolvers[2].address, "9.9.9.9:853");
        assert_eq!(config.dns.upstream.resolvers[2].protocol, ResolverProtocol::Dot);
        assert_eq!(config.dns.upstream.resolvers[3].address, "https://dns.google/dns-query");
        assert_eq!(config.dns.upstream.resolvers[3].protocol, ResolverProtocol::Doh);
        assert!(config.dns.upstream.enable_dnssec);
        assert_eq!(config.dns.upstream.query_timeout, 5);
        
        // HTTP客户端配置
        assert_eq!(config.dns.http_client.timeout, 10);
        assert_eq!(config.dns.http_client.pool.idle_timeout, 60);
        assert_eq!(config.dns.http_client.pool.max_idle_connections, 20);
        assert_eq!(config.dns.http_client.request.user_agent, "Oxide-WDNS/0.1.0");
        assert_eq!(config.dns.http_client.request.ip_header_names.len(), 2);
        assert_eq!(config.dns.http_client.request.ip_header_names[0], "X-Forwarded-For");
        assert_eq!(config.dns.http_client.request.ip_header_names[1], "X-Real-IP");
        
        // 缓存配置
        assert!(config.dns.cache.enabled);
        assert_eq!(config.dns.cache.size, 10000);
        assert_eq!(config.dns.cache.ttl.min, 60);
        assert_eq!(config.dns.cache.ttl.max, 86400);
        assert_eq!(config.dns.cache.ttl.negative, 300);
    }

    #[test]
    fn test_config_load_missing_file() {
        // 测试：尝试加载一个不存在的配置文件。
        // 1. 定义一个不存在的文件路径。
        let non_existent_path = PathBuf::from("/tmp/this_file_should_not_exist_12345.yml");
        
        // 2. 调用 ServerConfig::from_file 加载该路径。
        let config_result = ServerConfig::from_file(&non_existent_path);
        
        // 3. 断言：返回 `Err`，且错误类型表示文件未找到。
        assert!(config_result.is_err(), "加载不存在的文件应该失败");
        let error = config_result.unwrap_err().to_string();
        assert!(error.contains("Failed to read config file"), "错误信息应该表明无法读取文件");
    }

    #[test]
    fn test_config_load_invalid_format_yaml() {
        // 测试：加载一个格式无效的 YAML 文件。
        // 1. 定义一个明确包含无效 YAML 语法的字符串。
        let invalid_yaml = r#"
http_server: {
  listen_addr: "127.0.0.1:8053",
  // 这是YAML中的无效语法，注释应该使用#，而不是//
  timeout: 30,
}

dns_resolver:
  upstream:
    resolvers:
      - address: "8.8.8.8:53"
        protocol: udp
"#;

        // 2. 创建临时配置文件。
        let (_temp_dir, config_path) = create_temp_config_file(invalid_yaml);
        
        // 3. 加载配置。
        let config_result = ServerConfig::from_file(&config_path);
        
        // 4. 断言：返回 `Err`，且错误类型表示 YAML 解析失败。
        assert!(config_result.is_err(), "加载格式无效的YAML应该失败");
        let error = config_result.unwrap_err().to_string();
        assert!(error.contains("Invalid config file format") || error.contains("Failed to parse"), 
               "错误信息应该表明配置文件格式无效或解析失败");
    }

    #[test]
    fn test_config_load_invalid_value_type() {
        // 测试：加载一个字段值类型错误的配置文件（例如端口号是字符串）。
        // 1. 定义一个timeout字段为字符串的配置内容。
        let invalid_type_config = r#"
http_server:
  listen_addr: "127.0.0.1:8053"
  timeout: "thirty" # 应该是数字而不是字符串

dns_resolver:
  upstream:
    resolvers:
      - address: "8.8.8.8:53"
        protocol: udp
"#;

        // 2. 创建临时配置文件。
        let (_temp_dir, config_path) = create_temp_config_file(invalid_type_config);
        
        // 3. 加载配置。
        let config_result = ServerConfig::from_file(&config_path);
        
        // 4. 断言：返回 `Err`，且错误类型表示值类型不匹配或反序列化失败。
        assert!(config_result.is_err(), "加载字段类型错误的配置应该失败");
        let error = config_result.unwrap_err().to_string();
        assert!(error.contains("Invalid config file format") || error.contains("Failed to parse"),
               "错误信息应该表明配置文件格式无效或解析失败");
    }

    #[test]
    fn test_config_missing_required_field() {
        // 测试：加载缺少必需字段的配置文件。
        // 1. 定义缺少 resolvers 的配置内容。
        let missing_field_config = r#"
http_server:
  listen_addr: "127.0.0.1:8053"

dns_resolver:
  upstream:
    # 缺少resolvers字段，这是必需的
    enable_dnssec: true
    query_timeout: 5
"#;

        // 2. 创建临时配置文件。
        let (_temp_dir, config_path) = create_temp_config_file(missing_field_config);
        
        // 3. 加载配置并期望失败
        let config_result = ServerConfig::from_file(&config_path);
        
        // 4. 断言：加载应该失败，因为缺少必需字段
        assert!(config_result.is_err(), "缺少必需字段的配置应该加载失败");
        
        // 5. 检查错误消息是否包含对resolvers字段的引用
        let error = config_result.unwrap_err().to_string();
        assert!(error.contains("resolvers") || error.contains("missing field"), 
               "错误信息应该提及缺少必需字段'resolvers'");
    }

    #[test]
    fn test_config_default_values() {
        // 测试：对于可选字段，如果不提供，是否正确应用了默认值。
        // 1. 定义只包含必需字段的配置内容。
        let minimal_config = r#"
# 最小配置，所有可选字段都使用默认值
http_server:
  listen_addr: "127.0.0.1:8053"
dns_resolver:
  upstream:
    resolvers:
      - address: "8.8.8.8:53"
        protocol: udp
"#;

        // 2. 创建临时配置文件并加载。
        let (_temp_dir, config_path) = create_temp_config_file(minimal_config);
        let config_result = ServerConfig::from_file(&config_path);
        
        // 3. 断言：成功加载。
        assert!(config_result.is_ok(), "加载最小配置应该成功");
        let config = config_result.unwrap();
        
        // 4. 断言：Config 结构体中对应的可选字段具有预期的默认值。
        
        // HTTP服务器默认值
        assert!(config.http.timeout > 0, "超时应该有默认值");
        // 注意：默认情况下速率限制可能已启用或禁用，这取决于实际实现
        
        // 上游DNS默认值
        assert!(!config.dns.upstream.enable_dnssec, "默认应该禁用DNSSEC");
        assert!(config.dns.upstream.query_timeout > 0, "查询超时应该有默认值");
        
        // 缓存默认值
        assert!(config.dns.cache.enabled, "默认应该启用缓存");
        assert_eq!(config.dns.cache.size, DEFAULT_CACHE_SIZE, "缓存大小应该使用默认值");
        assert!(config.dns.cache.ttl.min > 0, "最小TTL应该有默认值");
        assert!(config.dns.cache.ttl.max > 0, "最大TTL应该有默认值");
        assert!(config.dns.cache.ttl.negative > 0, "负缓存TTL应该有默认值");
        
        // HTTP客户端默认值
        assert!(config.dns.http_client.timeout > 0, "HTTP客户端超时应该有默认值");
        assert!(config.dns.http_client.pool.idle_timeout > 0, "连接池空闲超时应该有默认值");
        assert!(config.dns.http_client.pool.max_idle_connections > 0, "最大空闲连接数应该有默认值");
        assert!(!config.dns.http_client.request.user_agent.is_empty(), "User-Agent应该有默认值");
        assert!(!config.dns.http_client.request.ip_header_names.is_empty(), "IP头字段名列表应该有默认值");
    }

    #[test]
    fn test_config_validate_upstream_format() {
        // 测试：加载包含格式错误的上游服务器地址的配置。
        // 1. 定义包含无效上游地址（DoH地址不是https://开头）的配置。
        let invalid_upstream_config = r#"
http_server:
  listen_addr: "127.0.0.1:8053"
dns_resolver:
  upstream:
    resolvers:
      - address: "http://dns.google/dns-query" # 应该是https://
        protocol: doh
"#;

        // 2. 创建临时文件并加载。
        let (_temp_dir, config_path) = create_temp_config_file(invalid_upstream_config);
        let config_result = ServerConfig::from_file(&config_path);
        
        // 3. 断言：加载成功，但验证失败
        assert!(config_result.is_ok(), "加载包含无效上游地址的配置应该成功");
        let config = config_result.unwrap();
        
        let validation_result = config.test();
        assert!(validation_result.is_err(), "验证包含无效上游地址的配置应该失败");
        let error = validation_result.unwrap_err().to_string();
        assert!(error.contains("DoH resolver address must start with 'https://'"), 
              "错误信息应该表明DoH解析器地址必须以https://开头");
    }
} 