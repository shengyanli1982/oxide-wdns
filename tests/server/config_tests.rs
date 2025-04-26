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
    use tracing::info;

    // === 辅助函数 ===
    fn create_temp_config_file(content: &str) -> (TempDir, PathBuf) {
        // 创建临时目录
        let temp_dir = TempDir::new().expect("Failed to create temporary directory");
        
        // 创建唯一文件名
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Failed to get timestamp")
            .as_millis();
        let file_name = format!("test_config_{}.yml", timestamp);
        let file_path = temp_dir.path().join(file_name);
        
        // 创建并写入文件
        let mut file = File::create(&file_path).expect("Failed to create temporary config file");
        file.write_all(content.as_bytes()).expect("Failed to write config content");
        
        // 返回文件路径和临时目录（用于自动清理）
        (temp_dir, file_path)
    }

    #[test]
    fn test_config_load_valid_minimal() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_config_load_valid_minimal");

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
        info!(config_content = %minimal_config, "Defined minimal config content.");

        // 2. 创建一个包含该内容的临时配置文件。
        info!("Creating temporary config file...");
        let (_temp_dir, config_path) = create_temp_config_file(minimal_config);
        info!(config_path = %config_path.display(), "Temporary config file created.");

        // 3. 调用 ServerConfig::from_file 函数加载该文件。
        info!("Loading config from file...");
        let config_result = ServerConfig::from_file(&config_path);
        info!(is_ok = config_result.is_ok(), "Config loading finished.");

        // 4. 断言：成功返回 `Ok(ServerConfig)`。
        assert!(config_result.is_ok(), "Loading a valid minimal config should succeed");
        
        // 5. 断言：ServerConfig 结构体中的字段值与预期一致。
        info!("Validating loaded config values...");
        let config = config_result.unwrap();
        assert_eq!(config.http.listen_addr.to_string(), "127.0.0.1:8053");
        assert_eq!(config.dns.upstream.resolvers.len(), 1);
        assert_eq!(config.dns.upstream.resolvers[0].address, "8.8.8.8:53");
        assert_eq!(config.dns.upstream.resolvers[0].protocol, ResolverProtocol::Udp);
        info!("Config values validated successfully.");
        info!("Test completed: test_config_load_valid_minimal");
    }

    #[test]
    fn test_config_load_valid_full() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_config_load_valid_full");

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
        info!(config_content_len = full_config.len(), "Defined full config content.");

        // 2. 创建临时配置文件。
        info!("Creating temporary config file...");
        let (_temp_dir, config_path) = create_temp_config_file(full_config);
        info!(config_path = %config_path.display(), "Temporary config file created.");
        
        // 3. 加载配置。
        info!("Loading config from file...");
        let config_result = ServerConfig::from_file(&config_path);
        info!(is_ok = config_result.is_ok(), "Config loading finished.");
        
        // 4. 断言：成功返回 `Ok(ServerConfig)`。
        assert!(config_result.is_ok(), "Loading a valid full config should succeed");
        
        // 5. 断言：所有字段的值都正确加载。
        info!("Validating loaded config values...");
        let config = config_result.unwrap();
        
        // HTTP服务器配置
        assert_eq!(config.http.listen_addr.to_string(), "127.0.0.1:8053");
        assert_eq!(config.http.timeout, 30);
        assert!(config.http.rate_limit.enabled);
        assert_eq!(config.http.rate_limit.per_ip_rate, 100);
        assert_eq!(config.http.rate_limit.per_ip_concurrent, 10);
        info!("Validated HTTP server config.");
        
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
        info!("Validated upstream DNS config.");
        
        // HTTP客户端配置
        assert_eq!(config.dns.http_client.timeout, 10);
        assert_eq!(config.dns.http_client.pool.idle_timeout, 60);
        assert_eq!(config.dns.http_client.pool.max_idle_connections, 20);
        assert_eq!(config.dns.http_client.request.user_agent, "Oxide-WDNS/0.1.0");
        assert_eq!(config.dns.http_client.request.ip_header_names.len(), 2);
        assert_eq!(config.dns.http_client.request.ip_header_names[0], "X-Forwarded-For");
        assert_eq!(config.dns.http_client.request.ip_header_names[1], "X-Real-IP");
        info!("Validated HTTP client config.");
        
        // 缓存配置
        assert!(config.dns.cache.enabled);
        assert_eq!(config.dns.cache.size, 10000);
        assert_eq!(config.dns.cache.ttl.min, 60);
        assert_eq!(config.dns.cache.ttl.max, 86400);
        assert_eq!(config.dns.cache.ttl.negative, 300);
        info!("Validated cache config.");
        info!("Config values validated successfully.");
        info!("Test completed: test_config_load_valid_full");
    }

    #[test]
    fn test_config_load_missing_file() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_config_load_missing_file");

        // 测试：尝试加载一个不存在的配置文件。
        // 1. 定义一个不存在的文件路径。
        let non_existent_path = PathBuf::from("/tmp/this_file_should_not_exist_12345.yml");
        info!(path = %non_existent_path.display(), "Defined non-existent config path.");

        // 2. 调用 ServerConfig::from_file 加载该路径。
        info!("Attempting to load config from non-existent file...");
        let config_result = ServerConfig::from_file(&non_existent_path);
        info!(is_err = config_result.is_err(), "Config loading finished.");

        // 3. 断言：返回 `Err`，且错误类型表示文件未找到。
        assert!(config_result.is_err(), "Loading a non-existent file should fail");
        let error = config_result.unwrap_err();
        info!(error = %error, "Received expected error.");
        let error_string = error.to_string();
        assert!(error_string.contains("Failed to read config file") || error_string.contains("No such file or directory"),
                "Error message should indicate failure to read file: '{}'", error_string);
        info!("Validated error message.");
        info!("Test completed: test_config_load_missing_file");
    }

    #[test]
    fn test_config_load_invalid_format_yaml() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_config_load_invalid_format_yaml");

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
        info!(config_content = %invalid_yaml, "Defined invalid YAML config content.");

        // 2. 创建临时配置文件。
        info!("Creating temporary config file with invalid YAML...");
        let (_temp_dir, config_path) = create_temp_config_file(invalid_yaml);
        info!(config_path = %config_path.display(), "Temporary config file created.");

        // 3. 加载配置。
        info!("Attempting to load invalid YAML config from file...");
        let config_result = ServerConfig::from_file(&config_path);
        info!(is_err = config_result.is_err(), "Config loading finished.");

        // 4. 断言：返回 `Err`，且错误类型表示 YAML 解析失败。
        assert!(config_result.is_err(), "Loading invalid YAML format should fail");
        let error = config_result.unwrap_err();
        info!(error = %error, "Received expected error.");
        let error_string = error.to_string();
        assert!(error_string.contains("Invalid config file format") || error_string.contains("Failed to parse"), 
               "Error message should indicate invalid config format or parse failure: '{}'", error_string);
        info!("Validated error message.");
        info!("Test completed: test_config_load_invalid_format_yaml");
    }

    #[test]
    fn test_config_load_invalid_value_type() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_config_load_invalid_value_type");

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
        info!(config_content = %invalid_type_config, "Defined config content with invalid value type.");

        // 2. 创建临时配置文件。
        info!("Creating temporary config file with invalid value type...");
        let (_temp_dir, config_path) = create_temp_config_file(invalid_type_config);
        info!(config_path = %config_path.display(), "Temporary config file created.");

        // 3. 加载配置。
        info!("Attempting to load config with invalid value type from file...");
        let config_result = ServerConfig::from_file(&config_path);
        info!(is_err = config_result.is_err(), "Config loading finished.");

        // 4. 断言：返回 `Err`，且错误类型表示值类型不匹配或反序列化失败。
        assert!(config_result.is_err(), "Loading config with wrong field type should fail");
        let error = config_result.unwrap_err();
        info!(error = %error, "Received expected error.");
        let error_string = error.to_string();
        assert!(error_string.contains("Invalid config file format") || error_string.contains("Failed to parse"),
               "Error message should indicate invalid config format or parse failure: '{}'", error_string);
        info!("Validated error message.");
        info!("Test completed: test_config_load_invalid_value_type");
    }

    #[test]
    fn test_config_missing_required_field() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_config_missing_required_field");

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
        info!(config_content = %missing_field_config, "Defined config content missing required field 'resolvers'.");

        // 2. 创建临时配置文件。
        info!("Creating temporary config file missing required field...");
        let (_temp_dir, config_path) = create_temp_config_file(missing_field_config);
        info!(config_path = %config_path.display(), "Temporary config file created.");

        // 3. 加载配置。
        info!("Attempting to load config missing required field from file...");
        let config_result = ServerConfig::from_file(&config_path);
        info!(is_err = config_result.is_err(), "Config loading finished.");

        // 4. 断言：返回 `Err`，且错误类型表示字段缺失。
        assert!(config_result.is_err(), "Loading config with missing required field should fail");
        let error = config_result.unwrap_err();
        info!(error = %error, "Received expected error.");
        let error_string = error.to_string();
        // 检查 serde 相关的错误信息
        assert!(error_string.contains("missing field `resolvers`") || error_string.contains("Invalid config file format"),
               "Error message should indicate missing field 'resolvers' or invalid format: '{}'", error_string);
        info!("Validated error message.");
        info!("Test completed: test_config_missing_required_field");
    }

    #[test]
    fn test_config_default_values() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_config_default_values");

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
        info!(config_content = %minimal_config, "Defined minimal config for default value test.");

        // 2. 创建临时配置文件并加载。
        info!("Creating temporary config file...");
        let (_temp_dir, config_path) = create_temp_config_file(minimal_config);
        info!(config_path = %config_path.display(), "Temporary config file created.");
        info!("Loading minimal config from file...");
        let config_result = ServerConfig::from_file(&config_path);
        info!(is_ok = config_result.is_ok(), "Config loading finished.");

        // 3. 断言：成功加载。
        assert!(config_result.is_ok(), "Loading minimal config should succeed");
        let config = config_result.unwrap();
        info!(?config, "Config loaded successfully.");

        // 4. 断言：Config 结构体中对应的可选字段具有预期的默认值。
        info!("Validating default values...");

        // HTTP服务器默认值
        assert!(config.http.timeout > 0, "Timeout should have a default value > 0");
        info!(config.http.timeout, "Validated http.timeout default value.");
        // 注意：默认情况下速率限制可能已启用或禁用，这取决于实际实现
        // 这里假设默认禁用，如果实现变化，需要调整断言
        // assert!(!config.http.rate_limit.enabled, "Rate limit should be disabled by default");
        // info!(config.http.rate_limit.enabled, "Validated http.rate_limit.enabled default value.");

        // 上游DNS默认值
        assert!(!config.dns.upstream.enable_dnssec, "DNSSEC should be disabled by default");
        info!(config.dns.upstream.enable_dnssec, "Validated upstream.enable_dnssec default value.");
        assert!(config.dns.upstream.query_timeout > 0, "Query timeout should have a default value > 0");
        info!(config.dns.upstream.query_timeout, "Validated upstream.query_timeout default value.");

        // 缓存默认值
        // 假设默认启用缓存
        assert!(config.dns.cache.enabled, "Cache should be enabled by default");
        info!(config.dns.cache.enabled, "Validated cache.enabled default value.");
        assert_eq!(config.dns.cache.size, DEFAULT_CACHE_SIZE, "Cache size should use the default value");
        info!(config.dns.cache.size, expected = DEFAULT_CACHE_SIZE, "Validated cache.size default value.");
        assert!(config.dns.cache.ttl.min > 0, "Min TTL should have a default value > 0");
        info!(config.dns.cache.ttl.min, "Validated cache.ttl.min default value.");
        assert!(config.dns.cache.ttl.max > 0, "Max TTL should have a default value > 0");
        info!(config.dns.cache.ttl.max, "Validated cache.ttl.max default value.");
        assert!(config.dns.cache.ttl.negative > 0, "Negative cache TTL should have a default value > 0");
        info!(config.dns.cache.ttl.negative, "Validated cache.ttl.negative default value.");

        // HTTP客户端默认值
        assert!(config.dns.http_client.timeout > 0, "HTTP client timeout should have a default value > 0");
        info!(config.dns.http_client.timeout, "Validated http_client.timeout default value.");
        assert!(config.dns.http_client.pool.idle_timeout > 0, "Connection pool idle timeout should have a default value > 0");
        info!(config.dns.http_client.pool.idle_timeout, "Validated http_client.pool.idle_timeout default value.");
        assert!(config.dns.http_client.pool.max_idle_connections > 0, "Max idle connections should have a default value > 0");
        info!(config.dns.http_client.pool.max_idle_connections, "Validated http_client.pool.max_idle_connections default value.");
        assert!(!config.dns.http_client.request.user_agent.is_empty(), "User-Agent should have a non-empty default value");
        info!(config.dns.http_client.request.user_agent, "Validated http_client.request.user_agent default value.");
        assert!(!config.dns.http_client.request.ip_header_names.is_empty(), "IP header names list should have a default value");
        info!(?config.dns.http_client.request.ip_header_names, "Validated http_client.request.ip_header_names default value.");
        info!("Default values validated successfully.");
        info!("Test completed: test_config_default_values");
    }

    #[test]
    fn test_config_validate_upstream_format() {
        // 启用 tracing 日志
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_config_validate_upstream_format");

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
        info!(config_content = %invalid_upstream_config, "Defined config content with invalid DoH upstream address.");

        // 2. 创建临时文件并加载。
        info!("Creating temporary config file...");
        let (_temp_dir, config_path) = create_temp_config_file(invalid_upstream_config);
        info!(config_path = %config_path.display(), "Temporary config file created.");
        info!("Loading config from file...");
        let config_result = ServerConfig::from_file(&config_path);
        info!(is_ok = config_result.is_ok(), "Config loading finished.");

        // 3. 断言：加载成功，但验证失败
        assert!(config_result.is_ok(), "Loading config with invalid upstream address should succeed initially");
        let config = config_result.unwrap();
        info!(?config, "Config loaded successfully (prior to validation).");

        // 4. 调用验证逻辑。
        info!("Calling config.test() for validation...");
        let validation_result = config.test();
        info!(is_err = validation_result.is_err(), "Validation finished.");
        assert!(validation_result.is_err(), "Validation of config with invalid upstream address should fail");
        let error = validation_result.unwrap_err();
        info!(error = %error, "Received expected validation error.");
        let error_string = error.to_string();
        assert!(error_string.contains("DoH resolver address must start with 'https://'"), 
              "Error message should indicate that DoH resolver address must start with https://: '{}'", error_string);
        info!("Validated error message.");
        info!("Test completed: test_config_validate_upstream_format");
    }
} 