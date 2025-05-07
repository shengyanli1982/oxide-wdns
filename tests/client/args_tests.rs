// tests/client/args_tests.rs

#[cfg(test)]
mod tests {
    use clap::Parser;
    use oxide_wdns::client::CliArgs;
    use tracing::info;

    #[test]
    fn test_required_args_only() {
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_required_args_only");
        // 测试：只提供必需的参数 (server_url 和 domain)
        let args = CliArgs::parse_from(["owdns-cli", "https://dns.google/dns-query", "example.com"]);
        
        assert_eq!(args.server_url, "https://dns.google/dns-query");
        assert_eq!(args.domain, "example.com");
        assert_eq!(args.record_type, "A"); // 默认记录类型
        assert!(!args.dnssec); // 默认不启用 DNSSEC
        assert!(args.method.is_none()); // 默认自动选择方法
        assert!(!args.insecure); // 默认启用证书验证
        assert_eq!(args.verbose, 0); // 默认不显示详细信息
        info!("Test finished: test_required_args_only");
    }

    #[test]
    fn test_record_type_option() {
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_record_type_option");
        // 测试：指定记录类型
        let args = CliArgs::parse_from([
            "owdns-cli", 
            "https://dns.google/dns-query", 
            "example.com", 
            "--record", "AAAA"
        ]);
        
        assert_eq!(args.record_type, "AAAA");
        info!("Test finished: test_record_type_option");
    }
    
    #[test]
    fn test_dnssec_flag() {
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_dnssec_flag");
        // 测试：启用 DNSSEC
        let args = CliArgs::parse_from([
            "owdns-cli", 
            "https://dns.google/dns-query", 
            "example.com", 
            "--dnssec"
        ]);
        
        assert!(args.dnssec);
        info!("Test finished: test_dnssec_flag");
    }
    
    #[test]
    fn test_format_option() {
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_format_option");
        // 测试：指定 JSON 格式
        let args = CliArgs::parse_from([
            "owdns-cli", 
            "https://dns.google/dns-query", 
            "example.com", 
            "--format", "json"
        ]);
        
        use oxide_wdns::client::args::DohFormat;
        assert!(matches!(args.format, DohFormat::Json));
        info!("Test finished: test_format_option");
    }
    
    #[test]
    fn test_method_option() {
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_method_option");
        // 测试：指定 HTTP 方法
        let args = CliArgs::parse_from([
            "owdns-cli", 
            "https://dns.google/dns-query", 
            "example.com", 
            "--method", "post"
        ]);
        
        use oxide_wdns::client::args::HttpMethod;
        assert!(matches!(args.method, Some(HttpMethod::Post)));
        info!("Test finished: test_method_option");
    }
    
    #[test]
    fn test_verbose_levels() {
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_verbose_levels");
        // 测试：不同详细程度级别
        let args1 = CliArgs::parse_from([
            "owdns-cli", 
            "https://dns.google/dns-query", 
            "example.com", 
            "-v"
        ]);
        assert_eq!(args1.verbose, 1);
        
        let args2 = CliArgs::parse_from([
            "owdns-cli", 
            "https://dns.google/dns-query", 
            "example.com", 
            "-vv"
        ]);
        assert_eq!(args2.verbose, 2);
        
        let args3 = CliArgs::parse_from([
            "owdns-cli", 
            "https://dns.google/dns-query", 
            "example.com", 
            "-vvv"
        ]);
        assert_eq!(args3.verbose, 3);
        info!("Test finished: test_verbose_levels");
    }
    
    #[test]
    fn test_payload_option() {
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_payload_option");
        // 测试：指定原始载荷
        let payload = "0001010000010000000000000377777706676f6f676c6503636f6d0000010001";
        let args = CliArgs::parse_from([
            "owdns-cli", 
            "https://dns.google/dns-query", 
            "example.com", 
            "--payload", payload
        ]);
        
        assert_eq!(args.payload, Some(payload.to_string()));
        info!("Test finished: test_payload_option");
    }
    
    #[test]
    fn test_http_version_option() {
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_http_version_option");
        // 测试：指定 HTTP 版本
        let args = CliArgs::parse_from([
            "owdns-cli", 
            "https://dns.google/dns-query", 
            "example.com", 
            "--http", "http2"
        ]);
        
        use oxide_wdns::client::args::HttpVersion;
        assert!(matches!(args.http_version, Some(HttpVersion::Http2)));
        info!("Test finished: test_http_version_option");
    }
    
    #[test]
    fn test_validate_option() {
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_validate_option");
        // 测试：指定验证条件
        let args = CliArgs::parse_from([
            "owdns-cli", 
            "https://dns.google/dns-query", 
            "example.com", 
            "--validate", "rcode=NOERROR,min-answers=1"
        ]);
        
        assert_eq!(args.validate, Some("rcode=NOERROR,min-answers=1".to_string()));
        info!("Test finished: test_validate_option");
    }
    
    #[test]
    fn test_validate_method() {
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_validate_method");
        // 测试：validate 方法 - 有效 URL
        let args = CliArgs {
            server_url: "https://dns.google/dns-query".to_string(),
            domain: "example.com".to_string(),
            record_type: "A".to_string(),
            format: oxide_wdns::client::args::DohFormat::Wire,
            method: None,
            http_version: None,
            dnssec: false,
            payload: None,
            validate: None,
            insecure: false,
            verbose: 0,
            no_color: false,
        };
        
        let result = args.validate();
        assert!(result.is_ok());
        info!("Test finished: test_validate_method");
    }
    
    #[test]
    fn test_validate_method_invalid_url() {
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_validate_method_invalid_url");
        // 测试：validate 方法 - 非 HTTPS URL
        let args = CliArgs {
            server_url: "http://dns.google/dns-query".to_string(),
            domain: "example.com".to_string(),
            record_type: "A".to_string(),
            format: oxide_wdns::client::args::DohFormat::Wire,
            method: None,
            http_version: None,
            dnssec: false,
            payload: None,
            validate: None,
            insecure: false,
            verbose: 0,
            no_color: false,
        };
        
        let result = args.validate();
        assert!(result.is_err());
        info!("Test finished: test_validate_method_invalid_url");
    }
    
    #[test]
    fn test_validate_method_invalid_payload() {
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_validate_method_invalid_payload");
        // 测试：validate 方法 - 无效载荷 (非十六进制)
        let args = CliArgs {
            server_url: "https://dns.google/dns-query".to_string(),
            domain: "example.com".to_string(),
            record_type: "A".to_string(),
            format: oxide_wdns::client::args::DohFormat::Wire,
            method: None,
            http_version: None,
            dnssec: false,
            payload: Some("GZ".to_string()), // 包含非十六进制字符
            validate: None,
            insecure: false,
            verbose: 0,
            no_color: false,
        };
        
        let result = args.validate();
        assert!(result.is_err());
        info!("Test finished: test_validate_method_invalid_payload");
    }
    
    #[test]
    fn test_validate_method_invalid_record_type() {
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_validate_method_invalid_record_type");
        // 测试：validate 方法 - 无效记录类型
        let args = CliArgs {
            server_url: "https://dns.google/dns-query".to_string(),
            domain: "example.com".to_string(),
            record_type: "INVALID".to_string(),  // 无效的记录类型
            format: oxide_wdns::client::args::DohFormat::Wire,
            method: None,
            http_version: None,
            dnssec: false,
            payload: None,
            validate: None,
            insecure: false,
            verbose: 0,
            no_color: false,
        };
        
        let result = args.validate();
        assert!(result.is_err());
        info!("Test finished: test_validate_method_invalid_record_type");
    }
    
    #[test]
    fn test_validate_method_numeric_record_type() {
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_validate_method_numeric_record_type");
        // 测试：validate 方法 - 数字记录类型
        let args = CliArgs {
            server_url: "https://dns.google/dns-query".to_string(),
            domain: "example.com".to_string(),
            record_type: "28".to_string(),  // AAAA 记录的数字表示
            format: oxide_wdns::client::args::DohFormat::Wire,
            method: None,
            http_version: None,
            dnssec: false,
            payload: None,
            validate: None,
            insecure: false,
            verbose: 0,
            no_color: false,
        };
        
        let result = args.validate();
        assert!(result.is_ok());
        info!("Test finished: test_validate_method_numeric_record_type");
    }
    
    #[test]
    fn test_no_color_flag() {
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_no_color_flag");
        // 测试：禁用彩色输出
        let args = CliArgs::parse_from([
            "owdns-cli", 
            "https://dns.google/dns-query", 
            "example.com", 
            "--no-color"
        ]);
        
        assert!(args.no_color);
        info!("Test finished: test_no_color_flag");
    }
    
    #[test]
    fn test_insecure_flag() {
        let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
        info!("Starting test: test_insecure_flag");
        // 测试：禁用 TLS 证书验证
        let args = CliArgs::parse_from([
            "owdns-cli", 
            "https://dns.google/dns-query", 
            "example.com", 
            "--insecure"
        ]);
        
        assert!(args.insecure);
        
        // 测试 -k 简写
        let args2 = CliArgs::parse_from([
            "owdns-cli", 
            "https://dns.google/dns-query", 
            "example.com", 
            "-k"
        ]);
        
        assert!(args2.insecure);
        info!("Test finished: test_insecure_flag");
    }
} 