// tests/server/args_tests.rs

#[cfg(test)]
mod tests {
    use assert_cmd::Command;
    use std::fs;
    use predicates::str as predicatesStr;
    use tempfile::NamedTempFile;
    
    // 创建一个临时配置文件
    fn create_temp_config_file() -> NamedTempFile {
        let tmp_file = NamedTempFile::new().expect("Failed to create temp file");
        let config_content = r#"
http_server:
  listen_addr: "127.0.0.1:8053"
  timeout: 10
  rate_limit:
    enabled: true
    per_ip_rate: 50
    per_ip_concurrent: 10
dns_resolver:
  upstream:
    resolvers:
      - address: "8.8.8.8:53"
        protocol: udp
    query_timeout: 3
    enable_dnssec: true
  http_client:
    timeout: 5
    pool:
      idle_timeout: 60
      max_idle_connections: 20
    request:
      user_agent: "oxide-wdns-test/0.1.0"
  cache:
    enabled: true
    size: 1000
    ttl:
      min: 10
      max: 300
      negative: 30
        "#;
        
        fs::write(&tmp_file, config_content).expect("Failed to write temp config file");
        tmp_file
    }
    
    #[test]
    fn test_help_flag() {
        let mut cmd = Command::cargo_bin("owdns").expect("Failed to find binary");
        
        cmd.arg("--help")
            .assert()
            .success()
            .stdout(predicatesStr::contains("High-performance Secure DNS via HTTP (DoH) Gateway"))
            .stdout(predicatesStr::contains("Server configuration file path"));
    }
    
    #[test]
    fn test_version_flag() {
        let mut cmd = Command::cargo_bin("owdns").expect("Failed to find binary");
        
        cmd.arg("--version")
            .assert()
            .success();
    }
    
    #[test]
    fn test_config_flag() {
        let tmp_config = create_temp_config_file();
        let config_path = tmp_config.path().to_str().unwrap();
        
        let mut cmd = Command::cargo_bin("owdns").expect("Failed to find binary");
        
        cmd.arg("--config")
            .arg(config_path)
            .arg("--test")
            .assert()
            .success()
            .stdout(predicatesStr::contains("Configuration test successful"));
    }
    
    #[test]
    fn test_invalid_config_path() {
        let invalid_path = "/path/does/not/exist/config.yml";
        
        let mut cmd = Command::cargo_bin("owdns").expect("Failed to find binary");
        
        cmd.arg("--config")
            .arg(invalid_path)
            .assert()
            .failure()
            .stderr(predicatesStr::contains("Configuration file does not exist"));
    }
    
    #[test]
    fn test_test_config_flag() {
        let tmp_config = create_temp_config_file();
        let config_path = tmp_config.path().to_str().unwrap();
        
        let mut cmd = Command::cargo_bin("owdns").expect("Failed to find binary");
        
        cmd.arg("--config")
            .arg(config_path)
            .arg("--test")
            .assert()
            .success()
            .stdout(predicatesStr::contains("Configuration test successful"));
    }
    
    #[test]
    fn test_debug_flag() {
        let tmp_config = create_temp_config_file();
        let config_path = tmp_config.path().to_str().unwrap();
        
        let mut cmd = Command::cargo_bin("owdns").expect("Failed to find binary");
        
        cmd.arg("--config")
            .arg(config_path)
            .arg("--debug")
            .arg("--test")
            .assert()
            .success()
            .stdout(predicatesStr::contains("Debug logging enabled"));
    }
}
