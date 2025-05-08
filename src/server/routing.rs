// src/server/routing.rs

use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::sync::Arc;
use lazy_static::lazy_static;
use regex::Regex;
use tokio::sync::RwLock as AsyncRwLock;
use tracing::{error, info};
use reqwest::Client;
use tokio::time::{Duration, interval};

use crate::server::config::{RoutingConfig, MatchType, MatchCondition};
use crate::server::error::{ServerError, Result};
use crate::common::consts::BLACKHOLE_UPSTREAM_GROUP_NAME;
use crate::server::metrics::METRICS;

// 路由决策结果
#[derive(Debug, Clone, PartialEq)]
pub enum RouteDecision {
    // 使用特定上游组
    UseGroup(String),
    // 使用全局上游配置
    UseGlobal,
    // 黑洞（阻止查询）
    Blackhole,
}

// 编译后的规则（经过处理的匹配条件）
#[derive(Debug)]
enum CompiledMatcher {
    // 精确匹配集合
    Exact(HashSet<String>),
    // 正则表达式列表
    Regex(Vec<Regex>),
    // 通配符模式列表
    Wildcard(Vec<WildcardPattern>),
    // 文件规则（包含各种类型）
    File {
        exact: HashSet<String>,
        regex: Vec<Regex>,
        wildcard: Vec<WildcardPattern>,
    },
    // URL规则（包含各种类型，异步更新）
    Url {
        url: String,
        rules: Arc<AsyncRwLock<UrlRules>>,
    },
}

// URL规则容器，用于异步更新
#[derive(Debug, Default)]
struct UrlRules {
    // 精确匹配集合
    exact: HashSet<String>,
    // 正则表达式列表
    regex: Vec<Regex>,
    // 通配符模式列表
    wildcard: Vec<WildcardPattern>,
    // 上次更新时间
    last_updated: Option<std::time::Instant>,
}

// 通配符模式
#[derive(Debug, Clone)]
struct WildcardPattern {
    // 原始模式
    pattern: String,
    // 前缀（如果有）
    prefix: Option<String>,
    // 后缀（如果有）
    suffix: Option<String>,
}

// 编译后的规则
#[derive(Debug)]
struct CompiledRule {
    // 编译后的匹配器
    matcher: CompiledMatcher,
    // 目标上游组名称
    upstream_group: String,
}

// DNS 路由器
pub struct Router {
    // 是否启用
    enabled: bool,
    // 编译后的规则列表
    rules: Vec<CompiledRule>,
    // 默认上游组名称
    default_upstream_group: Option<String>,
    // HTTP客户端（用于URL规则）
    http_client: Option<Client>,
}

impl Router {
    // 创建新的路由器
    pub async fn new(routing_config: RoutingConfig, http_client: Option<Client>) -> Result<Self> {
        // 如果未启用路由，返回一个禁用的路由器
        if !routing_config.enabled {
            return Ok(Self {
                enabled: false,
                rules: Vec::new(),
                default_upstream_group: None,
                http_client: None,
            });
        }
        
        // 编译规则
        let mut compiled_rules = Vec::new();
        for rule in routing_config.rules {
            // 编译匹配条件
            let matcher = Self::compile_matcher(&rule.match_)?;
            
            // 创建编译后的规则
            let compiled_rule = CompiledRule {
                matcher,
                upstream_group: rule.upstream_group,
            };
            
            compiled_rules.push(compiled_rule);
        }
        
        // 创建路由器
        let router = Self {
            enabled: true,
            rules: compiled_rules,
            default_upstream_group: routing_config.default_upstream_group,
            http_client,
        };
        
        // 启动URL规则更新任务
        router.start_url_updater().await;
        
        Ok(router)
    }
    
    // 匹配域名，返回路由决策
    pub async fn match_domain(&self, domain: &str) -> RouteDecision {
        // 如果路由未启用，返回使用全局上游
        if !self.enabled {
            return RouteDecision::UseGlobal;
        }
        
        // 规范化域名（转换为小写，去除尾部的点）
        let domain_lowercase = domain.to_lowercase();
        let domain_normalized = domain_lowercase.trim_end_matches('.');
        
        // 按顺序检查每个规则
        for rule in &self.rules {
            let matches = match &rule.matcher {
                CompiledMatcher::Exact(set) => {
                    set.iter().any(|s| s == domain_normalized)
                },
                
                CompiledMatcher::Regex(patterns) => {
                    patterns.iter().any(|re| re.is_match(domain_normalized))
                },
                
                CompiledMatcher::Wildcard(patterns) => {
                    Self::match_wildcard_patterns(domain_normalized, patterns)
                },
                
                CompiledMatcher::File { exact, regex, wildcard, .. } => {
                    exact.iter().any(|s| s == domain_normalized) ||
                    regex.iter().any(|re| re.is_match(domain_normalized)) ||
                    Self::match_wildcard_patterns(domain_normalized, wildcard)
                },
                
                CompiledMatcher::Url { rules, .. } => {
                    // 读取当前规则
                    let url_rules = rules.read().await;
                    
                    // 检查是否匹配
                    url_rules.exact.iter().any(|s| s == domain_normalized) ||
                    url_rules.regex.iter().any(|re| re.is_match(domain_normalized)) ||
                    Self::match_wildcard_patterns(domain_normalized, &url_rules.wildcard)
                },
            };
            
            // 如果匹配成功
            if matches {
                // 如果是黑洞，返回黑洞决策
                if rule.upstream_group == BLACKHOLE_UPSTREAM_GROUP_NAME {
                    return RouteDecision::Blackhole;
                }
                
                // 否则返回使用特定上游组
                return RouteDecision::UseGroup(rule.upstream_group.clone());
            }
        }
        
        // 如果没有规则匹配，检查默认上游组
        if let Some(default_group) = &self.default_upstream_group {
            return RouteDecision::UseGroup(default_group.clone());
        }
        
        // 没有匹配规则且没有默认组，使用全局上游
        RouteDecision::UseGlobal
    }
    
    // 编译匹配条件
    fn compile_matcher(condition: &MatchCondition) -> Result<CompiledMatcher> {
        match condition.type_ {
            MatchType::Exact => {
                // 获取值列表
                let values = condition.values.as_ref()
                    .ok_or_else(|| ServerError::InvalidRuleFormat("Exact matcher requires values".to_string()))?;
                
                // 创建域名集合（转换为小写）
                let mut domains = HashSet::new();
                for domain in values {
                    domains.insert(domain.to_lowercase().trim_end_matches('.').to_string());
                }
                
                Ok(CompiledMatcher::Exact(domains))
            },
            
            MatchType::Regex => {
                // 获取值列表
                let values = condition.values.as_ref()
                    .ok_or_else(|| ServerError::InvalidRuleFormat("Regex matcher requires values".to_string()))?;
                
                // 编译正则表达式
                let mut patterns = Vec::new();
                for pattern_str in values {
                    match Regex::new(pattern_str) {
                        Ok(re) => patterns.push(re),
                        Err(e) => return Err(ServerError::RegexCompilation(format!(
                            "Failed to compile regex '{}': {}", 
                            pattern_str, e
                        ))),
                    }
                }
                
                Ok(CompiledMatcher::Regex(patterns))
            },
            
            MatchType::Wildcard => {
                // 获取值列表
                let values = condition.values.as_ref()
                    .ok_or_else(|| ServerError::InvalidRuleFormat("Wildcard matcher requires values".to_string()))?;
                
                // 解析通配符模式
                let patterns = values.iter()
                    .map(|p| Self::parse_wildcard_pattern(p))
                    .collect();
                
                Ok(CompiledMatcher::Wildcard(patterns))
            },
            
            MatchType::File => {
                // 获取文件路径
                let path = condition.path.as_ref()
                    .ok_or_else(|| ServerError::InvalidRuleFormat("File matcher requires path".to_string()))?
                    .clone();
                
                // 从文件加载规则
                let (exact, regex, wildcard) = Self::load_rules_from_file(&path)?;
                
                Ok(CompiledMatcher::File {
                    exact,
                    regex,
                    wildcard,
                })
            },
            
            MatchType::Url => {
                // 获取URL
                let url = condition.url.as_ref()
                    .ok_or_else(|| ServerError::InvalidRuleFormat("URL matcher requires url".to_string()))?
                    .clone();
                
                // 创建空的初始规则集
                let rules = Arc::new(AsyncRwLock::new(UrlRules::default()));
                
                Ok(CompiledMatcher::Url {
                    url,
                    rules,
                })
            },
        }
    }
    
    // 从文件加载规则
    fn load_rules_from_file(path: &str) -> Result<(HashSet<String>, Vec<Regex>, Vec<WildcardPattern>)> {
        // 打开文件
        let file = match File::open(path) {
            Ok(f) => f,
            Err(e) => {
                // 记录文件加载失败指标
                METRICS.with(|m| m.record_rule_source_update("file", "failure"));
                METRICS.with(|m| m.record_error("RuleLoadError"));
                
                return Err(ServerError::RuleLoad(format!(
                    "Failed to open rules file '{}': {}", 
                    path, e
                )));
            }
        };
        
        // 创建缓冲读取器
        let reader = BufReader::new(file);
        
        // 初始化规则集合
        let mut exact = HashSet::new();
        let mut regex = Vec::new();
        let mut wildcard = Vec::new();
        
        // 读取行
        for (line_num, line_result) in reader.lines().enumerate() {
            let line = match line_result {
                Ok(l) => l,
                Err(e) => {
                    // 记录文件加载失败指标
                    METRICS.with(|m| m.record_rule_source_update("file", "failure"));
                    METRICS.with(|m| m.record_error("RuleLoadError"));
                    
                    return Err(ServerError::RuleLoad(format!(
                        "Failed to read line {} from file '{}': {}", 
                        line_num + 1, path, e
                    )));
                }
            };
            
            // 处理规则行
            if let Err(e) = Self::process_rule_line(&line, &mut exact, &mut regex, &mut wildcard) {
                // 记录规则解析失败指标
                METRICS.with(|m| m.record_rule_source_update("file", "failure"));
                METRICS.with(|m| m.record_error("InvalidRuleFormat"));
                
                return Err(ServerError::RuleLoad(format!(
                    "Error in file '{}' at line {}: {}", 
                    path, line_num + 1, e
                )));
            }
        }
        
        // 记录文件加载成功指标
        METRICS.with(|m| m.record_rule_source_update("file", "success"));
        
        // 记录上次成功更新时间戳
        let current_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        METRICS.with(|m| m.record_rule_source_last_update_timestamp("file", path, current_timestamp));
        
        info!(
            file = path,
            exact_rules = exact.len(),
            regex_rules = regex.len(),
            wildcard_rules = wildcard.len(),
            "Loaded domain rules from file"
        );
        
        Ok((exact, regex, wildcard))
    }
    
    // 处理规则行
    fn process_rule_line(
        line: &str, 
        exact: &mut HashSet<String>, 
        regex: &mut Vec<Regex>, 
        wildcard: &mut Vec<WildcardPattern>
    ) -> Result<()> {
        // 去除前后空白
        let line = line.trim();
        
        // 忽略空行和注释
        if line.is_empty() || line.starts_with('#') {
            return Ok(());
        }
        
        // 检查特殊前缀
        if let Some(pattern) = line.strip_prefix("regex:") {
            // 提取正则表达式
            let pattern = pattern.trim();
            match Regex::new(pattern) {
                Ok(re) => regex.push(re),
                Err(e) => return Err(ServerError::RegexCompilation(format!(
                    "Failed to compile regex '{}': {}", 
                    pattern, e
                ))),
            }
        } else if let Some(pattern) = line.strip_prefix("wildcard:") {
            // 提取通配符模式
            let pattern = pattern.trim();
            wildcard.push(Self::parse_wildcard_pattern(pattern));
        } else {
            // 默认为精确匹配（转换为小写）
            exact.insert(line.to_lowercase().trim_end_matches('.').to_string());
        }
        
        Ok(())
    }
    
    // 解析通配符模式
    fn parse_wildcard_pattern(pattern: &str) -> WildcardPattern {
        // 去除前后空白，转为小写
        let pattern = pattern.trim().to_lowercase();
        
        // 处理特殊情况：*
        if pattern == "*" {
            return WildcardPattern {
                pattern: "*".to_string(),
                prefix: None,
                suffix: None,
            };
        }
        
        // 处理特殊情况：*.domain.com
        if let Some(suffix) = pattern.strip_prefix("*.") {
            return WildcardPattern {
                pattern: pattern.clone(),
                prefix: None,
                suffix: Some(suffix.to_string()),
            };
        }
        
        // 处理特殊情况：prefix.*
        if pattern.ends_with(".*") {
            let prefix_len = pattern.len() - 2;
            let prefix = pattern[..prefix_len].to_string();
            return WildcardPattern {
                pattern: pattern.clone(),
                prefix: Some(prefix),
                suffix: None,
            };
        }
        
        // 处理一般情况：将*替换为正则表达式
        WildcardPattern {
            pattern,
            prefix: None,
            suffix: None,
        }
    }
    
    // 匹配通配符模式
    fn match_wildcard_patterns(domain: &str, patterns: &[WildcardPattern]) -> bool {
        for pattern in patterns {
            // 全域名通配符
            if pattern.pattern == "*" {
                return true;
            }
            
            // 前缀通配符：*.domain.com
            if let Some(suffix) = &pattern.suffix {
                if domain == suffix || (domain.len() > suffix.len() + 1 && 
                                       domain.ends_with(suffix) && 
                                       domain.as_bytes()[domain.len() - suffix.len() - 1] == b'.') {
                    return true;
                }
            }
            
            // 后缀通配符：prefix.*
            else if let Some(prefix) = &pattern.prefix {
                if domain == prefix || (domain.len() > prefix.len() + 1 && 
                                       domain.starts_with(prefix) && 
                                       domain.as_bytes()[prefix.len()] == b'.') {
                    return true;
                }
            }
            
            // 正则风格的通配符模式（将 * 转换为 .* 进行正则匹配）
            else if let Ok(re) = Self::wildcard_to_regex(&pattern.pattern) {
                if re.is_match(domain) {
                    return true;
                }
            }
        }
        
        false
    }
    
    // 将通配符模式转换为正则表达式
    fn wildcard_to_regex(pattern: &str) -> Result<Regex> {
        lazy_static! {
            static ref SPECIAL_CHARS: Regex = Regex::new(r"[.+^$(){}|\[\]\\]").unwrap();
        }
        
        // 预估结果字符串的大小，为原大小的2倍加上锚点字符的长度
        let mut result = String::with_capacity(pattern.len() * 2 + 2);
        
        // 添加开始锚点
        result.push('^');
        
        // 转义特殊字符并将 * 替换为 .*
        let mut last_pos = 0;
        for mat in SPECIAL_CHARS.find_iter(pattern) {
            // 添加前面未处理的部分
            let start = mat.start();
            if start > last_pos {
                // 检查并处理星号
                for c in pattern[last_pos..start].chars() {
                    if c == '*' {
                        result.push_str(".*");
                    } else {
                        result.push(c);
                    }
                }
            }
            
            // 添加转义字符
            result.push('\\');
            result.push_str(mat.as_str());
            
            last_pos = mat.end();
        }
        
        // 处理剩余部分
        if last_pos < pattern.len() {
            for c in pattern[last_pos..].chars() {
                if c == '*' {
                    result.push_str(".*");
                } else {
                    result.push(c);
                }
            }
        }
        
        // 添加结束锚点
        result.push('$');
        
        // 编译正则表达式
        Regex::new(&result).map_err(|e| ServerError::RegexCompilation(format!(
            "Failed to compile wildcard pattern regex '{}': {}",
            result, e
        )))
    }
    
    // 从URL加载规则
    async fn load_rules_from_url(client: &Client, url: &str) -> Result<(HashSet<String>, Vec<Regex>, Vec<WildcardPattern>)> {
        // 发送 HTTP 请求
        let response = match client.get(url).send().await {
            Ok(resp) => resp,
            Err(e) => {
                // 记录失败指标
                METRICS.with(|m| m.record_error("RuleFetchError"));
                
                return Err(ServerError::RuleFetch(format!(
                    "Failed to fetch rules from URL '{}': {}", 
                    url, e
                )));
            }
        };
        
        // 检查状态码
        if !response.status().is_success() {
            // 记录失败指标
            METRICS.with(|m| m.record_error("RuleFetchError"));
            
            return Err(ServerError::RuleFetch(format!(
                "Failed to fetch rules from URL '{}': HTTP status {}", 
                url, response.status()
            )));
        }
        
        // 获取响应文本
        let text = match response.text().await {
            Ok(t) => t,
            Err(e) => {
                // 记录失败指标
                METRICS.with(|m| m.record_error("RuleFetchError"));
                
                return Err(ServerError::RuleFetch(format!(
                    "Failed to read content from URL '{}': {}", 
                    url, e
                )));
            }
        };
        
        // 初始化规则集合
        let mut exact = HashSet::new();
        let mut regex = Vec::new();
        let mut wildcard = Vec::new();
        
        // 处理每一行
        for (line_num, line) in text.lines().enumerate() {
            // 处理规则行
            if let Err(e) = Self::process_rule_line(line, &mut exact, &mut regex, &mut wildcard) {
                // 记录规则解析失败指标
                METRICS.with(|m| m.record_error("InvalidRuleFormat"));
                
                return Err(ServerError::RuleFetch(format!(
                    "Error in URL '{}' content at line {}: {}", 
                    url, line_num + 1, e
                )));
            }
        }
        
        info!(
            url = url,
            exact_rules = exact.len(),
            regex_rules = regex.len(),
            wildcard_rules = wildcard.len(),
            "Loaded domain rules from URL"
        );
        
        Ok((exact, regex, wildcard))
    }
    
    // 启动URL规则更新任务
    async fn start_url_updater(&self) {
        // 如果没有HTTP客户端，无法更新URL规则
        let Some(client) = &self.http_client else {
            return;
        };
        
        // 收集所有URL规则
        let mut url_rules = Vec::new();
        for rule in &self.rules {
            if let CompiledMatcher::Url { url, rules } = &rule.matcher {
                url_rules.push((url.to_string(), Arc::clone(rules)));
            }
        }
        
        // 如果没有URL规则，无需启动更新任务
        if url_rules.is_empty() {
            return;
        }
        
        // 创建HTTP客户端的克隆
        let client = client.clone();
        
        // 启动更新任务
        tokio::spawn(async move {
            // 创建间隔计时器（每小时更新一次）
            let mut interval = interval(Duration::from_secs(3600));
            
            info!("URL rules updater started - {} URLs", url_rules.len());
            
            // 立即执行第一次更新
            Self::update_url_rules(&client, &url_rules).await;
            
            // 定期更新
            loop {
                interval.tick().await;
                Self::update_url_rules(&client, &url_rules).await;
            }
        });
    }
    
    // 更新URL规则
    async fn update_url_rules(client: &Client, url_rules: &[(String, Arc<AsyncRwLock<UrlRules>>)]) {
        for (url, rules) in url_rules {
            // 尝试更新规则
            match Self::load_rules_from_url(client, url).await {
                Ok((exact, regex, wildcard)) => {
                    // 获取写锁
                    let mut rules_write = rules.write().await;
                    
                    // 更新规则
                    rules_write.exact = exact;
                    rules_write.regex = regex;
                    rules_write.wildcard = wildcard;
                    rules_write.last_updated = Some(std::time::Instant::now());
                    
                    // 记录成功指标
                    METRICS.with(|m| m.record_rule_source_update("url", "success"));
                    
                    // 记录上次成功更新时间戳
                    let current_timestamp = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64;
                    METRICS.with(|m| m.record_rule_source_last_update_timestamp("url", url, current_timestamp));
                    
                    // 记录成功
                    info!(url = url, "Updated rules from URL");
                },
                Err(e) => {
                    // 记录失败指标
                    METRICS.with(|m| m.record_rule_source_update("url", "failure"));
                    METRICS.with(|m| m.record_error("RuleFetchError"));
                    
                    // 记录失败
                    error!(url = url, error = %e, "Failed to update rules from URL");
                }
            }
        }
    }
} 