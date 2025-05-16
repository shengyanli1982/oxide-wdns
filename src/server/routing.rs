// src/server/routing.rs

use std::collections::{HashMap, HashSet, BTreeMap};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::sync::Arc;
use lazy_static::lazy_static;
use regex::Regex;
use tokio::sync::RwLock as AsyncRwLock;
use tracing::{debug, error, info, warn};
use reqwest::Client;
use tokio::time::{Duration, interval};
use xxhash_rust::xxh64::xxh64;

use crate::server::config::{RoutingConfig, MatchType};
use crate::server::error::{ServerError, Result};
use crate::common::consts::{
    BLACKHOLE_UPSTREAM_GROUP_NAME,
};
use crate::server::metrics::METRICS;

// 规则类型标签值
const ROUTE_RULE_TYPE_EXACT: &str = "exact";
const ROUTE_RULE_TYPE_REGEX: &str = "regex";
const ROUTE_RULE_TYPE_WILDCARD: &str = "wildcard";
const ROUTE_RULE_TYPE_FILE: &str = "file";
const ROUTE_RULE_TYPE_URL: &str = "url";

// 路由结果类型标签值
const ROUTE_RESULT_DISABLED: &str = "disabled";
const ROUTE_RESULT_BLACKHOLE: &str = "blackhole";
const ROUTE_RESULT_RULE_MATCH: &str = "rule_match";
const ROUTE_RESULT_DEFAULT: &str = "default";
const ROUTE_RESULT_GLOBAL: &str = "global";

// URL规则更新相关常量
const URL_RULE_UPDATE_STATUS_SUCCESS: &str = "success";
const URL_RULE_UPDATE_STATUS_FAILED: &str = "failed";
const URL_RULE_UPDATE_STATUS_UNCHANGED: &str = "unchanged";

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

// 优化的路由引擎核心数据结构
struct RouterCore {
    // 精确匹配规则 - 域名 -> (上游组名)
    exact_rules: HashMap<String, String>,
    
    // 通配符匹配规则 - 反转后缀 -> (上游组名, 模式)
    wildcard_rules: BTreeMap<String, (String, String)>,
    
    // 全局通配符规则 (*) -> (上游组名)
    global_wildcard: Option<String>,
    
    // 正则表达式规则 - (正则表达式, 上游组名, 原始模式)
    regex_rules: Vec<(Regex, String, String)>,
    
    // 正则预筛选 - 特征 -> 规则索引集合
    regex_prefilter: HashMap<String, HashSet<usize>>,
}

// URL规则数据结构 - 与之前相同
#[derive(Debug, Default)]
struct UrlRules {
    exact: HashSet<String>,
    regex: Vec<Regex>,
    wildcard: Vec<WildcardPattern>,
    last_updated: Option<std::time::Instant>,
    last_hash: Option<u64>,
}

// 通配符模式 - 优化结构
#[derive(Debug, Clone)]
struct WildcardPattern {
    // 原始模式
    pattern: String,
    // 前缀（如果有）
    prefix: Option<String>,
    // 后缀（如果有）
    suffix: Option<String>,
}

// 文件规则数据
struct FileRuleData {
    // 规则内容
    core: RouterCore,
    // 上游组名
    upstream_group: String,
}

// URL规则数据
struct UrlRuleData {
    // URL地址
    url: String,
    // 规则内容 - 使用RwLock以支持异步更新
    rules: Arc<AsyncRwLock<UrlRules>>,
    // 上游组名
    upstream_group: String,
    // 周期性更新配置
    periodic: Option<PeriodicConfig>,
}

// 周期性更新配置 - 与之前相同
#[derive(Debug, Clone)]
struct PeriodicConfig {
    enabled: bool,
    interval_secs: u64,
}

// DNS 路由器 - 优化重构版
pub struct Router {
    // 是否启用
    enabled: bool,
    
    // 核心路由规则 - 不包括文件和URL规则
    core: RouterCore,
    
    // 文件规则列表
    file_rules: Vec<FileRuleData>,
    
    // URL规则列表
    url_rules: Vec<UrlRuleData>,
    
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
                core: RouterCore::new(),
                file_rules: Vec::new(),
                url_rules: Vec::new(),
                default_upstream_group: None,
                http_client: None,
            });
        }
        
        // 创建主核心路由结构
        let mut core = RouterCore::new();
        
        // 文件规则列表
        let mut file_rules = Vec::new();
        
        // URL规则列表
        let mut url_rules = Vec::new();
        
        // 跟踪不同类型规则的数量
        let mut exact_count = 0;
        let mut regex_count = 0;
        let mut wildcard_count = 0;
        let mut file_count = 0;
        let mut url_count = 0;
        
        // 编译所有规则
        for rule in routing_config.rules {
            match &rule.match_ {
                condition if condition.type_ == MatchType::Exact => {
                    // 处理精确匹配规则
                    if let Some(values) = &condition.values {
                        for domain in values {
                            core.add_exact_rule(domain.clone(), rule.upstream_group.clone());
                            exact_count += 1;
                        }
                    }
                },
                
                condition if condition.type_ == MatchType::Wildcard => {
                    // 处理通配符规则
                    if let Some(values) = &condition.values {
                        for pattern in values {
                            core.add_wildcard_rule(pattern.clone(), rule.upstream_group.clone());
                            wildcard_count += 1;
                        }
                    }
                },
                
                condition if condition.type_ == MatchType::Regex => {
                    // 处理正则表达式规则
                    if let Some(values) = &condition.values {
                        for pattern in values {
                            match Regex::new(pattern) {
                                Ok(regex) => {
                                    core.add_regex_rule(pattern.clone(), regex, rule.upstream_group.clone());
                                    regex_count += 1;
                                },
                                Err(e) => {
                                    return Err(ServerError::RegexCompilation(format!(
                                        "Failed to compile regex '{}': {}", 
                                        pattern, e
                                    )));
                                }
                            }
                        }
                    }
                },
                
                condition if condition.type_ == MatchType::File => {
                    // 处理文件规则
                    if let Some(path) = &condition.path {
                        let file_rule_core = Self::load_rules_from_file(path)?;
                        
                        file_rules.push(FileRuleData {
                            core: file_rule_core,
                            upstream_group: rule.upstream_group.clone(),
                        });
                        
                        file_count += 1;
                    }
                },
                
                condition if condition.type_ == MatchType::Url => {
                    // 处理URL规则
                    if let Some(url) = &condition.url {
                        // 创建空的初始规则集
                        let rules = Arc::new(AsyncRwLock::new(UrlRules::default()));
                        
                        // 解析周期性更新配置
                        let periodic = condition.periodic.as_ref().map(|p| PeriodicConfig {
                            enabled: p.enabled,
                            interval_secs: p.interval_secs,
                        });
                        
                        url_rules.push(UrlRuleData {
                            url: url.clone(),
                            rules,
                            upstream_group: rule.upstream_group.clone(),
                            periodic,
                        });
                        
                        url_count += 1;
                    }
                },
                
                _ => {
                    return Err(ServerError::InvalidRuleFormat("Unknown match type".to_string()));
                }
            }
        }
        
        // 记录规则计数指标 - 确保所有类型的计数都被更新
        {
            METRICS.route_rules().with_label_values(&[ROUTE_RULE_TYPE_EXACT]).set(exact_count as f64);
            METRICS.route_rules().with_label_values(&[ROUTE_RULE_TYPE_REGEX]).set(regex_count as f64);
            METRICS.route_rules().with_label_values(&[ROUTE_RULE_TYPE_WILDCARD]).set(wildcard_count as f64);
            METRICS.route_rules().with_label_values(&[ROUTE_RULE_TYPE_FILE]).set(file_count as f64);
            METRICS.route_rules().with_label_values(&[ROUTE_RULE_TYPE_URL]).set(url_count as f64);
        }
        
        // 创建路由器实例
        let router = Self {
            enabled: true,
            core,
            file_rules,
            url_rules,
            default_upstream_group: routing_config.default_upstream_group,
            http_client,
        };
        
        // 启动URL规则更新任务
        router.start_url_updaters().await;
        
        Ok(router)
    }
    
    // 匹配域名，返回路由决策 - 主要入口方法
    pub async fn match_domain(&self, domain: &str) -> RouteDecision {
        // 如果路由未启用，返回使用全局上游
        if !self.enabled {
            {
                METRICS.route_results_total().with_label_values(&[ROUTE_RESULT_DISABLED]).inc();
            }
            return RouteDecision::UseGlobal;
        }
        
        // 规范化域名（转换为小写，去除尾部的点）
        let domain_lower = domain.to_lowercase();
        let domain_normalized = domain_lower.trim_end_matches('.');
        
        // 1. 首先尝试匹配核心规则 (高效的数据结构)
        if let Some((upstream_group, pattern, rule_type)) = self.core.match_domain(domain_normalized) {
            // 如果是黑洞，返回黑洞决策
            if upstream_group == BLACKHOLE_UPSTREAM_GROUP_NAME {
                {
                    METRICS.route_results_total().with_label_values(&[ROUTE_RESULT_BLACKHOLE]).inc();
                }
                return RouteDecision::Blackhole;
            }
            
            // 记录匹配
            {
                METRICS.route_results_total().with_label_values(&[ROUTE_RESULT_RULE_MATCH]).inc();
            }
            
            debug!(
                domain = %domain_normalized,
                pattern = %pattern,
                rule_type = %rule_type,
                upstream_group = %upstream_group,
                "Domain matched core rule"
            );
            
            return RouteDecision::UseGroup(upstream_group);
        }
        
        // 2. 然后尝试匹配文件规则 (文件规则也使用高效数据结构)
        for file_rule in &self.file_rules {
            if let Some((_, pattern, rule_type)) = file_rule.core.match_domain(domain_normalized) {
                let upstream_group = &file_rule.upstream_group;
                
                // 如果是黑洞，返回黑洞决策
                if upstream_group == BLACKHOLE_UPSTREAM_GROUP_NAME {
                    {
                        METRICS.route_results_total().with_label_values(&[ROUTE_RESULT_BLACKHOLE]).inc();
                    }
                    return RouteDecision::Blackhole;
                }
                
                // 记录匹配
                {
                    METRICS.route_results_total().with_label_values(&[ROUTE_RESULT_RULE_MATCH]).inc();
                }
                
                debug!(
                    domain = %domain_normalized,
                    pattern = %pattern,
                    rule_type = %rule_type,
                    source = "file",
                    "Domain matched file rule"
                );
                
                return RouteDecision::UseGroup(upstream_group.clone());
            }
        }
        
        // 3. 最后尝试匹配URL规则 (需要异步读取)
        for url_rule in &self.url_rules {
            // 读取URL规则
            let url_rules = url_rule.rules.read().await;
            
            // 先检查精确匹配
            if url_rules.exact.contains(domain_normalized) {
                let upstream_group = &url_rule.upstream_group;
                
                // 如果是黑洞，返回黑洞决策
                if upstream_group == BLACKHOLE_UPSTREAM_GROUP_NAME {
                    {
                        METRICS.route_results_total().with_label_values(&[ROUTE_RESULT_BLACKHOLE]).inc();
                    }
                    return RouteDecision::Blackhole;
                }
                
                // 记录匹配
                {
                    METRICS.route_results_total().with_label_values(&[ROUTE_RESULT_RULE_MATCH]).inc();
                }
                
                debug!(
                    domain = %domain_normalized,
                    rule_type = "exact",
                    upstream_group = %upstream_group,
                    source = "url",
                    "Domain matched URL exact rule"
                );
                
                return RouteDecision::UseGroup(upstream_group.clone());
            }
            
            // 检查正则表达式匹配
            for regex in &url_rules.regex {
                if regex.is_match(domain_normalized) {
                    let upstream_group = &url_rule.upstream_group;
                    
                    // 如果是黑洞，返回黑洞决策
                    if upstream_group == BLACKHOLE_UPSTREAM_GROUP_NAME {
                        {
                            METRICS.route_results_total().with_label_values(&[ROUTE_RESULT_BLACKHOLE]).inc();
                        }
                        return RouteDecision::Blackhole;
                    }
                    
                    // 记录匹配
                    {
                        METRICS.route_results_total().with_label_values(&[ROUTE_RESULT_RULE_MATCH]).inc();
                    }
                    
                    debug!(
                        domain = %domain_normalized,
                        rule_type = "regex",
                        upstream_group = %upstream_group,
                        source = "url",
                        "Domain matched URL regex rule"
                    );
                    
                    return RouteDecision::UseGroup(upstream_group.clone());
                }
            }
            
            // 检查通配符匹配
            if Self::match_wildcard_patterns(domain_normalized, &url_rules.wildcard) {
                let upstream_group = &url_rule.upstream_group;
                
                // 如果是黑洞，返回黑洞决策
                if upstream_group == BLACKHOLE_UPSTREAM_GROUP_NAME {
                    {
                        METRICS.route_results_total().with_label_values(&[ROUTE_RESULT_BLACKHOLE]).inc();
                    }
                    return RouteDecision::Blackhole;
                }
                
                // 记录匹配
                {
                    METRICS.route_results_total().with_label_values(&[ROUTE_RESULT_RULE_MATCH]).inc();
                }
                
                debug!(
                    domain = %domain_normalized,
                    rule_type = "wildcard",
                    upstream_group = %upstream_group,
                    source = "url",
                    "Domain matched URL wildcard rule"
                );
                
                return RouteDecision::UseGroup(upstream_group.clone());
            }
        }
        
        // 如果没有规则匹配，检查默认上游组
        if let Some(default_group) = &self.default_upstream_group {
            {
                METRICS.route_results_total().with_label_values(&[ROUTE_RESULT_DEFAULT]).inc();
            }
            return RouteDecision::UseGroup(default_group.clone());
        }
        
        // 没有匹配规则且没有默认组，使用全局上游
        {
            METRICS.route_results_total().with_label_values(&[ROUTE_RESULT_GLOBAL]).inc();
        }
        RouteDecision::UseGlobal
    }
    
    // 从文件加载规则
    fn load_rules_from_file(path: &str) -> Result<RouterCore> {
        // 打开文件
        let file = match File::open(path) {
            Ok(f) => f,
            Err(e) => {
                error!("Failed to open rules file '{}': {}", path, e);
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
                    error!("Failed to read line {} from file '{}': {}", line_num + 1, path, e);
                    return Err(ServerError::RuleLoad(format!(
                        "Failed to read line {} from file '{}': {}", 
                        line_num + 1, path, e
                    )));
                }
            };
            
            // 处理规则行
            if let Err(e) = Self::process_rule_line(&line, &mut exact, &mut regex, &mut wildcard) {
                error!("Error in file '{}' at line {}: {}", path, line_num + 1, e);
                return Err(ServerError::RuleLoad(format!(
                    "Error in file '{}' at line {}: {}", 
                    path, line_num + 1, e
                )));
            }
        }
        
        // 更新文件规则指标
        {
            // 注意：这里使用文件规则类型标签，与URL规则区分
            METRICS.route_rules().with_label_values(&[ROUTE_RULE_TYPE_FILE]).set((exact.len() + regex.len() + wildcard.len()) as f64);
        }
        
        info!(
            file = path,
            exact_rules = exact.len(),
            regex_rules = regex.len(),
            wildcard_rules = wildcard.len(),
            "Loaded domain rules from file"
        );
        
        // 创建并填充 RouterCore
        let mut core = RouterCore::new();
        
        // 添加精确匹配规则
        for domain in exact {
            core.add_exact_rule(domain, "file_rule".to_string());
        }
        
        // 添加通配符规则
        for pattern in wildcard {
            core.add_wildcard_rule(pattern.pattern.clone(), "file_rule".to_string());
        }
        
        // 添加正则表达式规则
        for (i, re) in regex.iter().enumerate() {
            let pattern = format!("regex_pattern_{}", i);
            core.add_regex_rule(pattern, re.clone(), "file_rule".to_string());
        }
        
        Ok(core)
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
        let pattern_lower = pattern.trim().to_lowercase();
        
        // 处理特殊情况：*
        if pattern_lower == "*" {
            return WildcardPattern {
                pattern: "*".to_string(),
                prefix: None,
                suffix: None,
            };
        }
        
        // 处理特殊情况：*.domain.com
        if let Some(suffix) = pattern_lower.strip_prefix("*.") {
            return WildcardPattern {
                pattern: pattern_lower.clone(),
                prefix: None,
                suffix: Some(suffix.to_string()),
            };
        }
        
        // 处理特殊情况：prefix.*
        if pattern_lower.ends_with(".*") {
            let prefix_len = pattern_lower.len() - 2;
            let prefix = pattern_lower[..prefix_len].to_string();
            return WildcardPattern {
                pattern: pattern_lower.clone(),
                prefix: Some(prefix),
                suffix: None,
            };
        }
        
        // 处理一般情况
        WildcardPattern {
            pattern: pattern_lower.clone(),
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
            else {
                // 使用已经预先解析的正则表达式
                lazy_static! {
                    static ref PATTERN_REGEX_CACHE: std::sync::Mutex<HashMap<String, Option<Regex>>> = 
                        std::sync::Mutex::new(HashMap::new());
                }
                
                // 尝试从缓存获取，如果没有则创建并缓存
                let regex_opt = {
                    let mut cache = PATTERN_REGEX_CACHE.lock().unwrap();
                    if !cache.contains_key(&pattern.pattern) {
                        let regex_result = Self::wildcard_to_regex(&pattern.pattern);
                        cache.insert(pattern.pattern.clone(), regex_result.ok());
                    }
                    cache.get(&pattern.pattern).unwrap().clone()
                };
                
                // 如果有正则表达式，尝试匹配
                if let Some(re) = regex_opt {
                    if re.is_match(domain) {
                        return true;
                    }
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
        
        // 快速路径：检查是否有特殊字符或星号
        let has_special = pattern.contains('*') || 
                          pattern.chars().any(|c| ".+^$(){}|[]\\".contains(c));
                          
        if !has_special {
            // 简单情况：无特殊字符，直接添加锚点
            let regex_str = format!("^{}$", pattern);
            return Regex::new(&regex_str).map_err(|e| ServerError::RegexCompilation(format!(
                "Failed to compile wildcard pattern regex '{}': {}",
                regex_str, e
            )));
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
                // 处理从last_pos到start的内容
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
    async fn load_rules_from_url(client: &Client, url: &str) -> Result<(String, UrlRules)> {
        // 发送 HTTP 请求
        let response = match client.get(url).send().await {
            Ok(resp) => resp,
            Err(e) => {
                error!("Failed to fetch rules from {}: {}", url, e);
                return Err(ServerError::Http(e.to_string()));
            }
        };
        
        // 检查状态码
        if !response.status().is_success() {
            error!("Failed to fetch rules from {}: HTTP status {}", url, response.status());
            return Err(ServerError::RuleFetch(format!(
                "Failed to fetch rules from URL '{}': HTTP status {}",
                url, response.status()
            )));
        }
        
        // 获取响应文本
        let text = match response.text().await {
            Ok(t) => t,
            Err(e) => {
                error!("Failed to read response body from {}: {}", url, e);
                return Err(ServerError::Http(e.to_string()));
            }
        };
        
        // 初始化URL规则
        let mut url_rules = UrlRules::default();
        
        // 处理每一行
        for (line_num, line) in text.lines().enumerate() {
            // 去除前后空白
            let line = line.trim();
            
            // 忽略空行和注释
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            
            // 检查特殊前缀
            if let Some(pattern) = line.strip_prefix("regex:") {
                // 提取正则表达式
                let pattern = pattern.trim();
                match Regex::new(pattern) {
                    Ok(re) => url_rules.regex.push(re),
                    Err(e) => {
                        error!("Error in URL '{}' content at line {}: {}", url, line_num + 1, e);
                        return Err(ServerError::RegexCompilation(format!(
                            "Failed to compile regex '{}': {}", 
                            pattern, e
                        )));
                    }
                }
            } else if let Some(pattern) = line.strip_prefix("wildcard:") {
                // 提取通配符模式
                let pattern = pattern.trim();
                url_rules.wildcard.push(Self::parse_wildcard_pattern(pattern));
            } else {
                // 默认为精确匹配
                url_rules.exact.insert(line.to_lowercase().trim_end_matches('.').to_string());
            }
        }
        
        // 更新路由规则指标 - 使用统一的标签值
        {
            // 使用标准标签记录URL规则计数
            METRICS.route_rules().with_label_values(&[ROUTE_RULE_TYPE_EXACT]).set(url_rules.exact.len() as f64);
            METRICS.route_rules().with_label_values(&[ROUTE_RULE_TYPE_REGEX]).set(url_rules.regex.len() as f64);
            METRICS.route_rules().with_label_values(&[ROUTE_RULE_TYPE_WILDCARD]).set(url_rules.wildcard.len() as f64);
        }
        
        info!(
            url = url,
            exact_rules = url_rules.exact.len(),
            regex_rules = url_rules.regex.len(),
            wildcard_rules = url_rules.wildcard.len(),
            "Loaded domain rules from URL"
        );
        
        Ok((text, url_rules))
    }
    
    // 启动所有URL规则更新任务
    async fn start_url_updaters(&self) {
        // 如果没有HTTP客户端，无法更新URL规则
        let Some(client) = &self.http_client else {
            warn!("HTTP client not available, URL rules will not be automatically updated");
            return;
        };
        
        // 收集需要周期性更新的URL规则
        for (index, rule) in self.url_rules.iter().enumerate() {
            // 只对配置了周期性更新并启用的规则创建更新任务
            if let Some(config) = &rule.periodic {
                if config.enabled {
                    // 创建HTTP客户端和规则对象的克隆
                    let client_clone = client.clone();
                    let url_clone = rule.url.clone();
                    let rules_clone = Arc::clone(&rule.rules);
                    let interval_secs = config.interval_secs;
                    let upstream_group = rule.upstream_group.clone();
                    
                    // 启动独立的更新任务
                    tokio::spawn(async move {
                        // 创建间隔计时器
                        let mut interval_timer = interval(Duration::from_secs(interval_secs));
                        
                        info!(
                            url = url_clone, 
                            rule_index = index, 
                            interval_secs = interval_secs,
                            upstream_group = upstream_group,
                            "Started URL rule periodic updater"
                        );
                        
                        // 立即执行第一次更新
                        Self::update_single_url_rule(&client_clone, &url_clone, &rules_clone, &upstream_group).await;
                        
                        // 定期更新
                        loop {
                            interval_timer.tick().await;
                            Self::update_single_url_rule(&client_clone, &url_clone, &rules_clone, &upstream_group).await;
                        }
                    });
                } else {
                    debug!(url = rule.url, rule_index = index, "URL rule periodic update disabled by config");
                }
            } else {
                debug!(url = rule.url, rule_index = index, "URL rule has no periodic update configuration");
            }
        }
    }
    
    // 更新单个URL规则
    async fn update_single_url_rule(client: &Client, url: &str, rules: &Arc<AsyncRwLock<UrlRules>>, upstream_group: &str) {
        let start_time = std::time::Instant::now();
        let mut status = URL_RULE_UPDATE_STATUS_FAILED;
        
        // 尝试获取规则内容并计算哈希
        match Self::load_rules_from_url(client, url).await {
            Ok((content, new_rules)) => {
                // 计算内容哈希
                let new_hash = xxh64(content.as_bytes(), 0);
                
                // 先获取读锁，比较哈希值
                let need_update = {
                    let rules_read = rules.read().await;
                    match rules_read.last_hash {
                        Some(hash) if hash == new_hash => {
                            // 内容未变化，无需更新
                            debug!(url = url, "URL content unchanged (hash match), skipping update");
                            status = URL_RULE_UPDATE_STATUS_UNCHANGED;
                            false
                        },
                        _ => true
                    }
                };
                
                // 内容有变化或首次加载，需要更新规则
                if need_update {
                    // 获取写锁
                    let mut rules_write = rules.write().await;
                    
                    // 更新规则
                    rules_write.exact = new_rules.exact;
                    rules_write.regex = new_rules.regex;
                    rules_write.wildcard = new_rules.wildcard;
                    rules_write.last_updated = Some(std::time::Instant::now());
                    rules_write.last_hash = Some(new_hash);
                    
                    status = URL_RULE_UPDATE_STATUS_SUCCESS;
                    info!(
                        url = url,
                        exact_rules = rules_write.exact.len(),
                        regex_rules = rules_write.regex.len(),
                        wildcard_rules = rules_write.wildcard.len(),
                        elapsed_ms = start_time.elapsed().as_millis(),
                        "Updated URL rules successfully"
                    );
                    
                    // 更新指标统计 - 使用统一的标签值进行计数
                    METRICS.route_rules().with_label_values(&[ROUTE_RULE_TYPE_EXACT]).set(rules_write.exact.len() as f64);
                    METRICS.route_rules().with_label_values(&[ROUTE_RULE_TYPE_REGEX]).set(rules_write.regex.len() as f64);
                    METRICS.route_rules().with_label_values(&[ROUTE_RULE_TYPE_WILDCARD]).set(rules_write.wildcard.len() as f64);
                }
            },
            Err(e) => {
                error!(url = url, error = %e, "Failed to update rules from URL");
            }
        }
        
        // 更新指标
        let elapsed = start_time.elapsed().as_secs_f64();
        METRICS.url_rule_update_duration_seconds().with_label_values(&[status, upstream_group]).observe(elapsed);
    }
}

// RouterCore实现
impl RouterCore {
    // 创建新的空核心
    fn new() -> Self {
        Self {
            exact_rules: HashMap::new(),
            wildcard_rules: BTreeMap::new(),
            global_wildcard: None,
            regex_rules: Vec::new(),
            regex_prefilter: HashMap::new(),
        }
    }
    
    // 添加精确匹配规则
    fn add_exact_rule(&mut self, domain: String, upstream_group: String) {
        self.exact_rules.insert(domain.to_lowercase().trim_end_matches('.').to_string(), upstream_group);
    }
    
    // 添加通配符规则
    fn add_wildcard_rule(&mut self, pattern: String, upstream_group: String) {
        // 全局通配符特殊处理
        if pattern == "*" {
            self.global_wildcard = Some(upstream_group);
            return;
        }
        
        // 处理标准通配符格式: *.domain.com
        if let Some(suffix) = pattern.strip_prefix("*.") {
            let reversed_suffix = Self::reverse_domain_labels(suffix);
            self.wildcard_rules.insert(reversed_suffix, (upstream_group, pattern));
            return;
        }
        
        // 将其他通配符格式转换为正则表达式
        if let Ok(regex) = Router::wildcard_to_regex(&pattern) {
            let index = self.regex_rules.len();
            self.regex_rules.push((regex, upstream_group, pattern.clone()));
            
            // 添加到预筛选映射
            self.add_to_prefilter(index, &pattern);
        }
    }
    
    // 添加正则表达式规则
    fn add_regex_rule(&mut self, pattern: String, regex: Regex, upstream_group: String) {
        let index = self.regex_rules.len();
        let pattern_clone = pattern.clone();
        self.regex_rules.push((regex, upstream_group, pattern));
        
        // 添加到预筛选映射
        self.add_to_prefilter(index, &pattern_clone);
    }
    
    // 添加到正则预筛选映射
    fn add_to_prefilter(&mut self, rule_index: usize, pattern: &str) {
        // 1. 添加全局通配符作为兜底
        self.regex_prefilter
            .entry("*".to_string())
            .or_default()
            .insert(rule_index);
            
        // 2. 尝试提取TLD和SLD作为预筛选键
        if let Some(tld_pos) = pattern.rfind('.') {
            if let Some(tld) = pattern.get(tld_pos..) {
                // 使用TLD作为特征(如 .com, .org)
                self.regex_prefilter
                    .entry(tld.to_string())
                    .or_default()
                    .insert(rule_index);
                    
                // 尝试提取二级域名
                if let Some(sld_pos) = pattern[..tld_pos].rfind('.') {
                    if let Some(sld_tld) = pattern.get(sld_pos..) {
                        // 使用SLD.TLD作为特征(如 .example.com)
                        self.regex_prefilter
                            .entry(sld_tld.to_string())
                            .or_default()
                            .insert(rule_index);
                    }
                }
            }
        }
    }
    
    // 匹配域名 - 核心匹配逻辑
    fn match_domain(&self, domain: &str) -> Option<(String, String, &'static str)> {
        // 1. 优先尝试精确匹配 (O(1)复杂度)
        if let Some(upstream_group) = self.exact_rules.get(domain) {
            return Some((upstream_group.clone(), domain.to_string(), ROUTE_RULE_TYPE_EXACT));
        }
        
        // 2. 然后尝试通配符匹配 (O(log n)复杂度)
        // 仅处理标准通配符格式 *.domain.com
        // 避免创建临时Vec，直接使用迭代器
        let mut part_count = 0;
        let mut suffix_start_index = 0;
        
        // 首先计算域名部分数量
        for (i, c) in domain.chars().enumerate() {
            if c == '.' {
                part_count += 1;
                if part_count == 1 {
                    suffix_start_index = i + 1;
                }
            }
        }
        part_count += 1; // 加上最后一个部分
        
        if part_count >= 2 {
            // 尝试匹配各级子域名
            let mut current_suffix = &domain[suffix_start_index..];
            let mut current_suffix_rev = Self::reverse_domain_labels(current_suffix);
            
            // 检查当前后缀是否匹配
            if let Some((upstream_group, pattern)) = self.wildcard_rules.get(&current_suffix_rev) {
                return Some((upstream_group.clone(), pattern.clone(), ROUTE_RULE_TYPE_WILDCARD));
            }
            
            // 继续查找更高级别的域名
            let mut next_dot = current_suffix.find('.');
            while let Some(dot_pos) = next_dot {
                current_suffix = &current_suffix[dot_pos + 1..];
                current_suffix_rev = Self::reverse_domain_labels(current_suffix);
                
                if let Some((upstream_group, pattern)) = self.wildcard_rules.get(&current_suffix_rev) {
                    return Some((upstream_group.clone(), pattern.clone(), ROUTE_RULE_TYPE_WILDCARD));
                }
                
                next_dot = current_suffix.find('.');
            }
        }
        
        // 3. 最后尝试正则表达式匹配 (使用预筛选优化)
        let mut candidate_indices: HashSet<usize> = HashSet::new();
        
        // 添加全局通配符索引
        if let Some(indices) = self.regex_prefilter.get("*") {
            candidate_indices.extend(indices);
        }
        
        // 预筛选优化 - 基于TLD和SLD
        let domain_parts: Vec<&str> = domain.split('.').collect();
        let parts_len = domain_parts.len();
        
        // 提取TLD作为特征
        if parts_len >= 1 {
            let tld = format!(".{}", domain_parts[parts_len - 1]);
            if let Some(indices) = self.regex_prefilter.get(&tld) {
                candidate_indices.extend(indices);
            }
            
            // 提取SLD.TLD作为特征
            if parts_len >= 2 {
                let sld_tld = format!(".{}.{}", domain_parts[parts_len - 2], domain_parts[parts_len - 1]);
                if let Some(indices) = self.regex_prefilter.get(&sld_tld) {
                    candidate_indices.extend(indices);
                }
            }
        }
        
        // 尝试匹配候选正则表达式
        for &index in &candidate_indices {
            let (regex, upstream_group, pattern): &(Regex, String, String) = &self.regex_rules[index];
            if regex.is_match(domain) {
                return Some((upstream_group.clone(), pattern.clone(), ROUTE_RULE_TYPE_REGEX));
            }
        }
        
        // 4. 全局通配符匹配
        if let Some(upstream_group) = &self.global_wildcard {
            return Some((upstream_group.clone(), "*".to_string(), ROUTE_RULE_TYPE_WILDCARD));
        }
        
        // 没有匹配的规则
        None
    }
    
    // 反转域名标签，例如 "example.com" -> "com.example"
    // 这个函数在 `find_match` 方法中被多次调用，因此使用 `#[inline(always)]` 优化
    #[inline(always)]
    fn reverse_domain_labels(domain_suffix: &str) -> String {
        if domain_suffix.is_empty() {
            return String::new();
        }

        // 预先分配足够空间 (最坏情况需要额外的点号)
        let mut result = String::with_capacity(domain_suffix.len() + 1);

        // 计算段数以确定何时添加分隔符
        let segments: Vec<(usize, usize)> = domain_suffix
            .char_indices()
            .filter(|(_, c)| *c == '.')
            .map(|(i, _)| i)
            .fold(Vec::with_capacity(10), |mut acc, i| {
                if let Some(&(_, last)) = acc.last() {
                    acc.push((last + 1, i));
                } else {
                    acc.push((0, i));
                }
                acc
            });

        // 处理最后一段
        if let Some(&(start, _)) = segments.last() {
            result.push_str(&domain_suffix[start..]);
        } else {
            // 没有点号，直接返回原字符串
            return domain_suffix.to_string();
        }

        // 反向处理其他段
        for i in (0..segments.len()-1).rev() {
            let (start, end) = segments[i];
            result.push('.');
            result.push_str(&domain_suffix[start..end]);
        }

        result
    }
} 