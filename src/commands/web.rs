use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead};
use std::sync::Arc;
use std::time::Duration;
use anyhow::Result;
use colored::*;
use futures::stream::{self, StreamExt};
use indicatif::ProgressBar;
use indicatif::ProgressStyle;
use reqwest::header::{HeaderMap, HeaderValue, HeaderName, USER_AGENT};
use reqwest::redirect::Policy;
use serde::{Serialize, Deserialize};
use strum::{EnumIter, Display};
use tokio::sync::{Semaphore, Mutex};
use crate::utils::output;
use std::collections::HashSet;
use regex::Regex;
use url::Url;

#[derive(Clone, Debug, clap::Subcommand, EnumIter, Display, Serialize, Deserialize)]
pub enum WebCommands {
    /// Web目录扫描 - 常见路径爆破、隐藏文件发现
    #[clap(name = "scan")]
    Scan {
        /// 目标URL (例如: http://example.com)
        #[arg(short, long)]
        target: String,

        /// 自定义字典文件路径
        #[arg(short = 'w', long)]
        wordlist: Option<String>,

        /// 扫描线程数/并发数
        #[arg(long, default_value = "50")]
        threads: u32,

        /// 超时时间(秒)
        #[arg(long, default_value = "10")]
        timeout: u64,

        /// 扫描的扩展名列表 (逗号分隔)
        #[arg(long, default_value = "php,html,js,css,txt,bak,conf,sql,xml,json")]
        extensions: String,

        /// 启用递归扫描
        #[arg(long, default_value = "false")]
        recursive: bool,

        /// 递归深度限制
        #[arg(long, default_value = "3")]
        depth: u32,

        /// 跟随重定向
        #[arg(long, default_value = "true")]
        follow_redirects: bool,

        /// 仅显示有效路径 (过滤掉404)
        #[arg(long, default_value = "false")]
        show_only_found: bool,

        /// 输出格式 (text, json, csv)
        #[arg(short = 'f', long, default_value = "text")]
        output_format: String,

        /// 保存结果到文件
        #[arg(short = 'o', long)]
        output_file: Option<String>,

        /// 启用详细输出
        #[arg(short = 'v', long, default_value = "false")]
        verbose: bool,

        /// 添加自定义User-Agent
        #[arg(long, default_value = "rtk-web-scanner/1.0")]
        user_agent: String,

        /// 添加自定义请求头
        #[arg(long)]
        headers: Option<Vec<String>>,
    },

    /// Web递归扫描 - 自动发现链接并递归扫描
    #[clap(name = "recursive")]
    Recursive {
        /// 目标URL (例如: http://example.com)
        #[arg(short, long)]
        target: String,

        /// 扫描线程数/并发数
        #[arg(long, default_value = "20")]
        threads: u32,

        /// 超时时间(秒)
        #[arg(long, default_value = "10")]
        timeout: u64,

        /// 递归深度限制
        #[arg(short, long, default_value = "3")]
        depth: u32,

        /// 最大扫描页面数
        #[arg(short, long, default_value = "1000")]
        max_pages: u32,

        /// 跟随重定向
        #[arg(long, default_value = "true")]
        follow_redirects: bool,

        /// 只显示找到的路径
        #[arg(long, default_value = "false")]
        show_only_found: bool,

        /// 输出格式 (text, json, csv)
        #[arg(short = 'f', long, default_value = "text")]
        output_format: String,

        /// 输出文件路径
        #[arg(short = 'o', long)]
        output_file: Option<String>,

        /// 详细输出
        #[arg(short = 'v', long, default_value = "false")]
        verbose: bool,

        /// 用户代理字符串
        #[arg(long, default_value = "rtk-web-scanner/1.0")]
        user_agent: String,

        /// 自定义HTTP头 (格式: "Header: Value")
        #[arg(long)]
        headers: Option<Vec<String>>,

        /// 排除的文件扩展名
        #[arg(long, default_value = "jpg,jpeg,png,gif,bmp,ico,woff,woff2,ttf,eot")]
        exclude_extensions: String,

        /// 排除的路径模式 (正则表达式)
        #[arg(long)]
        exclude_patterns: Option<Vec<String>>,
    },

    /// Web侦察 - 技术栈识别、服务器信息收集
    #[clap(name = "recon")]
    Recon {
        /// 目标URL (例如: http://example.com)
        #[arg(short = 'u', long)]
        target: String,

        /// 详细输出
        #[arg(short = 'v', long, default_value = "false")]
        verbose: bool,

        /// 输出格式 (text, json)
        #[arg(short = 'f', long, default_value = "text")]
        output_format: String,

        /// 超时时间(秒)
        #[arg(long, default_value = "10")]
        timeout: u64,
    },
}

// Web扫描结果结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub url: String,
    pub status_code: u16,
    pub content_length: Option<u64>,
    pub content_type: Option<String>,
    pub title: Option<String>,
    pub path: String,
    pub found: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconResult {
    pub url: String,
    pub server: Option<String>,
    pub technologies: Vec<String>,
    pub headers: HashMap<String, String>,
    pub status_code: u16,
    pub title: Option<String>,
}

// 主处理函数
pub async fn handle_web_command(command: WebCommands) -> Result<()> {
    match command {
        WebCommands::Scan {
            target,
            wordlist,
            threads,
            timeout,
            extensions,
            recursive,
            depth,
            follow_redirects,
            show_only_found,
            output_format,
            output_file,
            verbose,
            user_agent,
            headers,
        } => {
            web_directory_scan(
                &target,
                wordlist,
                threads,
                timeout,
                &extensions,
                recursive,
                depth,
                follow_redirects,
                show_only_found,
                &output_format,
                output_file,
                verbose,
                &user_agent,
                headers,
            ).await?;
        }
        WebCommands::Recursive {
            target,
            threads,
            timeout,
            depth,
            max_pages,
            follow_redirects,
            show_only_found,
            output_format,
            output_file,
            verbose,
            user_agent,
            headers,
            exclude_extensions,
            exclude_patterns,
        } => {
            web_recursive_scan(
                &target,
                threads,
                timeout,
                depth,
                max_pages,
                follow_redirects,
                show_only_found,
                &output_format,
                output_file,
                verbose,
                &user_agent,
                headers,
                &exclude_extensions,
                exclude_patterns,
            ).await?;
        }
        WebCommands::Recon {
            target,
            verbose,
            output_format,
            timeout,
        } => {
            web_recon(&target, verbose, &output_format, timeout).await?;
        }
    }
    Ok(())
}

// Web目录扫描主函数
async fn web_directory_scan(
    target: &str,
    wordlist: Option<String>,
    threads: u32,
    timeout: u64,
    extensions: &str,
    recursive: bool,
    depth: u32,
    follow_redirects: bool,
    show_only_found: bool,
    output_format: &str,
    output_file: Option<String>,
    verbose: bool,
    user_agent: &str,
    headers: Option<Vec<String>>,
) -> Result<()> {
    output::print_header("🔍 Web Directory Scanner");
    output::print_info(&format!("Target: {}", target));
    output::print_info(&format!("Threads: {}, Timeout: {}s", threads, timeout));

    // 解析扩展名
    let ext_list: Vec<&str> = extensions.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).collect();

    // 生成字典
    let wordlist_data = generate_wordlist(wordlist, &ext_list).await?;

    // 创建HTTP客户端
    let client = create_http_client(timeout, follow_redirects, user_agent, headers).await?;

    // 创建进度条
    let pb = ProgressBar::new(wordlist_data.len() as u64);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) {msg}")
        .unwrap()
        .progress_chars("#>-"));
    pb.set_message("Scanning directories...");

    // 并发扫描
    let semaphore = Arc::new(Semaphore::new(threads as usize));
    let results = Arc::new(Mutex::new(Vec::new()));

    let stream = stream::iter(wordlist_data);
    stream
        .for_each_concurrent(threads as usize, |path| {
            let target = target.to_string();
            let client = client.clone();
            let pb = pb.clone();
            let results = Arc::clone(&results);
            let semaphore = Arc::clone(&semaphore);
            let verbose = verbose;

            async move {
                let _permit = semaphore.acquire().await.unwrap();
                let result = scan_single_path(&client, &target, &path, verbose).await;

                if let Ok(scan_result) = result {
                    let mut results = results.lock().await;
                    results.push(scan_result);
                }

                pb.inc(1);
            }
        })
        .await;

    pb.finish_with_message("Scan completed!");

    // 输出结果
    let final_results = Arc::try_unwrap(results).unwrap().into_inner();
    output_scan_results(&final_results, show_only_found, output_format, output_file).await?;

    Ok(())
}

// 生成字典
async fn generate_wordlist(wordlist_path: Option<String>, extensions: &[&str]) -> Result<Vec<String>> {
    let mut paths = Vec::new();

    if let Some(path) = wordlist_path {
        // 从文件加载
        let file = File::open(&path)?;
        let reader = io::BufReader::new(file);
        for line in reader.lines() {
            let line = line?;
            let path = line.trim();
            if !path.is_empty() {
                paths.push(path.to_string());
            }
        }
    } else {
        // 使用内置字典
        paths.extend(get_default_wordlist());
    }

    // 添加扩展名变体
    let mut extended_paths = Vec::new();
    for path in paths {
        extended_paths.push(path.clone());

        for &ext in extensions {
            if !path.contains('.') {
                extended_paths.push(format!("{}.{}", path, ext));
            }
        }
    }

    Ok(extended_paths)
}

// 内置字典
fn get_default_wordlist() -> Vec<String> {
    let paths = vec![
        // 常见目录
        "admin", "login", "wp-admin", "wp-login", "dashboard", "config", "backup",
        "test", "dev", "staging", "tmp", "temp", "old", "bak", "backup",

        // 常见文件
        "index.html", "index.php", "index.htm", "default.html", "home.html",
        "robots.txt", "sitemap.xml", "crossdomain.xml", "clientaccesspolicy.xml",
        ".htaccess", ".htpasswd", "web.config",

        // 常见管理页面
        "admin.php", "admin.html", "login.php", "login.html", "signin.php",
        "signin.html", "wp-admin.php", "administrator", "manager", "console",

        // 常见配置文件
        "config.php", "configuration.php", "settings.php", "conf.php",
        "database.php", "db.php", "connect.php", "setup.php", "install.php",

        // 常见备份文件
        "backup.sql", "backup.zip", "backup.tar.gz", "database.sql",
        "wp-config.php", "config.inc", "config.inc.php",

        // 隐藏文件
        ".env", ".git", ".svn", ".hg", ".bzr", ".DS_Store", "thumbs.db",

        // 其他常见路径
        "api", "rest", "graphql", "docs", "documentation", "help", "support",
        "images", "img", "css", "js", "javascript", "assets", "static",
        "uploads", "files", "media", "content", "data", "storage", "cache",
        "tmp", "temp", "logs", "log", "error_log", "access_log",

        // Web服务器相关
        "server-status", "server-info", "phpinfo.php", "info.php", "test.php",
        "status", "health", "metrics", "stats", "statistics", "monitoring",

        // 常见框架路径
        "vendor", "node_modules", "bower_components", "src", "lib", "library",
        "includes", "classes", "models", "views", "controllers",

        // 常见CMS路径
        "wp-content", "wp-includes", "wp-json", "xmlrpc.php", "wp-cron.php",
        "administrator", "components", "modules", "plugins", "themes", "templates",

        // 常见数据库相关
        "phpmyadmin", "myadmin", "adminer", "mysql", "database", "db",
        "sql", "query", "search", "find", "browse",

        // 其他
        "favicon.ico", "logo.png", "banner.jpg", "header", "footer", "sidebar",
        "navigation", "menu", "search", "contact", "about", "privacy", "terms",
    ];

    paths.iter().map(|s| s.to_string()).collect()
}

// 创建HTTP客户端
async fn create_http_client(
    timeout: u64,
    follow_redirects: bool,
    user_agent: &str,
    headers: Option<Vec<String>>,
) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout))
        .user_agent(user_agent);

    // 设置重定向策略
    if !follow_redirects {
        builder = builder.redirect(Policy::none());
    }

    // 添加自定义请求头
    if let Some(custom_headers) = headers {
        let mut header_map = HeaderMap::new();
        for header_str in &custom_headers {
            if let Some((key, value)) = header_str.split_once(':') {
                if let Ok(header_name) = HeaderName::from_bytes(key.trim().as_bytes()) {
                    if let Ok(header_value) = HeaderValue::from_str(value.trim()) {
                        header_map.insert(header_name, header_value);
                    }
                }
            }
        }
        builder = builder.default_headers(header_map);
    }

    Ok(builder.build()?)
}

// 扫描单个路径
async fn scan_single_path(
    client: &reqwest::Client,
    target: &str,
    path: &str,
    verbose: bool,
) -> Result<ScanResult> {
    let url = if target.ends_with('/') {
        format!("{}{}", target, path)
    } else {
        format!("{}/{}", target, path)
    };

    let response = client.get(&url).send().await;

    match response {
        Ok(resp) => {
            let status_code = resp.status().as_u16();
            let content_length = resp.content_length();
            let content_type = resp
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());

            // 获取页面标题
            let title = extract_title(resp).await.unwrap_or(None);

            let scan_result = ScanResult {
                url: url.clone(),
                status_code,
                content_length,
                content_type,
                title,
                path: path.to_string(),
                found: status_code != 404,
            };

            if verbose {
                match status_code {
                    200 => output::print_success(&format!("✅ Found: {} [{}]", url, status_code)),
                    301 | 302 | 307 | 308 => output::print_info(&format!("🔄 Redirect: {} [{}]", url, status_code)),
                    401 | 403 => output::print_warning(&format!("🔒 Restricted: {} [{}]", url, status_code)),
                    404 => {
                        if verbose {
                            output::print_error(&format!("❌ Not found: {} [{}]", url, status_code));
                        }
                    }
                    _ => output::print_info(&format!("📄 Response: {} [{}]", url, status_code)),
                }
            }

            Ok(scan_result)
        }
        Err(e) => {
            if verbose {
                output::print_error(&format!("❌ Error scanning {}: {}", url, e));
            }
            Ok(ScanResult {
                url,
                status_code: 0,
                content_length: None,
                content_type: None,
                title: None,
                path: path.to_string(),
                found: false,
            })
        }
    }
}

// 提取页面标题 (从HTML文本中)
fn extract_title_from_html(text: &str) -> Option<String> {
    // 简单的HTML标题提取
    if let Some(start) = text.find("<title>") {
        if let Some(end) = text.find("</title>") {
            if start + 7 < end {
                let title = text[start + 7..end].trim();
                return Some(title.to_string());
            }
        }
    }
    None
}

// 提取页面标题 (从响应中，先获取文本)
async fn extract_title(mut response: reqwest::Response) -> Result<Option<String>> {
    let text = response.text().await.unwrap_or_default();
    Ok(extract_title_from_html(&text))
}

// 输出扫描结果
async fn output_scan_results(
    results: &[ScanResult],
    show_only_found: bool,
    output_format: &str,
    output_file: Option<String>,
) -> Result<()> {
    let filtered_results: Vec<&ScanResult> = if show_only_found {
        results.iter().filter(|r| r.found).collect()
    } else {
        results.iter().collect()
    };

    match output_format {
        "json" => output_json_results(&filtered_results, output_file).await?,
        "csv" => output_csv_results(&filtered_results, output_file).await?,
        _ => output_text_results(&filtered_results, output_file).await?,
    }

    output::print_info(&format!("Found {} valid paths out of {} total", filtered_results.len(), results.len()));
    Ok(())
}

// 文本格式输出
async fn output_text_results(results: &[&ScanResult], output_file: Option<String>) -> Result<()> {
    let mut output_text = String::new();

    output_text.push_str("📊 Web Directory Scan Results\n");
    output_text.push_str("====================================\n\n");

    for result in results {
        if result.found {
            let status_icon = match result.status_code {
                200 => "✅",
                301 | 302 | 307 | 308 => "🔄",
                401 | 403 => "🔒",
                _ => "📄",
            };

            let size_str = result.content_length
                .map(|size| format!("{} bytes", size))
                .unwrap_or_else(|| "Unknown".to_string());

            let title_str = result.title
                .as_ref()
                .map(|t| format!(" - {}", t))
                .unwrap_or_default();

            output_text.push_str(&format!(
                "{} {} [{}] - {}{}\n",
                status_icon, result.url, result.status_code, size_str, title_str
            ));
        }
    }

    if let Some(file_path) = output_file {
        tokio::fs::write(&file_path, output_text).await?;
        output::print_success(&format!("Results saved to: {}", file_path));
    } else {
        print!("{}", output_text);
    }

    Ok(())
}

// JSON格式输出
async fn output_json_results(results: &[&ScanResult], output_file: Option<String>) -> Result<()> {
    let json_output = serde_json::to_string_pretty(results)?;

    if let Some(file_path) = output_file {
        tokio::fs::write(&file_path, json_output).await?;
        output::print_success(&format!("Results saved to: {}", file_path));
    } else {
        println!("{}", json_output);
    }

    Ok(())
}

// CSV格式输出
async fn output_csv_results(results: &[&ScanResult], output_file: Option<String>) -> Result<()> {
    let mut csv_output = String::new();
    csv_output.push_str("URL,Status Code,Content Length,Content Type,Title,Path\n");

    for result in results {
        let title = result.title.as_ref().map(|t| t.replace(",", "")).unwrap_or_default();
        let content_type = result.content_type.as_ref().map(|t| t.replace(",", "")).unwrap_or_default();
        let content_length = result.content_length.unwrap_or(0);

        csv_output.push_str(&format!(
            "{},{},{},\"{}\",\"{}\",{}\n",
            result.url, result.status_code, content_length, content_type, title, result.path
        ));
    }

    if let Some(file_path) = output_file {
        tokio::fs::write(&file_path, csv_output).await?;
        output::print_success(&format!("Results saved to: {}", file_path));
    } else {
        print!("{}", csv_output);
    }

    Ok(())
}

// Web信息收集
async fn web_recon(target: &str, verbose: bool, output_format: &str, timeout: u64) -> Result<()> {
    output::print_header("🔍 Web Reconnaissance");
    output::print_info(&format!("Target: {}", target));

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout))
        .user_agent("Mozilla/5.0 (compatible; rtk-recon/1.0)")
        .build()?;

    let response = client.get(target).send().await?;

    let mut recon_result = ReconResult {
        url: target.to_string(),
        server: None,
        technologies: Vec::new(),
        headers: HashMap::new(),
        status_code: response.status().as_u16(),
        title: None,
    };

    // 提取响应头
    for (name, value) in response.headers() {
        let value_str = value.to_str().unwrap_or("").to_string();
        recon_result.headers.insert(name.to_string(), value_str.clone());

        if name.as_str() == "server" {
            recon_result.server = Some(value_str);
        }
    }

    // 提取页面标题和技术栈识别（需要先获取文本）
    let text = response.text().await.unwrap_or_default();
    recon_result.title = extract_title_from_html(&text);
    recon_result.technologies = identify_technologies(&text, &recon_result.headers);

    // 输出结果
    match output_format {
        "json" => println!("{}", serde_json::to_string_pretty(&recon_result)?),
        _ => output_recon_text(&recon_result),
    }

    Ok(())
}

// 技术栈识别
fn identify_technologies(content: &str, headers: &HashMap<String, String>) -> Vec<String> {
    let mut technologies = Vec::new();

    // 检查响应头中的技术栈信息
    for (name, value) in headers {
        let name_lower = name.to_lowercase();
        let value_lower = value.to_lowercase();

        if name_lower.contains("x-powered-by") {
            if value_lower.contains("php") {
                technologies.push("PHP".to_string());
            }
            if value_lower.contains("asp.net") {
                technologies.push("ASP.NET".to_string());
            }
            if value_lower.contains("node") {
                technologies.push("Node.js".to_string());
            }
        }

        if name_lower.contains("server") {
            if value_lower.contains("apache") {
                technologies.push("Apache".to_string());
            }
            if value_lower.contains("nginx") {
                technologies.push("Nginx".to_string());
            }
            if value_lower.contains("iis") {
                technologies.push("IIS".to_string());
            }
        }
    }

    // 检查内容中的技术栈信息
    let content_lower = content.to_lowercase();

    if content_lower.contains("wordpress") {
        technologies.push("WordPress".to_string());
    }
    if content_lower.contains("joomla") {
        technologies.push("Joomla".to_string());
    }
    if content_lower.contains("drupal") {
        technologies.push("Drupal".to_string());
    }
    if content_lower.contains("react") {
        technologies.push("React".to_string());
    }
    if content_lower.contains("vue") {
        technologies.push("Vue.js".to_string());
    }
    if content_lower.contains("angular") {
        technologies.push("Angular".to_string());
    }
    if content_lower.contains("bootstrap") {
        technologies.push("Bootstrap".to_string());
    }
    if content_lower.contains("jquery") {
        technologies.push("jQuery".to_string());
    }

    technologies.sort();
    technologies.dedup();
    technologies
}

// 文本格式输出Web信息收集结果
fn output_recon_text(result: &ReconResult) {
    println!("🌐 Target: {}", result.url);
    println!("📊 Status Code: {}", result.status_code);

    if let Some(server) = &result.server {
        println!("🖥️  Server: {}", server);
    }

    if let Some(title) = &result.title {
        println!("📄 Title: {}", title);
    }

    if !result.technologies.is_empty() {
        println!("🔧 Technologies:");
        for tech in &result.technologies {
            println!("   • {}", tech);
        }
    }

    if !result.headers.is_empty() {
        println!("📋 Headers:");
        for (name, value) in &result.headers {
            println!("   {}: {}", name, value);
        }
    }
}

// Web递归扫描函数
async fn web_recursive_scan(
    target: &str,
    threads: u32,
    timeout: u64,
    depth: u32,
    max_pages: u32,
    follow_redirects: bool,
    show_only_found: bool,
    output_format: &str,
    output_file: Option<String>,
    verbose: bool,
    user_agent: &str,
    headers: Option<Vec<String>>,
    exclude_extensions: &str,
    exclude_patterns: Option<Vec<String>>,
) -> Result<()> {
    println!("{}", "🔍 启动Web递归扫描...".bright_cyan().bold());
    
    // 解析目标URL
    let base_url = Url::parse(target)?;
    let base_domain = base_url.host_str().unwrap_or("").to_string();
    
    // 创建HTTP客户端
    let client = create_http_client(timeout, follow_redirects, user_agent, headers).await?;
    
    // 初始化数据结构
    let visited_urls = Arc::new(Mutex::new(HashSet::new()));
    let found_urls = Arc::new(Mutex::new(Vec::new()));
    let url_queue = Arc::new(Mutex::new(vec![target.to_string()]));
    
    // 解析排除扩展名
    let exclude_exts: HashSet<String> = exclude_extensions
        .split(',')
        .map(|s| s.trim().to_lowercase())
        .collect();
    
    // 编译排除模式
    let exclude_regexes: Vec<Regex> = if let Some(patterns) = exclude_patterns {
        patterns.iter()
            .filter_map(|pattern| Regex::new(pattern).ok())
            .collect()
    } else {
        Vec::new()
    };
    
    // 创建进度条
    let pb = ProgressBar::new(max_pages as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) {msg}")
            .unwrap()
            .progress_chars("#>-"),
    );
    
    let semaphore = Arc::new(Semaphore::new(threads as usize));
    let mut current_depth = 0;
    let mut scanned_count = 0;
    
    while current_depth < depth && scanned_count < max_pages {
        let urls_to_process = {
            let mut queue = url_queue.lock().await;
            if queue.is_empty() {
                break;
            }
            std::mem::take(&mut *queue)
        };
        
        if urls_to_process.is_empty() {
            break;
        }
        
        pb.set_message(format!("深度 {}/{} - 扫描中...", current_depth + 1, depth));
        
        let mut tasks = Vec::new();
        
        for url in urls_to_process {
            if scanned_count >= max_pages {
                break;
            }
            
            let client = client.clone();
            let visited_urls = visited_urls.clone();
            let found_urls = found_urls.clone();
            let url_queue = url_queue.clone();
            let semaphore = semaphore.clone();
            let pb = pb.clone();
            let base_domain = base_domain.clone();
            let exclude_exts = exclude_exts.clone();
            let exclude_regexes = exclude_regexes.clone();
            
            let task = tokio::spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();
                
                // 检查是否已访问
                {
                    let mut visited = visited_urls.lock().await;
                    if visited.contains(&url) {
                        return;
                    }
                    visited.insert(url.clone());
                }
                
                // 扫描单个URL
                match scan_recursive_url(&client, &url, verbose).await {
                    Ok(result) => {
                        if result.found {
                            let mut found = found_urls.lock().await;
                            found.push(result.clone());
                            
                            // 暂停进度条，输出结果，然后恢复
                            if verbose || !show_only_found {
                                pb.suspend(|| {
                                    println!(" ✓ `{}` [{}] {} bytes", 
                                        result.url.bright_white(),
                                        format!("{}", result.status_code).bright_yellow(),
                                        result.content_length.unwrap_or(0)
                                    );
                                });
                            }
                            
                            // 提取新链接
                            if let Ok(response) = client.get(&url).send().await {
                                if let Ok(content) = response.text().await {
                                    let new_urls = extract_links_from_content(&content, &url, &base_domain, &exclude_exts, &exclude_regexes);
                                    if verbose && !new_urls.is_empty() {
                                        pb.suspend(|| {
                                            println!("   📎 从 {} 提取到 {} 个新链接", url, new_urls.len());
                                        });
                                    }
                                    let mut queue = url_queue.lock().await;
                                    queue.extend(new_urls);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        if verbose {
                            pb.suspend(|| {
                                println!(" ✗ {} - {}", url.red(), e);
                            });
                        }
                    }
                }
                
                pb.inc(1);
            });
            
            tasks.push(task);
            scanned_count += 1;
        }
        
        // 等待当前深度的所有任务完成
        for task in tasks {
            let _ = task.await;
        }
        
        current_depth += 1;
    }
    
    pb.finish_with_message("扫描完成");
    
    // 输出结果
    let found_results = found_urls.lock().await;
    let scan_results: Vec<ScanResult> = found_results.clone();
    
    println!("\n{}", "📊 扫描结果统计".bright_cyan().bold());
    println!("总扫描页面: {}", scanned_count.to_string().bright_yellow());
    println!("发现有效页面: {}", scan_results.len().to_string().bright_green());
    println!("扫描深度: {}", current_depth.to_string().bright_blue());
    
    // 输出结果到文件或控制台
    output_scan_results(&scan_results, show_only_found, output_format, output_file).await?;
    
    Ok(())
}

// 扫描单个递归URL
async fn scan_recursive_url(
    client: &reqwest::Client,
    url: &str,
    verbose: bool,
) -> Result<ScanResult> {
    let start_time = std::time::Instant::now();
    
    match client.get(url).send().await {
        Ok(response) => {
            let status_code = response.status().as_u16();
            let content_length = response.content_length();
            let content_type = response.headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            
            let title = if status_code == 200 {
                extract_title(response).await.unwrap_or(None)
            } else {
                None
            };
            
            let found = matches!(status_code, 200 | 301 | 302 | 403);
            
            if verbose {
                let duration = start_time.elapsed();
                println!("{} {} [{}] {:.2}ms", 
                    if found { "✓".green() } else { "✗".red() },
                    url,
                    status_code.to_string().bright_yellow(),
                    duration.as_millis()
                );
            }
            
            Ok(ScanResult {
                url: url.to_string(),
                status_code,
                content_length,
                content_type,
                title,
                path: url.to_string(),
                found,
            })
        }
        Err(e) => {
            if verbose {
                println!("{} {} - {}", "✗".red(), url, e);
            }
            
            Ok(ScanResult {
                url: url.to_string(),
                status_code: 0,
                content_length: None,
                content_type: None,
                title: None,
                path: url.to_string(),
                found: false,
            })
        }
    }
}

// 从HTML内容中提取链接
fn extract_links_from_content(
    content: &str,
    base_url: &str,
    base_domain: &str,
    exclude_exts: &HashSet<String>,
    exclude_regexes: &[Regex],
) -> Vec<String> {
    let mut links = Vec::new();
    let base_url_parsed = match Url::parse(base_url) {
        Ok(url) => url,
        Err(_) => return links,
    };
    
    // 提取href链接 - 支持带引号和不带引号的情况
    let href_regex = Regex::new(r#"href\s*=\s*(?:["']([^"']+)["']|([^\s>]+))"#).unwrap();
    for cap in href_regex.captures_iter(content) {
        let link_str = if let Some(quoted_link) = cap.get(1) {
            quoted_link.as_str()
        } else if let Some(unquoted_link) = cap.get(2) {
            unquoted_link.as_str()
        } else {
            continue;
        };
        
        // 跳过无效链接
        if link_str.is_empty() || link_str.starts_with('#') || link_str.starts_with("javascript:") || link_str.starts_with("mailto:") {
            continue;
        }
        
        // 解析相对URL为绝对URL
        if let Ok(absolute_url) = base_url_parsed.join(link_str) {
            let url_str = absolute_url.to_string();
            
            // 检查是否为同域名或子域名
            if let Some(host) = absolute_url.host_str() {
                if host == base_domain || host.ends_with(&format!(".{}", base_domain)) {
                    // 检查是否应该排除
                    if !should_exclude_url(&url_str, exclude_exts, exclude_regexes) {
                        links.push(url_str);
                    }
                }
            }
        }
    }
    
    // 提取src链接（图片、脚本等）- 也支持带引号和不带引号的情况
    let src_regex = Regex::new(r#"src\s*=\s*(?:["']([^"']+)["']|([^\s>]+))"#).unwrap();
    for cap in src_regex.captures_iter(content) {
        let link_str = if let Some(quoted_link) = cap.get(1) {
            quoted_link.as_str()
        } else if let Some(unquoted_link) = cap.get(2) {
            unquoted_link.as_str()
        } else {
            continue;
        };
        
        // 跳过无效链接
        if link_str.is_empty() || link_str.starts_with("data:") || link_str.starts_with("javascript:") {
            continue;
        }
        
        if let Ok(absolute_url) = base_url_parsed.join(link_str) {
            let url_str = absolute_url.to_string();
            
            if let Some(host) = absolute_url.host_str() {
                if host == base_domain || host.ends_with(&format!(".{}", base_domain)) {
                    if !should_exclude_url(&url_str, exclude_exts, exclude_regexes) {
                        links.push(url_str);
                    }
                }
            }
        }
    }
    
    // 去重
    links.sort();
    links.dedup();
    links
}

// 检查URL是否应该被排除
fn should_exclude_url(
    url: &str,
    exclude_exts: &HashSet<String>,
    exclude_regexes: &[Regex],
) -> bool {
    // 检查扩展名
    if let Ok(parsed_url) = Url::parse(url) {
        if let Some(path_segments) = parsed_url.path_segments() {
            if let Some(last_segment) = path_segments.last() {
                if let Some(ext_pos) = last_segment.rfind('.') {
                    let ext = &last_segment[ext_pos + 1..].to_lowercase();
                    if exclude_exts.contains(ext) {
                        return true;
                    }
                }
            }
        }
    }
    
    // 检查正则表达式模式
    for regex in exclude_regexes {
        if regex.is_match(url) {
            return true;
        }
    }
    
    false
}