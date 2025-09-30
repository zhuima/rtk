use std::fs::File;
use std::io::{self, BufRead};
use std::sync::Arc;
use std::time::Duration;
use anyhow::Result;
use colored::*;
use futures::stream::StreamExt;
use indicatif::ProgressBar;
use indicatif::ProgressStyle;
use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT};
use reqwest::redirect::Policy;
use serde::{Serialize, Deserialize};
use strum::{EnumIter, Display};
use tokio::sync::{Semaphore, Mutex};
use crate::utils::output;

#[derive(Clone, Debug, clap::Subcommand, EnumIter, Display, Serialize, Deserialize)]
pub enum WebScanCommands {
    /// 目录路径爆破扫描
    #[clap(name = "dir")]
    Directory {
        /// 目标URL (例如: http://example.com)
        #[arg(short, long)]
        target: String,

        /// 自定义字典文件路径
        #[arg(short, long)]
        wordlist: Option<String>,

        /// 扫描线程数/并发数
        #[arg(short, long, default_value = "50")]
        threads: u32,

        /// 超时时间(秒)
        #[arg(short, long, default_value = "10")]
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

        /// 只显示找到的路径
        #[arg(long, default_value = "false")]
        show_only_found: bool,

        /// 输出格式 (text, json, csv)
        #[arg(short, long, default_value = "text")]
        output_format: String,

        /// 输出文件路径
        #[arg(long)]
        output_file: Option<String>,

        /// 详细输出
        #[arg(short, long, default_value = "false")]
        verbose: bool,

        /// 自定义User-Agent
        #[arg(long, default_value = "rtk-web-scanner/1.0")]
        user_agent: String,

        /// 自定义HTTP头 (格式: "Header: Value")
        #[arg(long)]
        headers: Option<Vec<String>>,
    },

    /// 隐藏文件发现
    #[clap(name = "hidden")]
    Hidden {
        /// 目标URL (例如: http://example.com)
        #[arg(short, long)]
        target: String,

        /// 扫描线程数/并发数
        #[arg(short, long, default_value = "30")]
        threads: u32,

        /// 超时时间(秒)
        #[arg(short, long, default_value = "10")]
        timeout: u64,

        /// 详细输出
        #[arg(short, long, default_value = "false")]
        verbose: bool,

        /// 输出格式 (text, json)
        #[arg(short, long, default_value = "text")]
        output_format: String,

        /// 输出文件路径
        #[arg(long)]
        output_file: Option<String>,

        /// 自定义User-Agent
        #[arg(long, default_value = "rtk-web-scanner/1.0")]
        user_agent: String,
    },

    /// 备份文件发现
    #[clap(name = "backup")]
    Backup {
        /// 目标URL (例如: http://example.com)
        #[arg(short, long)]
        target: String,

        /// 扫描线程数/并发数
        #[arg(short, long, default_value = "30")]
        threads: u32,

        /// 超时时间(秒)
        #[arg(short, long, default_value = "10")]
        timeout: u64,

        /// 详细输出
        #[arg(short, long, default_value = "false")]
        verbose: bool,

        /// 输出格式 (text, json)
        #[arg(short, long, default_value = "text")]
        output_format: String,

        /// 输出文件路径
        #[arg(long)]
        output_file: Option<String>,

        /// 自定义User-Agent
        #[arg(long, default_value = "rtk-web-scanner/1.0")]
        user_agent: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub url: String,
    pub status_code: u16,
    pub content_length: Option<u64>,
    pub content_type: Option<String>,
    pub title: Option<String>,
    pub path: String,
    pub found: bool,
    pub scan_type: String,
}

/// 处理Web扫描命令
pub async fn handle_web_scan_command(command: WebScanCommands) -> Result<()> {
    match command {
        WebScanCommands::Directory {
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
            directory_scan(
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
        WebScanCommands::Hidden {
            target,
            threads,
            timeout,
            verbose,
            output_format,
            output_file,
            user_agent,
        } => {
            hidden_files_scan(
                &target,
                threads,
                timeout,
                verbose,
                &output_format,
                output_file,
                &user_agent,
            ).await?;
        }
        WebScanCommands::Backup {
            target,
            threads,
            timeout,
            verbose,
            output_format,
            output_file,
            user_agent,
        } => {
            backup_files_scan(
                &target,
                threads,
                timeout,
                verbose,
                &output_format,
                output_file,
                &user_agent,
            ).await?;
        }
    }
    Ok(())
}

/// 目录路径爆破扫描
async fn directory_scan(
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
    output::print_header("🔍 Web Directory Scanning");
    output::print_info(&format!("Target: {}", target.bright_cyan()));
    output::print_info(&format!("Threads: {}", threads.to_string().bright_yellow()));
    output::print_info(&format!("Timeout: {}s", timeout.to_string().bright_yellow()));

    let client = create_http_client(timeout, follow_redirects, user_agent, headers).await?;
    let extensions: Vec<&str> = extensions.split(',').collect();
    let wordlist = generate_wordlist(wordlist, &extensions).await?;

    output::print_info(&format!("Wordlist size: {}", wordlist.len().to_string().bright_green()));

    let semaphore = Arc::new(Semaphore::new(threads as usize));
    let results = Arc::new(Mutex::new(Vec::new()));
    let progress_bar = ProgressBar::new(wordlist.len() as u64);
    progress_bar.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
            .unwrap()
            .progress_chars("#>-"),
    );

    let mut tasks = Vec::new();
    for path in wordlist {
        let client = client.clone();
        let target = target.to_string();
        let semaphore = semaphore.clone();
        let results = results.clone();
        let progress_bar = progress_bar.clone();

        let task = tokio::spawn(async move {
            let _permit = semaphore.acquire().await.unwrap();
            
            match scan_single_path(&client, &target, &path, verbose, "directory").await {
                Ok(result) => {
                    if verbose || result.found {
                        let status_color = match result.status_code {
                            200..=299 => "green",
                            300..=399 => "yellow", 
                            400..=499 => "red",
                            500..=599 => "magenta",
                            _ => "white",
                        };
                        
                        if result.found {
                            println!("{} {} [{}] {} bytes", 
                                "✓".bright_green(),
                                result.url.bright_cyan(),
                                result.status_code.to_string().color(status_color),
                                result.content_length.unwrap_or(0).to_string().bright_white()
                            );
                        }
                    }
                    
                    results.lock().await.push(result);
                }
                Err(e) => {
                    if verbose {
                        eprintln!("Error scanning {}: {}", path, e);
                    }
                }
            }
            
            progress_bar.inc(1);
        });
        
        tasks.push(task);
    }

    // 等待所有任务完成
    for task in tasks {
        task.await?;
    }

    progress_bar.finish_with_message("Scan completed!");

    let results = results.lock().await;
    output_scan_results(&results, show_only_found, output_format, output_file).await?;

    Ok(())
}

/// 隐藏文件发现扫描
async fn hidden_files_scan(
    target: &str,
    threads: u32,
    timeout: u64,
    verbose: bool,
    output_format: &str,
    output_file: Option<String>,
    user_agent: &str,
) -> Result<()> {
    output::print_header("🔍 Hidden Files Discovery");
    output::print_info(&format!("Target: {}", target.bright_cyan()));

    let client = create_http_client(timeout, true, user_agent, None).await?;
    let hidden_files = get_hidden_files_wordlist();

    output::print_info(&format!("Checking {} hidden files", hidden_files.len().to_string().bright_green()));

    let semaphore = Arc::new(Semaphore::new(threads as usize));
    let results = Arc::new(Mutex::new(Vec::new()));
    let progress_bar = ProgressBar::new(hidden_files.len() as u64);
    progress_bar.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
            .unwrap()
            .progress_chars("#>-"),
    );

    let mut tasks = Vec::new();
    for file in hidden_files {
        let client = client.clone();
        let target = target.to_string();
        let semaphore = semaphore.clone();
        let results = results.clone();
        let progress_bar = progress_bar.clone();

        let task = tokio::spawn(async move {
            let _permit = semaphore.acquire().await.unwrap();
            
            match scan_single_path(&client, &target, &file, verbose, "hidden").await {
                Ok(result) => {
                    if result.found {
                        println!("{} {} [{}] {} bytes", 
                            "🔍".bright_yellow(),
                            result.url.bright_cyan(),
                            result.status_code.to_string().bright_green(),
                            result.content_length.unwrap_or(0).to_string().bright_white()
                        );
                    }
                    
                    results.lock().await.push(result);
                }
                Err(e) => {
                    if verbose {
                        eprintln!("Error scanning {}: {}", file, e);
                    }
                }
            }
            
            progress_bar.inc(1);
        });
        
        tasks.push(task);
    }

    for task in tasks {
        task.await?;
    }

    progress_bar.finish_with_message("Hidden files scan completed!");

    let results = results.lock().await;
    output_scan_results(&results, true, output_format, output_file).await?;

    Ok(())
}

/// 备份文件发现扫描
async fn backup_files_scan(
    target: &str,
    threads: u32,
    timeout: u64,
    verbose: bool,
    output_format: &str,
    output_file: Option<String>,
    user_agent: &str,
) -> Result<()> {
    output::print_header("🔍 Backup Files Discovery");
    output::print_info(&format!("Target: {}", target.bright_cyan()));

    let client = create_http_client(timeout, true, user_agent, None).await?;
    let backup_patterns = get_backup_files_wordlist();

    output::print_info(&format!("Checking {} backup file patterns", backup_patterns.len().to_string().bright_green()));

    let semaphore = Arc::new(Semaphore::new(threads as usize));
    let results = Arc::new(Mutex::new(Vec::new()));
    let progress_bar = ProgressBar::new(backup_patterns.len() as u64);
    progress_bar.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
            .unwrap()
            .progress_chars("#>-"),
    );

    let mut tasks = Vec::new();
    for pattern in backup_patterns {
        let client = client.clone();
        let target = target.to_string();
        let semaphore = semaphore.clone();
        let results = results.clone();
        let progress_bar = progress_bar.clone();

        let task = tokio::spawn(async move {
            let _permit = semaphore.acquire().await.unwrap();
            
            match scan_single_path(&client, &target, &pattern, verbose, "backup").await {
                Ok(result) => {
                    if result.found {
                        println!("{} {} [{}] {} bytes", 
                            "💾".bright_blue(),
                            result.url.bright_cyan(),
                            result.status_code.to_string().bright_green(),
                            result.content_length.unwrap_or(0).to_string().bright_white()
                        );
                    }
                    
                    results.lock().await.push(result);
                }
                Err(e) => {
                    if verbose {
                        eprintln!("Error scanning {}: {}", pattern, e);
                    }
                }
            }
            
            progress_bar.inc(1);
        });
        
        tasks.push(task);
    }

    for task in tasks {
        task.await?;
    }

    progress_bar.finish_with_message("Backup files scan completed!");

    let results = results.lock().await;
    output_scan_results(&results, true, output_format, output_file).await?;

    Ok(())
}

/// 生成扫描字典
async fn generate_wordlist(wordlist_path: Option<String>, extensions: &[&str]) -> Result<Vec<String>> {
    let mut wordlist = Vec::new();

    if let Some(path) = wordlist_path {
        let file = File::open(&path)?;
        let reader = io::BufReader::new(file);
        
        for line in reader.lines() {
            let line = line?;
            let trimmed = line.trim();
            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                wordlist.push(trimmed.to_string());
                
                // 为每个路径添加扩展名
                for ext in extensions {
                    wordlist.push(format!("{}.{}", trimmed, ext));
                }
            }
        }
    } else {
        wordlist = get_default_wordlist();
        
        // 为默认字典添加扩展名
        let base_wordlist = wordlist.clone();
        for word in base_wordlist {
            for ext in extensions {
                wordlist.push(format!("{}.{}", word, ext));
            }
        }
    }

    Ok(wordlist)
}

/// 获取默认目录字典
fn get_default_wordlist() -> Vec<String> {
    vec![
        // 常见目录
        "admin", "administrator", "login", "panel", "dashboard", "control",
        "manager", "management", "config", "configuration", "settings",
        "backup", "backups", "bak", "old", "temp", "tmp", "test", "testing",
        "dev", "development", "staging", "prod", "production", "www",
        "public", "private", "secure", "security", "auth", "authentication",
        "user", "users", "account", "accounts", "profile", "profiles",
        "api", "apis", "service", "services", "web", "webservice",
        "upload", "uploads", "download", "downloads", "file", "files",
        "image", "images", "img", "photo", "photos", "pic", "pics",
        "doc", "docs", "document", "documents", "pdf", "archive", "archives",
        "log", "logs", "error", "errors", "debug", "cache", "data",
        "database", "db", "sql", "mysql", "postgres", "oracle",
        "include", "includes", "lib", "library", "libraries", "vendor",
        "assets", "static", "css", "js", "javascript", "style", "styles",
        "theme", "themes", "template", "templates", "layout", "layouts",
        "plugin", "plugins", "module", "modules", "component", "components",
        "widget", "widgets", "app", "application", "applications",
        "system", "sys", "bin", "sbin", "usr", "var", "etc", "opt",
        "home", "root", "mail", "email", "news", "blog", "forum", "forums",
        "shop", "store", "cart", "checkout", "payment", "pay", "order", "orders",
        "search", "find", "help", "support", "contact", "about", "info",
        "sitemap", "robots", "favicon", "crossdomain", "clientaccesspolicy",
    ].iter().map(|s| s.to_string()).collect()
}

/// 获取隐藏文件字典
fn get_hidden_files_wordlist() -> Vec<String> {
    vec![
        // 隐藏配置文件
        ".htaccess", ".htpasswd", ".htgroup", ".htusers",
        ".env", ".env.local", ".env.production", ".env.development",
        ".git", ".gitignore", ".gitconfig", ".github",
        ".svn", ".bzr", ".hg", ".cvs",
        ".DS_Store", "._.DS_Store", "Thumbs.db", "desktop.ini",
        ".bash_history", ".bash_profile", ".bashrc", ".profile",
        ".ssh", ".ssh/id_rsa", ".ssh/id_dsa", ".ssh/authorized_keys",
        ".mysql_history", ".psql_history", ".sqlite_history",
        ".vimrc", ".vim", ".emacs", ".nano",
        ".config", ".cache", ".local", ".mozilla", ".gnupg",
        ".aws", ".docker", ".kube", ".terraform",
        ".npmrc", ".yarnrc", ".bowerrc", ".editorconfig",
        ".eslintrc", ".jshintrc", ".jscsrc", ".stylelintrc",
        ".travis.yml", ".gitlab-ci.yml", ".circleci", ".github/workflows",
        ".dockerignore", ".gitattributes", ".mailmap",
        ".well-known", ".well-known/security.txt", ".well-known/acme-challenge",
    ].iter().map(|s| s.to_string()).collect()
}

/// 获取备份文件字典
fn get_backup_files_wordlist() -> Vec<String> {
    vec![
        // 常见备份文件扩展名和模式
        "index.php.bak", "index.html.bak", "config.php.bak", "database.sql.bak",
        "backup.sql", "dump.sql", "db.sql", "database.sql", "data.sql",
        "backup.zip", "backup.tar.gz", "backup.rar", "site.zip", "www.zip",
        "config.bak", "config.old", "config.orig", "config.save",
        "web.config.bak", "web.config.old", ".htaccess.bak", ".htaccess.old",
        "wp-config.php.bak", "wp-config.php.old", "wp-config.php.save",
        "settings.php.bak", "local_settings.py.bak", "config.json.bak",
        "package.json.bak", "composer.json.bak", "requirements.txt.bak",
        "Dockerfile.bak", "docker-compose.yml.bak", "nginx.conf.bak",
        "apache.conf.bak", "httpd.conf.bak", "my.cnf.bak", "php.ini.bak",
        "readme.txt", "README.md", "CHANGELOG.md", "TODO.txt", "INSTALL.txt",
        "LICENSE.txt", "COPYING.txt", "VERSION.txt", "HISTORY.txt",
        "error_log", "access_log", "debug.log", "application.log", "system.log",
        "phpinfo.php", "info.php", "test.php", "debug.php", "admin.php",
        "login.php", "auth.php", "connect.php", "connection.php", "db.php",
        "install.php", "setup.php", "upgrade.php", "migration.php",
        "shell.php", "webshell.php", "backdoor.php", "cmd.php", "eval.php",
    ].iter().map(|s| s.to_string()).collect()
}

/// 创建HTTP客户端
async fn create_http_client(
    timeout: u64,
    follow_redirects: bool,
    user_agent: &str,
    headers: Option<Vec<String>>,
) -> Result<reqwest::Client> {
    let mut client_builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout))
        .danger_accept_invalid_certs(true);

    if follow_redirects {
        client_builder = client_builder.redirect(Policy::limited(10));
    } else {
        client_builder = client_builder.redirect(Policy::none());
    }

    let mut default_headers = HeaderMap::new();
    default_headers.insert(USER_AGENT, HeaderValue::from_str(user_agent)?);

    if let Some(custom_headers) = headers {
        for header in custom_headers {
            if let Some((key, value)) = header.split_once(':') {
                let key = key.trim();
                let value = value.trim();
                if let (Ok(header_name), Ok(header_value)) = (
                    reqwest::header::HeaderName::from_bytes(key.as_bytes()),
                    HeaderValue::from_str(value)
                ) {
                    default_headers.insert(header_name, header_value);
                }
            }
        }
    }

    client_builder = client_builder.default_headers(default_headers);

    Ok(client_builder.build()?)
}

/// 扫描单个路径
async fn scan_single_path(
    client: &reqwest::Client,
    target: &str,
    path: &str,
    verbose: bool,
    scan_type: &str,
) -> Result<ScanResult> {
    let url = if path.starts_with('/') {
        format!("{}{}", target.trim_end_matches('/'), path)
    } else {
        format!("{}/{}", target.trim_end_matches('/'), path)
    };

    let response = client.get(&url).send().await?;
    let status_code = response.status().as_u16();
    let content_length = response.content_length();
    let content_type = response.headers()
        .get("content-type")
        .and_then(|ct| ct.to_str().ok())
        .map(|s| s.to_string());

    let title = if status_code == 200 {
        extract_title(response).await.unwrap_or(None)
    } else {
        None
    };

    let found = match status_code {
        200..=299 => true,
        403 => true, // 403 也可能表示目录存在但无权限
        _ => false,
    };

    Ok(ScanResult {
        url,
        status_code,
        content_length,
        content_type,
        title,
        path: path.to_string(),
        found,
        scan_type: scan_type.to_string(),
    })
}

/// 从HTML中提取标题
fn extract_title_from_html(text: &str) -> Option<String> {
    let re = regex::Regex::new(r"<title[^>]*>([^<]*)</title>").ok()?;
    re.captures(text)?.get(1).map(|m| m.as_str().trim().to_string())
}

/// 提取响应标题
async fn extract_title(response: reqwest::Response) -> Result<Option<String>> {
    let text = response.text().await?;
    Ok(extract_title_from_html(&text))
}

/// 输出扫描结果
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

    let found_count = results.iter().filter(|r| r.found).count();
    output::print_success(&format!("Scan completed! Found {} accessible paths", found_count));

    Ok(())
}

/// 输出文本格式结果
async fn output_text_results(results: &[&ScanResult], output_file: Option<String>) -> Result<()> {
    let mut output_lines = Vec::new();
    
    output_lines.push("=== Web Scan Results ===".to_string());
    output_lines.push("".to_string());

    for result in results {
        if result.found {
            let mut line = format!("[{}] {} - {}", 
                result.status_code,
                result.url,
                result.scan_type.to_uppercase()
            );
            
            if let Some(length) = result.content_length {
                line.push_str(&format!(" ({} bytes)", length));
            }
            
            if let Some(title) = &result.title {
                line.push_str(&format!(" - \"{}\"", title));
            }
            
            output_lines.push(line);
        }
    }

    if let Some(file_path) = output_file {
        tokio::fs::write(&file_path, output_lines.join("\n")).await?;
        output::print_info(&format!("Results saved to: {}", file_path));
    } else {
        for line in output_lines {
            println!("{}", line);
        }
    }

    Ok(())
}

/// 输出JSON格式结果
async fn output_json_results(results: &[&ScanResult], output_file: Option<String>) -> Result<()> {
    let json_output = serde_json::to_string_pretty(results)?;
    
    if let Some(file_path) = output_file {
        tokio::fs::write(&file_path, json_output).await?;
        output::print_info(&format!("Results saved to: {}", file_path));
    } else {
        println!("{}", json_output);
    }

    Ok(())
}

/// 输出CSV格式结果
async fn output_csv_results(results: &[&ScanResult], output_file: Option<String>) -> Result<()> {
    let mut csv_lines = Vec::new();
    csv_lines.push("URL,Status Code,Content Length,Content Type,Title,Path,Found,Scan Type".to_string());

    for result in results {
        let line = format!("{},{},{},{},{},{},{},{}",
            result.url,
            result.status_code,
            result.content_length.map_or("".to_string(), |l| l.to_string()),
            result.content_type.as_deref().unwrap_or(""),
            result.title.as_deref().unwrap_or(""),
            result.path,
            result.found,
            result.scan_type
        );
        csv_lines.push(line);
    }

    let csv_output = csv_lines.join("\n");
    
    if let Some(file_path) = output_file {
        tokio::fs::write(&file_path, csv_output).await?;
        output::print_info(&format!("Results saved to: {}", file_path));
    } else {
        println!("{}", csv_output);
    }

    Ok(())
}