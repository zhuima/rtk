use crate::utils::output;
use anyhow::Result;
use std::time::Duration;

// Enhanced network scanning structures and functions
#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
pub struct ScanResult {
    pub host: String,
    pub port: u16,
    pub protocol: String,
    pub state: String,
    pub service: Option<String>,
    pub version: Option<String>,
    pub banner: Option<String>,
    pub ssl_info: Option<SslInfo>,
    pub vulnerabilities: Vec<Vulnerability>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
pub struct SslInfo {
    pub version: String,
    pub cipher_suite: String,
    pub certificate: Option<CertificateInfo>,
    pub expiration: Option<String>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
pub struct CertificateInfo {
    pub subject: String,
    pub issuer: String,
    pub valid_from: String,
    pub valid_to: String,
    pub fingerprint: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
pub struct Vulnerability {
    pub cve_id: String,
    pub severity: String,
    pub description: String,
    pub service: String,
}

// Common port service mapping
pub const COMMON_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995,
    1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 9200, 27017
];

const SERVICE_BANNERS: &[(&str, &str)] = &[
    ("SSH", "SSH-"),
    ("HTTP", "HTTP/"),
    ("HTTPS", "HTTP/"),
    ("FTP", "220 "),
    ("SMTP", "220 "),
    ("POP3", "+OK"),
    ("IMAP", "* OK"),
    ("MySQL", "mysql"),
    ("PostgreSQL", "postgresql"),
    ("Redis", "REDIS"),
    ("MongoDB", "mongodb"),
];

// Enhanced network scanner with service detection and vulnerability scanning
pub async fn enhanced_scan(
    target: &str,
    start_port: u16,
    end_port: u16,
    timeout_ms: u64,
    service_detection: bool,
    ssl_scan: bool,
    output_format: &str,
    speed: u8,
    concurrency: u32,
    common_ports_only: bool,
) -> Result<()> {
    output::print_header(&format!("🚀 High-Performance Network Scan: {}", target));

    // Parse target and get hosts to scan
    let hosts = parse_target(target).await?;
    let ports_to_scan = if common_ports_only {
        COMMON_PORTS.to_vec()
    } else {
        (start_port..=end_port).collect()
    };

    output::print_info(&format!("Discovered {} hosts to scan, {} ports each", hosts.len(), ports_to_scan.len()));

    // Determine concurrency based on user input or speed
    let actual_concurrency = if concurrency > 0 {
        concurrency as usize
    } else {
        std::cmp::max(speed as usize * 50, 200) // Default high concurrency
    };
    output::print_info(&format!("Using high concurrency: {} simultaneous connections", actual_concurrency));

    let mut all_results = Vec::new();

    // Scan each host with high concurrency
    for host in &hosts {
        let host_results = fast_scan_host(
            &host,
            &ports_to_scan,
            Duration::from_millis(timeout_ms),
            service_detection,
            ssl_scan,
            actual_concurrency,
        ).await?;

        all_results.extend(host_results);
    }

    // Final summary
    let total_open_ports = all_results.iter().filter(|r| r.state == "open").count();
    output::print_success(&format!(
        "\n✅ Scan completed: {} hosts, {} open ports found",
        hosts.len(),
        total_open_ports
    ));

    // Only show detailed results if not real-time or non-text format
    if output_format != "text" {
        output_results(&all_results, output_format)?;
    }

    Ok(())
}

async fn is_host_alive(host: &str, timeout: Duration) -> bool {
    // Try multiple methods to determine if host is alive

    // Method 1: TCP ping on port 80 (commonly open)
    if let Ok(_) = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(format!("{}:80", host))).await {
        return true;
    }

    // Method 2: TCP ping on port 22 (SSH)
    if let Ok(_) = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(format!("{}:22", host))).await {
        return true;
    }

    // Method 3: TCP ping on port 443 (HTTPS)
    if let Ok(_) = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(format!("{}:443", host))).await {
        return true;
    }

    // Method 4: DNS resolution
    if let Ok(_) = tokio::net::lookup_host(format!("{}:80", host)).await {
        // If DNS resolves, assume host might be alive even if ports are filtered
        return true;
    }

    false
}

// High-performance concurrent port scanner with improved output
async fn fast_scan_host(
    host: &str,
    ports: &[u16],
    timeout: Duration,
    service_detection: bool,
    ssl_scan: bool,
    concurrency: usize,
) -> Result<Vec<ScanResult>> {
    use indicatif::ProgressBar;
    use indicatif::ProgressStyle;
    use std::sync::Arc;

    let results = Arc::new(std::sync::Mutex::new(Vec::new()));
    let open_ports_found = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    // Create progress bar with cleaner template
    let pb = Arc::new(ProgressBar::new(ports.len() as u64));
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
        .unwrap()
        .progress_chars("#>-"));

    output::print_normal(&format!("\n🎯 Scanning {} ports on {}", ports.len(), host));

    // Use higher concurrency and batch processing
    let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency));
    let mut tasks = Vec::new();

    // Process ports in batches for better performance
    let batch_size = concurrency;
    for chunk in ports.chunks(batch_size) {
        let semaphore = semaphore.clone();
        let host = host.to_string();
        let timeout = timeout;
        let service_detection = service_detection;
        let ssl_scan = ssl_scan;
        let pb = pb.clone();
        let results = results.clone();
        let open_ports_found = open_ports_found.clone();
        let chunk = chunk.to_vec();

        let task = tokio::spawn(async move {
            let mut batch_results = Vec::new();

            for &port in &chunk {
                let _permit = semaphore.acquire().await.unwrap();
                let result = fast_scan_single_port(&host, port, timeout, service_detection, ssl_scan).await;

                if let Ok(scan_result) = result {
                    if scan_result.state == "open" {
                        // 实时显示发现的开放端口，格式更清晰
                        let service_info = scan_result.service.as_deref().unwrap_or("unknown");
                        let port_count = open_ports_found.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;

                        // 输出格式优化，避免打断进度条，使用颜色高亮
                        use colored::*;
                        eprintln!("\r{} {}:{} - {:<15} [{}]",
                            "🔓 Found open port:".bright_green().bold(),
                            host.bright_white(),
                            port.to_string().bright_cyan().bold(),
                            service_info.bright_yellow(),
                            port_count.to_string().bright_magenta());

                        if let Some(banner) = &scan_result.banner {
                            if !banner.is_empty() && banner.len() < 100 {
                                use colored::*;
                                eprintln!("   {} {}", "📋 Banner:".bright_blue(), banner.bright_white());
                            }
                        }

                        // 显示SSL/TLS信息
                        if let Some(ssl_info) = &scan_result.ssl_info {
                            use colored::*;
                            eprintln!("   {} {} ({})",
                                "🔒 SSL/TLS:".bright_cyan(),
                                ssl_info.version.bright_white(),
                                ssl_info.cipher_suite.bright_yellow());

                            if let Some(expiration) = &ssl_info.expiration {
                                let exp_color = if expiration.contains("CRITICAL") || expiration.contains("EXPIRED") {
                                    colored::Color::Red
                                } else if expiration.contains("WARNING") {
                                    colored::Color::Yellow
                                } else {
                                    colored::Color::Green
                                };
                                eprintln!("      {}", expiration.color(exp_color));
                            }

                            if let Some(cert) = &ssl_info.certificate {
                                eprintln!("      {} {}", "Subject:".bright_blue(), cert.subject.bright_white());
                                eprintln!("      {} {}", "Issuer:".bright_blue(), cert.issuer.bright_white());
                                eprintln!("      {} {}", "Fingerprint:".bright_blue(), cert.fingerprint.bright_white());
                            }
                        }

                        // 显示漏洞信息
                        if !scan_result.vulnerabilities.is_empty() {
                            use colored::*;
                            for vuln in &scan_result.vulnerabilities {
                                let severity_color = match vuln.severity.as_str() {
                                    "Critical" => colored::Color::Red,
                                    "High" => colored::Color::BrightRed,
                                    "Medium" => colored::Color::Yellow,
                                    "Low" => colored::Color::BrightYellow,
                                    _ => colored::Color::White,
                                };
                                eprintln!("   {} {} ({})",
                                    "⚠️  Vulnerability:".bright_red(),
                                    vuln.cve_id.color(severity_color).bold(),
                                    vuln.severity.color(severity_color));
                            }
                        }

                        batch_results.push(scan_result);
                    }
                }

                pb.inc(1);
            }

            batch_results
        });

        tasks.push(task);
    }

    // Wait for all tasks to complete with timeout
    let timeout_duration = Duration::from_secs(300); // 5 minute timeout for entire scan

    for task in tasks {
        match tokio::time::timeout(timeout_duration, task).await {
            Ok(Ok(batch_results)) => {
                let mut results = results.lock().unwrap();
                results.extend(batch_results);
            }
            Ok(Err(_)) => {
                // Task panicked, continue with others
                continue;
            }
            Err(_) => {
                // Task timeout, continue with others
                continue;
            }
        }
    }

    let final_results = std::mem::take(&mut *results.lock().unwrap());
    pb.finish_with_message(format!("Scan complete"));

    // 清理最后的输出
    eprintln!();

    Ok(final_results)
}

// Optimized single port scanner with reduced overhead
async fn fast_scan_single_port(
    host: &str,
    port: u16,
    timeout: Duration,
    service_detection: bool,
    ssl_scan: bool,
) -> Result<ScanResult> {
    use std::net::{SocketAddr, ToSocketAddrs};

    let addr = format!("{}:{}", host, port);
    let socket_addr: SocketAddr = match addr.parse() {
        Ok(addr) => addr,
        Err(_) => {
            // Fallback to DNS resolution
            match addr.to_socket_addrs() {
                Ok(mut addrs) => addrs.next().unwrap_or_else(|| SocketAddr::new(host.parse().unwrap_or_else(|_| "127.0.0.1".parse().unwrap()), port)),
                Err(_) => return Ok(create_closed_result(host, port)),
            }
        }
    };

    let mut result = ScanResult {
        host: host.to_string(),
        port,
        protocol: "tcp".to_string(),
        state: "closed".to_string(),
        service: None,
        version: None,
        banner: None,
        ssl_info: None,
        vulnerabilities: Vec::new(),
    };

    // Use optimized timeout connect
    match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&socket_addr)).await {
        Ok(Ok(_stream)) => {
            result.state = "open".to_string();

            // Quick service detection (simplified for speed)
            if service_detection {
                if let Ok(service_info) = quick_service_detect(host, port, timeout).await {
                    result.service = Some(service_info.service);
                    result.version = service_info.version;
                    result.banner = service_info.banner;
                }
            }

            // SSL scanning only for common SSL ports
            if ssl_scan && is_ssl_port(port) {
                if let Ok(ssl_info) = quick_ssl_scan(host, port, timeout).await {
                    result.ssl_info = Some(ssl_info);
                }
            }

            // Basic vulnerability detection
            result.vulnerabilities = detect_basic_vulnerabilities(&result);
        }
        Ok(Err(_)) => {
            result.state = "closed".to_string();
        }
        Err(_) => {
            result.state = "filtered".to_string();
        }
    }

    Ok(result)
}

// Quick service detection for performance
async fn quick_service_detect(host: &str, port: u16, timeout: Duration) -> Result<ServiceInfo> {
    use std::net::{SocketAddr, ToSocketAddrs};

    let addr = format!("{}:{}", host, port);
    let socket_addr: SocketAddr = addr.parse()
        .unwrap_or_else(|_| {
            addr.to_socket_addrs().unwrap().next().unwrap()
        });

    let mut stream = match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&socket_addr)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(_)) => return Ok(ServiceInfo {
            service: identify_service_from_banner("", port),
            version: None,
            banner: None,
        }),
        Err(_) => return Ok(ServiceInfo {
            service: identify_service_from_banner("", port),
            version: None,
            banner: None,
        }),
    };

    // Quick banner grab with short timeout
    let mut buffer = vec![0u8; 512]; // Smaller buffer for speed
    use tokio::io::AsyncReadExt;

    let banner = match tokio::time::timeout(Duration::from_millis(500), stream.read(&mut buffer)).await {
        Ok(Ok(n)) if n > 0 => {
            let banner = String::from_utf8_lossy(&buffer[..n]).trim().to_string();
            if !banner.is_empty() { Some(banner) } else { None }
        }
        _ => None,
    };

    let service = match &banner {
        Some(b) => identify_service_from_banner(b, port),
        None => identify_service_from_banner("", port),
    };

    let version = banner.as_ref()
        .and_then(|b| b.split_whitespace().nth(1))
        .map(|s| s.to_string());

    Ok(ServiceInfo {
        service,
        version,
        banner,
    })
}

// Enhanced SSL scan with certificate expiration and protocol version detection
async fn quick_ssl_scan(host: &str, port: u16, timeout: Duration) -> Result<SslInfo> {
    use std::net::TcpStream;
    use native_tls::TlsConnector;
    use std::time::Duration;
    use chrono::{DateTime, Utc};

    // Try to connect with different SSL/TLS versions to detect supported protocols
    let mut detected_version = "Unknown".to_string();
    let mut cipher_suite = "Unknown".to_string();
    let mut cert_info = None;
    let mut expiration_info = None;

    // Test TLS 1.2 first (most common)
    if let Ok(info) = try_ssl_connection(host, port, timeout, "TLSv1.2").await {
        detected_version = "TLSv1.2".to_string();
        cipher_suite = info.cipher_suite;
        cert_info = info.certificate;
        expiration_info = info.expiration;
    }
    // Test TLS 1.3
    else if let Ok(info) = try_ssl_connection(host, port, timeout, "TLSv1.3").await {
        detected_version = "TLSv1.3".to_string();
        cipher_suite = info.cipher_suite;
        cert_info = info.certificate;
        expiration_info = info.expiration;
    }
    // Test TLS 1.1 (deprecated)
    else if let Ok(info) = try_ssl_connection(host, port, timeout, "TLSv1.1").await {
        detected_version = "TLSv1.1".to_string();
        cipher_suite = info.cipher_suite;
        cert_info = info.certificate;
        expiration_info = info.expiration;
    }
    // Test TLS 1.0 (deprecated)
    else if let Ok(info) = try_ssl_connection(host, port, timeout, "TLSv1.0").await {
        detected_version = "TLSv1.0".to_string();
        cipher_suite = info.cipher_suite;
        cert_info = info.certificate;
        expiration_info = info.expiration;
    }

    Ok(SslInfo {
        version: detected_version,
        cipher_suite,
        certificate: cert_info,
        expiration: expiration_info,
    })
}

// Helper function to try SSL/TLS connection with specific version
async fn try_ssl_connection(host: &str, port: u16, timeout: Duration, version: &str) -> Result<SslInfo> {
    use std::net::TcpStream;
    use native_tls::TlsConnector;
    use sha2::Digest;
    use x509_parser::parse_x509_certificate;

    let connector = match version {
        "TLSv1.3" | "TLSv1.2" => TlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true)
            .build()?,
        "TLSv1.1" => TlsConnector::builder()
            .min_protocol_version(Some(native_tls::Protocol::Tlsv11))
            .max_protocol_version(Some(native_tls::Protocol::Tlsv11))
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true)
            .build()?,
        "TLSv1.0" => TlsConnector::builder()
            .min_protocol_version(Some(native_tls::Protocol::Tlsv10))
            .max_protocol_version(Some(native_tls::Protocol::Tlsv10))
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true)
            .build()?,
        _ => return Err(anyhow::anyhow!("Unsupported protocol version")),
    };

    let stream = TcpStream::connect(format!("{}:{}", host, port))?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    let tls_stream = connector.connect(host, stream)?;

    // Get certificate information
    let cert_der = tls_stream.peer_certificate()?.ok_or_else(|| anyhow::anyhow!("No certificate found"))?;
    let cert_bytes = cert_der.to_der()?;

    // Parse certificate
    let (_, x509_cert) = parse_x509_certificate(&cert_bytes)?;

    // Extract certificate information
    let subject = x509_cert.subject.to_string();
    let issuer = x509_cert.issuer.to_string();
    let valid_from = x509_cert.validity.not_before.to_rfc2822()
        .unwrap_or_else(|_| "Unknown".to_string());
    let valid_to = x509_cert.validity.not_after.to_rfc2822()
        .unwrap_or_else(|_| "Unknown".to_string());

    // Calculate fingerprint
    let mut hasher = sha2::Sha256::new();
    hasher.update(&cert_bytes);
    let fingerprint = hex::encode(hasher.finalize());

    // Calculate days until expiration and check for expiration issues
    let expiration = if let Ok(valid_dt) = chrono::DateTime::parse_from_rfc2822(&valid_to) {
        let expires_in = valid_dt.signed_duration_since(chrono::Utc::now()).num_days();
        if expires_in > 0 {
            if expires_in <= 30 {
                Some(format!("⚠️  Expires in {} days (CRITICAL)", expires_in))
            } else if expires_in <= 90 {
                Some(format!("⚠️  Expires in {} days (WARNING)", expires_in))
            } else {
                Some(format!("✅ Expires in {} days", expires_in))
            }
        } else {
            Some(format!("🚨 EXPIRED {} days ago", expires_in.abs()))
        }
    } else {
        None
    };

    // Try to get cipher suite (simplified - native-tls doesn't expose this easily)
    let cipher_suite = match version {
        "TLSv1.3" => "TLS_AES_256_GCM_SHA384 (assumed)",
        "TLSv1.2" => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (assumed)",
        "TLSv1.1" => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (assumed)",
        "TLSv1.0" => "TLS_RSA_WITH_AES_256_CBC_SHA (assumed)",
        _ => "Unknown",
    }.to_string();

    Ok(SslInfo {
        version: version.to_string(),
        cipher_suite,
        certificate: Some(CertificateInfo {
            subject,
            issuer,
            valid_from,
            valid_to,
            fingerprint,
        }),
        expiration,
    })
}

// Helper function to create closed result
fn create_closed_result(host: &str, port: u16) -> ScanResult {
    ScanResult {
        host: host.to_string(),
        port,
        protocol: "tcp".to_string(),
        state: "closed".to_string(),
        service: None,
        version: None,
        banner: None,
        ssl_info: None,
        vulnerabilities: Vec::new(),
    }
}

async fn parse_target(target: &str) -> Result<Vec<String>> {
    let mut hosts = Vec::new();

    // Handle IP range (e.g., 192.168.1.1-100)
    if target.contains('-') {
        let parts: Vec<&str> = target.split('-').collect();
        if parts.len() == 2 {
            let base_ip = parts[0];
            let end_host = parts[1].parse::<u32>().unwrap_or(255);

            // Extract base part
            let base_parts: Vec<&str> = base_ip.split('.').collect();
            if base_parts.len() == 4 {
                let base_start = base_parts[3].parse::<u32>().unwrap_or(1);
                let base_end = end_host.min(254);

                for i in base_start..=base_end {
                    let ip = format!("{}.{}.{}.{}", base_parts[0], base_parts[1], base_parts[2], i);
                    hosts.push(ip);
                }
            }
        }
    }
    // Handle CIDR notation (e.g., 192.168.1.0/24)
    else if target.contains('/') {
        // Simple CIDR handling - for now just check if it's a single host
        hosts.push(target.split('/').next().unwrap_or(target).to_string());
    }
    // Single host
    else {
        hosts.push(target.to_string());
    }

    Ok(hosts)
}

async fn scan_host(
    host: &str,
    ports: &[u16],
    timeout: Duration,
    service_detection: bool,
    ssl_scan: bool,
    concurrency: usize,
) -> Result<Vec<ScanResult>> {
    use indicatif::ProgressBar;
    use indicatif::ProgressStyle;
    use std::sync::Arc;

    let mut results = Vec::new();
    let pb = Arc::new(ProgressBar::new(ports.len() as u64));
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
        .unwrap()
        .progress_chars("#>-"));

    // Scan ports concurrently
    let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency));
    let mut tasks = Vec::new();

    for &port in ports {
        let semaphore = semaphore.clone();
        let host = host.to_string();
        let timeout = timeout;
        let service_detection = service_detection;
        let ssl_scan = ssl_scan;
        let pb = pb.clone();

        let task = tokio::spawn(async move {
            let _permit = semaphore.acquire().await.unwrap();
            let result = scan_single_port(&host, port, timeout, service_detection, ssl_scan).await;
            pb.inc(1);
            result
        });

        tasks.push(task);
    }

    // Wait for all tasks to complete
    for task in tasks {
        if let Ok(result) = task.await {
            if let Ok(scan_result) = result {
                results.push(scan_result);
            }
        }
    }

    pb.finish_with_message("Host scan complete!");
    Ok(results)
}

async fn scan_single_port(
    host: &str,
    port: u16,
    timeout: Duration,
    service_detection: bool,
    ssl_scan: bool,
) -> Result<ScanResult> {
    use std::net::{SocketAddr, ToSocketAddrs};

    let addr = format!("{}:{}", host, port);
    let socket_addr: SocketAddr = addr.parse()
        .unwrap_or_else(|_| {
            addr.to_socket_addrs().unwrap().next().unwrap()
        });

    let mut result = ScanResult {
        host: host.to_string(),
        port,
        protocol: "tcp".to_string(),
        state: "closed".to_string(),
        service: None,
        version: None,
        banner: None,
        ssl_info: None,
        vulnerabilities: Vec::new(),
    };

    // Check if port is open
    match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&socket_addr)).await {
        Ok(Ok(_stream)) => {
            result.state = "open".to_string();

            // Service detection
            if service_detection {
                if let Ok(service_info) = detect_service(host, port, timeout).await {
                    result.service = Some(service_info.service);
                    result.version = service_info.version;
                    result.banner = service_info.banner;
                }
            }

            // SSL scanning
            if ssl_scan && is_ssl_port(port) {
                if let Ok(ssl_info) = scan_ssl_service(host, port, timeout).await {
                    result.ssl_info = Some(ssl_info);
                }
            }

            // Basic vulnerability detection
            result.vulnerabilities = detect_basic_vulnerabilities(&result);
        }
        Ok(Err(_)) => {
            result.state = "closed".to_string();
        }
        Err(_) => {
            result.state = "filtered".to_string();
        }
    }

    Ok(result)
}

async fn detect_service(host: &str, port: u16, timeout: Duration) -> Result<ServiceInfo> {
    use std::net::{SocketAddr, ToSocketAddrs};

    let addr = format!("{}:{}", host, port);
    let socket_addr: SocketAddr = addr.parse()
        .unwrap_or_else(|_| {
            addr.to_socket_addrs().unwrap().next().unwrap()
        });

    let mut stream = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&socket_addr)).await??;

    // Try to read service banner
    let mut buffer = vec![0u8; 1024];
    use tokio::io::AsyncReadExt;
    let n = tokio::time::timeout(timeout, stream.read(&mut buffer)).await;

    let banner = if let Ok(Ok(n)) = n {
        if n > 0 {
            String::from_utf8_lossy(&buffer[..n]).trim().to_string()
        } else {
            String::new()
        }
    } else {
        String::new()
    };

    // Identify service from banner
    let service = identify_service_from_banner(&banner, port);
    let version = extract_version_from_banner(&banner);

    Ok(ServiceInfo {
        service,
        version,
        banner: if banner.is_empty() { None } else { Some(banner) },
    })
}

fn identify_service_from_banner(banner: &str, port: u16) -> String {
    for (service, pattern) in SERVICE_BANNERS {
        if banner.contains(pattern) {
            return service.to_string();
        }
    }

    // Enhanced port mapping with more services
    match port {
        21 => "FTP".to_string(),
        22 => "SSH".to_string(),
        23 => "Telnet".to_string(),
        25 => "SMTP".to_string(),
        53 => "DNS".to_string(),
        80 => "HTTP".to_string(),
        110 => "POP3".to_string(),
        111 => "RPC".to_string(),
        135 => "MSRPC".to_string(),
        139 => "NetBIOS".to_string(),
        143 => "IMAP".to_string(),
        443 => "HTTPS".to_string(),
        445 => "SMB".to_string(),
        993 => "IMAPS".to_string(),
        995 => "POP3S".to_string(),
        1433 => "MS-SQL".to_string(),
        1521 => "Oracle".to_string(),
        3306 => "MySQL".to_string(),
        3389 => "RDP".to_string(),
        5432 => "PostgreSQL".to_string(),
        5900 => "VNC".to_string(),
        6379 => "Redis".to_string(),
        8080 => "HTTP-Alt".to_string(),
        8443 => "HTTPS-Alt".to_string(),
        9200 => "Elasticsearch".to_string(),
        27017 => "MongoDB".to_string(),
        32130 => "Unknown Service".to_string(),
        30947 => "Unknown Service".to_string(),
        6443 => "Unknown Service".to_string(),
        _ => {
            // Try to identify from common port ranges
            if port >= 30000 && port <= 40000 {
                "Dynamic Port".to_string()
            } else if port >= 49152 {
                "Ephemeral Port".to_string()
            } else {
                "unknown".to_string()
            }
        }
    }
}

fn extract_version_from_banner(banner: &str) -> Option<String> {
    // Simple version extraction - can be enhanced
    let words: Vec<&str> = banner.split_whitespace().collect();
    words.get(1).map(|s| s.to_string())
}

async fn scan_ssl_service(host: &str, port: u16, _timeout: Duration) -> Result<SslInfo> {
    use std::net::TcpStream;
    use native_tls::TlsConnector;
    use sha2::Digest;
    use std::time::Duration;

    let connector = TlsConnector::builder()
        .danger_accept_invalid_certs(true) // For scanning purposes
        .danger_accept_invalid_hostnames(true) // For scanning purposes
        .build()?;

    let stream = TcpStream::connect(format!("{}:{}", host, port))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    let tls_stream = match connector.connect(host, stream) {
        Ok(stream) => stream,
        Err(_) => {
            // Fallback to basic info if connection fails
            return Ok(SslInfo {
                version: "TLSv1.2".to_string(),
                cipher_suite: "Unknown".to_string(),
                certificate: None,
                expiration: None,
            });
        }
    };

    // Get certificate information
    let cert_der = tls_stream.peer_certificate()?.ok_or_else(|| anyhow::anyhow!("No certificate found"))?;
    let cert_bytes = cert_der.to_der()?;

    // Parse certificate with x509-parser
    let (_, x509_cert) = x509_parser::parse_x509_certificate(&cert_bytes)?;

    // Extract certificate information with proper error handling
    let subject = x509_cert.subject.to_string();
    let issuer = x509_cert.issuer.to_string();
    let valid_from = x509_cert.validity.not_before.to_rfc2822()
        .unwrap_or_else(|_| "Unknown".to_string());
    let valid_to = x509_cert.validity.not_after.to_rfc2822()
        .unwrap_or_else(|_| "Unknown".to_string());

    // Calculate fingerprint
    let mut hasher = sha2::Sha256::new();
    hasher.update(&cert_bytes);
    let fingerprint = hex::encode(hasher.finalize());

    // Simplified version detection - since native-tls doesn't expose session info easily
    let version = "TLSv1.2"; // Default assumption
    let cipher_suite = "Unknown";

    // Calculate days until expiration (if valid date)
    let expiration = if let Ok(valid_dt) = chrono::DateTime::parse_from_rfc2822(&valid_to) {
        let expires_in = valid_dt.signed_duration_since(chrono::Utc::now()).num_days();
        if expires_in > 0 {
            Some(format!("Expires in {} days", expires_in))
        } else {
            Some(format!("Expired {} days ago", expires_in.abs()))
        }
    } else {
        None
    };

    Ok(SslInfo {
        version: version.to_string(),
        cipher_suite: cipher_suite.to_string(),
        certificate: Some(CertificateInfo {
            subject,
            issuer,
            valid_from,
            valid_to,
            fingerprint,
        }),
        expiration,
    })
}

fn is_ssl_port(port: u16) -> bool {
    // Common SSL/TLS ports
    matches!(port,
        443 |   // HTTPS
        993 |   // IMAPS
        995 |   // POP3S
        8443 |  // HTTPS Alt
        465 |   // SMTPS
        587 |   // SMTP with STARTTLS
        3389 |  // RDP (can have TLS)
        5223 |  // XMPP SSL
        5222 |  // XMPP with STARTTLS
        8883 |  // Secure MQTT
        636 |   // LDAPS
        989 |   // FTPS
        990     // FTPS
    )
}

fn detect_basic_vulnerabilities(result: &ScanResult) -> Vec<Vulnerability> {
    let mut vulns = Vec::new();

    // Check for common vulnerable services and versions
    if let Some(service) = &result.service {
        match service.as_str() {
            "SSH" => {
                if let Some(version) = &result.version {
                    // Check for specific vulnerable SSH versions
                    if version.contains("7.2") || version.contains("7.3") || version.contains("7.4") {
                        vulns.push(Vulnerability {
                            cve_id: "CVE-2023-XXXX".to_string(),
                            severity: "High".to_string(),
                            description: "Outdated SSH version with potential vulnerabilities".to_string(),
                            service: service.clone(),
                        });
                    }
                    if version.contains("OpenSSH_6.") {
                        vulns.push(Vulnerability {
                            cve_id: "CVE-2016-0777".to_string(),
                            severity: "Medium".to_string(),
                            description: "OpenSSH information disclosure vulnerability".to_string(),
                            service: service.clone(),
                        });
                    }
                }
                // Generic SSH security recommendations
                vulns.push(Vulnerability {
                    cve_id: "SSH-CONFIG-001".to_string(),
                    severity: "Low".to_string(),
                    description: "Review SSH configuration for security hardening".to_string(),
                    service: service.clone(),
                });
            }
            "HTTP" | "HTTPS" => {
                // Check for common HTTP vulnerabilities
                vulns.push(Vulnerability {
                    cve_id: "GENERIC-001".to_string(),
                    severity: "Medium".to_string(),
                    description: "Web server - check for HTTP headers, known vulnerabilities, and security misconfigurations".to_string(),
                    service: service.clone(),
                });

                // Check for outdated server versions
                if let Some(version) = &result.version {
                    if version.contains("Apache/2.2") {
                        vulns.push(Vulnerability {
                            cve_id: "CVE-2019-0211".to_string(),
                            severity: "Critical".to_string(),
                            description: "Apache 2.2.x has multiple critical vulnerabilities and is EOL".to_string(),
                            service: service.clone(),
                        });
                    }
                    if version.contains("nginx/1.14") || version.contains("nginx/1.15") {
                        vulns.push(Vulnerability {
                            cve_id: "CVE-2019-20372".to_string(),
                            severity: "High".to_string(),
                            description: "Nginx versions before 1.16.1 have memory corruption vulnerabilities".to_string(),
                            service: service.clone(),
                        });
                    }
                }

                // SSL/TLS specific checks
                if result.port == 443 || result.port == 8443 {
                    if let Some(ssl_info) = &result.ssl_info {
                        if ssl_info.version == "SSLv2" || ssl_info.version == "SSLv3" {
                            vulns.push(Vulnerability {
                                cve_id: "CVE-2014-3566".to_string(),
                                severity: "Critical".to_string(),
                                description: "POODLE attack - SSLv3 is vulnerable".to_string(),
                                service: service.clone(),
                            });
                        }
                        if ssl_info.version == "TLSv1.0" {
                            vulns.push(Vulnerability {
                                cve_id: "CVE-2011-3389".to_string(),
                                severity: "High".to_string(),
                                description: "BEAST attack - TLSv1.0 is vulnerable".to_string(),
                                service: service.clone(),
                            });
                        }
                    }
                }
            }
            "FTP" => {
                vulns.push(Vulnerability {
                    cve_id: "GENERIC-002".to_string(),
                    severity: "High".to_string(),
                    description: "FTP service transmits credentials in cleartext".to_string(),
                    service: service.clone(),
                });
            }
            "Telnet" => {
                vulns.push(Vulnerability {
                    cve_id: "GENERIC-003".to_string(),
                    severity: "Critical".to_string(),
                    description: "Telnet service transmits all data in cleartext".to_string(),
                    service: service.clone(),
                });
            }
            "MySQL" => {
                if let Some(version) = &result.version {
                    if version.starts_with("5.5") || version.starts_with("5.6") {
                        vulns.push(Vulnerability {
                            cve_id: "MYSQL-OLD-001".to_string(),
                            severity: "Medium".to_string(),
                            description: "MySQL version is outdated and has known vulnerabilities".to_string(),
                            service: service.clone(),
                        });
                    }
                }
            }
            "Redis" => {
                vulns.push(Vulnerability {
                    cve_id: "REDIS-SEC-001".to_string(),
                    severity: "High".to_string(),
                    description: "Redis server should be secured with authentication and firewall rules".to_string(),
                    service: service.clone(),
                });
            }
            "MongoDB" => {
                vulns.push(Vulnerability {
                    cve_id: "MONGODB-SEC-001".to_string(),
                    severity: "High".to_string(),
                    description: "MongoDB should be secured with authentication and network access control".to_string(),
                    service: service.clone(),
                });
            }
            "SMTP" => {
                vulns.push(Vulnerability {
                    cve_id: "SMTP-SEC-001".to_string(),
                    severity: "Medium".to_string(),
                    description: "SMTP server should be configured to prevent open relay and implement security headers".to_string(),
                    service: service.clone(),
                });
            }
            "DNS" => {
                vulns.push(Vulnerability {
                    cve_id: "DNS-SEC-001".to_string(),
                    severity: "Medium".to_string(),
                    description: "DNS server should be secured against DNS amplification attacks".to_string(),
                    service: service.clone(),
                });
            }
            _ => {}
        }
    }

    // Generic port-based vulnerability checks
    match result.port {
        23 => vulns.push(Vulnerability {
            cve_id: "GENERIC-TELNET".to_string(),
            severity: "Critical".to_string(),
            description: "Telnet port open - cleartext protocol".to_string(),
            service: "Telnet".to_string(),
        }),
        21 => vulns.push(Vulnerability {
            cve_id: "GENERIC-FTP".to_string(),
            severity: "High".to_string(),
            description: "FTP port open - cleartext authentication".to_string(),
            service: "FTP".to_string(),
        }),
        445 => vulns.push(Vulnerability {
            cve_id: "GENERIC-SMB".to_string(),
            severity: "Medium".to_string(),
            description: "SMB port open - ensure proper security configurations".to_string(),
            service: "SMB".to_string(),
        }),
        3389 => vulns.push(Vulnerability {
            cve_id: "GENERIC-RDP".to_string(),
            severity: "High".to_string(),
            description: "RDP port open - ensure strong authentication and network restrictions".to_string(),
            service: "RDP".to_string(),
        }),
        5900 => vulns.push(Vulnerability {
            cve_id: "GENERIC-VNC".to_string(),
            severity: "High".to_string(),
            description: "VNC port open - ensure proper authentication".to_string(),
            service: "VNC".to_string(),
        }),
        _ => {}
    }

    vulns
}

fn output_results(results: &[ScanResult], format: &str) -> Result<()> {
    match format {
        "json" => {
            println!("{}", serde_json::to_string_pretty(results)?);
        }
        "csv" => {
            println!("host,port,protocol,state,service,version,banner");
            for result in results {
                println!("{},{},{},{},{},{},{}",
                    result.host,
                    result.port,
                    result.protocol,
                    result.state,
                    result.service.as_deref().unwrap_or(""),
                    result.version.as_deref().unwrap_or(""),
                    result.banner.as_deref().unwrap_or("")
                );
            }
        }
        _ => {
            // Text format (default)
            for result in results {
                if result.state == "open" {
                    output::print_success(&format!(
                        "{}:{} - {} - {} {}",
                        result.host,
                        result.port,
                        result.service.as_deref().unwrap_or("unknown"),
                        result.version.as_deref().unwrap_or(""),
                        if result.ssl_info.is_some() { "[SSL]" } else { "" }
                    ));

                    if let Some(banner) = &result.banner {
                        output::print_normal(&format!("  Banner: {}", banner));
                    }

                    if let Some(ssl_info) = &result.ssl_info {
                        output::print_colored(&format!("  SSL/TLS: {} - {}", ssl_info.version, ssl_info.cipher_suite), colored::Color::Blue);
                        if let Some(cert) = &ssl_info.certificate {
                            output::print_normal(&format!("  Certificate: {}", cert.subject));
                            output::print_normal(&format!("  Issuer: {}", cert.issuer));
                            if let Some(exp) = &ssl_info.expiration {
                                output::print_warning(&format!("  {}", exp));
                            }
                        }
                    }

                    for vuln in &result.vulnerabilities {
                        output::print_error(&format!("  VULNERABILITY: {} - {}", vuln.cve_id, vuln.description));
                    }
                }
            }
        }
    }
    Ok(())
}

#[derive(Debug)]
pub struct ServiceInfo {
    pub service: String,
    pub version: Option<String>,
    pub banner: Option<String>,
}