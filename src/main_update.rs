use clap::{Arg, Command, ArgAction};
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::{Client, Method, Url};
use std::path::{PathBuf};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Semaphore, Mutex};
use tokio::task;
use std::collections::HashSet;

// Comprehensive SecLists wordlist locations
const DEFAULT_WORDLISTS: &[&str] = &[
    // Web Content Wordlists
    "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt",
    "/opt/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt",
    "~/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt",
    "./raft-medium-directories-lowercase.txt",
    "/usr/share/wordlists/seclists/raft-medium-directories-lowercase.txt",
    "~/wordlists/seclists/raft-medium-directories-lowercase.txt",

    // Additional Potential Locations
    "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
    "/opt/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
    "~/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
    "/usr/share/wordlists/seclists/directory-list-2.3-medium.txt",
];

/// Generate URLs with extensions
fn generate_urls(base_url: &str, path: &str, extensions: &[String]) -> Vec<String> {
    let mut urls = std::collections::HashSet::new();

    // Normalize base URL to remove multiple trailing slashes
    let base_url = base_url.trim_end_matches('/');

    // Add base path without and with single trailing slash
    urls.insert(format!("{}/{}", base_url, path));
    urls.insert(format!("{}/{}/", base_url, path));

    // Add URLs with extensions
    if !extensions.is_empty() {
        for ext in extensions {
            urls.insert(format!("{}/{}.{}", base_url, path, ext));
            urls.insert(format!("{}/{}.{}/", base_url, path, ext));
        }
    }

    // Convert HashSet to Vec and return
    urls.into_iter().collect()
}

/// Enhanced fuzzer configuration to include extensions
#[derive(Debug, Clone)]
struct FuzzerConfig {
    url: String,
    wordlist: PathBuf,
    threads: usize,
    verbose: bool,
    silent: bool,
    status_codes: Vec<u16>,
    timeout: u64,
    method: Method,
    extensions: Vec<String>,
}

/// Comprehensive wordlist finder with multiple locations
fn find_wordlist() -> Option<PathBuf> {
    for path in DEFAULT_WORDLISTS {
        let expanded_path = shellexpand::tilde(path).into_owned();
        let path_buf = PathBuf::from(expanded_path);
        if path_buf.exists() {
            return Some(path_buf);
        }
    }
    None
}

fn print_banner() {
    let banner = r#"
██████╗ ██╗██████╗          ██████╗██████╗  █████╗ ██╗    ██╗██╗     ███████╗██████╗
██╔══██╗██║██╔══██╗        ██╔════╝██╔══██╗██╔══██╗██║    ██║██║     ██╔════╝██╔══██╗
██║  ██║██║██████╔╝        ██║     ██████╔╝███████║██║ █╗ ██║██║     █████╗  ██████╔╝
██║  ██║██║██╔══██╗        ██║     ██╔══██╗██╔══██║██║███╗██║██║     ██╔══╝  ██╔══██╗
██████╔╝██║██║  ██║███████╗╚██████╗██║  ██║██║  ██║╚███╔███╔╝███████╗███████╗██║  ██║
╚═════╝ ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚══════╝╚══════╝╚═╝  ╚═╝
"#;

    println!("{}", banner.bright_magenta());
    println!("{}", format!("{}", "           [ Sylar's Dir_Crawler ]").yellow());
    println!("{}", "   🕵️‍♂️ 🌐 Network Directory Exploration Tool 🔍".truecolor(50, 150, 250));
    println!("{}", "~".repeat(65).truecolor(100, 100, 100));
    println!("{}", "   Empowering Cybersecurity Professionals with Precise Scanning".bright_white());
    println!("{}", "=".repeat(65).truecolor(80, 80, 80));
}

/// Enhanced URL validation with scheme detection
fn validate_url(url: &str) -> Result<String, String> {
    let parsed_url = Url::parse(url).map_err(|_| "Invalid URL format")?;

    match parsed_url.scheme() {
        "http" | "https" => Ok(url.to_string()),
        _ => {
            let http_url = format!("http://{}", url);
            let https_url = format!("https://{}", url);

            if Url::parse(&http_url).is_ok() {
                Ok(http_url)
            } else if Url::parse(&https_url).is_ok() {
                Ok(https_url)
            } else {
                Err("Invalid URL. Use full URL with http:// or https://".to_string())
            }
        }
    }
}

/// Enhanced directory fuzzing function with thread-safe result collection
async fn fuzz_directory(config: Arc<FuzzerConfig>) -> Result<(), Box<dyn std::error::Error>> {
    let start_time = Instant::now();

    // Enhanced HTTP client configuration
    let client = Client::builder()
        .timeout(Duration::from_secs(config.timeout))
        .build()?;

    // Read wordlist
    let file = File::open(&config.wordlist)?;
    let reader = BufReader::new(file);
    let entries: Vec<String> = reader.lines().collect::<Result<_, _>>()?;

    // Detailed startup information
    if !config.silent {
        println!("🔍 Directory Fuzzing Initiated");
        println!("🌐 Target URL: {}", config.url.green());
        println!("📋 Wordlist: {}", config.wordlist.display().to_string().blue());
        println!("🧵 Threads: {}", config.threads.to_string().yellow());
        println!("🚀 Request Method: {}", format!("{}", config.method).cyan());

        // Show extensions if provided
        if !config.extensions.is_empty() {
            println!("🔗 Extensions: {}", config.extensions.join(", ").magenta());
        }

        println!("📊 Total Paths to Check: {}",
            (entries.len() * (1 + config.extensions.len() + 1)).to_string().cyan()
        );
    }

    // Progress bar with extended path count
    let total_paths = entries.len() * (1 + config.extensions.len() + 1);
    let progress_bar = ProgressBar::new(total_paths as u64);
    let progress_style = ProgressStyle::default_bar()
        .template("{spinner} 🕵️ [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
        .unwrap()
        .progress_chars("#>-");
    progress_bar.set_style(progress_style);

    // Concurrency management
    let semaphore = Arc::new(Semaphore::new(config.threads));
    let found_paths = Arc::new(Mutex::new(HashSet::new()));
    let mut handles = Vec::new();

    // Process entries with extension support
    for path in entries {
        let config_clone = Arc::clone(&config);
        let client_clone = client.clone();
        let progress_clone = progress_bar.clone();
        let found_paths_clone = Arc::clone(&found_paths);
        let permit = Arc::clone(&semaphore).acquire_owned().await;

        let handle = task::spawn(async move {
            let _permit = permit;

            // Generate URLs with potential extensions
            let test_urls = generate_urls(&config_clone.url, &path, &config_clone.extensions);

            for test_url in test_urls {
                let request = match config_clone.method {
                    Method::GET => client_clone.get(&test_url),
                    Method::POST => client_clone.post(&test_url),
                    _ => client_clone.get(&test_url), // Fallback to GET
                };

                match request.send().await {
                    Ok(response) => {
                        let status = response.status();

                        // Sophisticated status code filtering
                        if config_clone.status_codes.is_empty() ||
                           config_clone.status_codes.contains(&status.as_u16()) {
                            if !config_clone.silent {
                                let status_str = format!("{}", status.as_u16());
                                let output = match status.as_u16() {
                                    200..=299 => status_str.green(),
                                    300..=399 => status_str.yellow(),
                                    400..=599 => status_str.red(),
                                    _ => status_str.white(),
                                };

                                println!(
                                    "🌐 Status: {} | URL: {} 📁",
                                    output,
                                    test_url
                                );
                            }

                            // Insert found path into shared HashSet
                            {
                                let mut paths = found_paths_clone.lock().await;
                                paths.insert((test_url.clone(), status.as_u16()));
                            }
                        }
                    }
                    Err(e) if config_clone.verbose => {
                        println!("❌ Error checking: {} - {}", test_url, e);
                    }
                    _ => {}
                }

                progress_clone.inc(1);
            }

            Ok::<(), reqwest::Error>(())
        });

        handles.push(handle);
    }

    // Wait for all handles to complete
    for handle in handles {
        handle.await??;
    }

    // Comprehensive results display
    let elapsed_time = start_time.elapsed();
    let found_paths_guard = found_paths.lock().await;

    if found_paths_guard.is_empty() {
        println!("🚫 No paths found. Possible reasons:");
        println!("   - Incorrect URL");
        println!("   - Firewall/Security blocking requests");
        println!("   - Server not responding");
        println!("   - Wordlist or extensions don't match server paths");
    } else {
        println!("\n🎉 Found Paths:");
        let mut sorted_paths: Vec<_> = found_paths_guard.iter().cloned().collect();
        sorted_paths.sort_by(|a, b| a.0.cmp(&b.0));

        for (path, status) in sorted_paths {
            let status_color = match status {
                200..=299 => path.green(),
                300..=399 => path.yellow(),
                400..=599 => path.red(),
                _ => path.white(),
            };
            println!("{} (Status: {})", status_color, status);
        }
    }

    // Detailed timing and performance information
    if !config.silent {
        println!(
            "\n⏱️  Total Scan Time: {:.2} seconds 🕒",
            elapsed_time.as_secs_f64()
        );
    }

    progress_bar.finish_with_message("🔍 Directory Fuzzing Complete!");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Demonstrate the banner
    print_banner();
    
    // Enhanced CLI Configuration with Extension Support
    let matches = Command::new("Directory Crawler 🕵️")
        .version("2.1")
        .author("Cybersecurity Enthusiast")
        .about("Advanced Directory Fuzzing Tool with Extension Support")
        .arg(
            Arg::new("url")
                .help("Target URL to fuzz")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::new("wordlist")
                .short('w')
                .long("wordlist")
                .help("Custom wordlist path")
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new("extensions")
                .short('x')
                .long("extensions")
                .help("File extensions to fuzz (comma-separated)")
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new("threads")
                .short('t')
                .long("threads")
                .help("Number of concurrent threads")
                .default_value("20")
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("Enable verbose mode")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("silent")
                .short('s')
                .long("silent")
                .help("Silent mode (minimal output)")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("status-codes")
                .short('c')
                .long("status")
                .help("Filter by specific status codes (comma-separated)")
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new("timeout")
                .long("timeout")
                .help("Request timeout in seconds")
                .default_value("10")
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new("method")
                .short('m')
                .long("method")
                .help("HTTP Request Method (GET/POST)")
                .default_value("GET")
                .action(ArgAction::Set),
        )
        .get_matches();

    // Validate and process URL
    let url = matches.get_one::<String>("url")
        .ok_or("URL is required")?;
    let validated_url = validate_url(url)?;

    // Process extensions
    let extensions = matches.get_one::<String>("extensions")
        .map(|ext|
            ext.split(',')
                .map(|e| e.trim().to_lowercase())
                .filter(|e| !e.is_empty())
                .collect()
        )
        .unwrap_or_else(Vec::new);

    // Flexible wordlist selection
    let wordlist = matches.get_one::<String>("wordlist")
        .map(PathBuf::from)
        .or_else(|| find_wordlist())
        .expect("No wordlist found. Please install SecLists or provide a custom path.");

    // Parse status codes with intelligent defaults
     let status_codes = matches.get_one::<String>("status-codes")
        .map(|codes|
            codes.split(',')
                .filter_map(|c| c.parse().ok())
                .collect()
        )
        .unwrap_or_else(|| vec![200, 204, 301, 302, 307, 401, 403]);

    // Parse request method
    let method = matches.get_one::<String>("method")
        .map(|m| match m.to_uppercase().as_str() {
            "POST" => Method::POST,
            _ => Method::GET,
        })
        .unwrap_or(Method::GET);

    // Create comprehensive fuzzer configuration
    let config = Arc::new(FuzzerConfig {
        url: validated_url,
        wordlist,
        threads: matches.get_one::<String>("threads")
            .and_then(|t| t.parse().ok())
            .unwrap_or(20),
        verbose: matches.get_flag("verbose"),
        silent: matches.get_flag("silent"),
        status_codes,
        timeout: matches.get_one::<String>("timeout")
            .and_then(|t| t.parse().ok())
            .unwrap_or(10),
        method,
        extensions,
    });

    // Run directory fuzzing
    fuzz_directory(config).await
}
