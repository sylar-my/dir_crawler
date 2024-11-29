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

// [Rest of the previous imports remain the same]

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

// [Rest of the code remains the same]
