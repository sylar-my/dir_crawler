# Dir_Crawler 🕵️‍♂️🌐

## Overview

Dir_Crawler is an advanced directory fuzzing and enumeration tool designed for cybersecurity professionals and penetration testers. It provides a powerful, flexible solution for discovering hidden directories and files on web servers.

## 🚀 Features

- **Comprehensive Scanning**: Thoroughly explore web directory structures
- **Multi-threaded Performance**: Rapid scanning with configurable thread count
- **Extension Support**: Fuzz with multiple file extensions
- **Flexible Filtering**: 
  - Custom wordlists
  - Status code filtering
  - Verbose and silent modes
- **Colorful CLI Output**: Easy-to-read results with color-coded status codes
- **Extensible Design**: Easily customizable for various scanning scenarios

## 🛠 Installation

### Prerequisites
- Rust (latest stable version)
- SecLists wordlist collection (recommended)

### Install via Cargo
```bash
cargo install --git https://github.com/sylar-my/dir_crawler
```

### Build from Source
```bash
git clone https://github.com/yourusername/dir_crawler.git
cd dir_crawler
cargo build --release
```

## 🔍 Usage Examples

### Basic Scan
```bash
dir_crawler http://example.com
```

### Advanced Scanning
```bash
# Scan with custom wordlist and extensions
dir_crawler http://example.com -w /path/to/wordlist.txt -x php,txt

# Customize threads and timeout
dir_crawler http://example.com -t 50 --timeout 15

# Filter specific status codes
dir_crawler http://example.com -c 200,301,403
```

## 📝 Command Line Options

- `-u, --url`: Target URL to scan (required)
- `-w, --wordlist`: Custom wordlist path
- `-x, --extensions`: File extensions to fuzz
- `-t, --threads`: Number of concurrent threads (default: 20)
- `-v, --verbose`: Enable verbose output
- `-s, --silent`: Minimal output mode
- `-c, --status`: Filter by specific HTTP status codes
- `--timeout`: Request timeout in seconds (default: 10)
- `-m, --method`: HTTP request method (GET/POST, default: GET)

## 🛡️ Ethical Use Notice

Dir_Crawler is intended for authorized security testing and vulnerability assessment. Always obtain proper permission before scanning any systems you do not own or have explicit authorization to test.

## 📦 Dependencies

- clap: CLI argument parsing
- reqwest: HTTP requesting
- tokio: Asynchronous runtime
- colored: Terminal color output
- indicatif: Progress bars and spinners

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.

## 🐛 Reporting Issues

Report any bugs or feature requests by opening a GitHub issue.

## 💡 Disclaimer

This tool is for educational and ethical security testing purposes only. Unauthorized scanning of systems is illegal and unethical.
