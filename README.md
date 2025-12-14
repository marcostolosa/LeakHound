# LeakHound

Automated security scanner for detecting exposed secrets in web infrastructure.

## Overview

LeakHound is a multi-threaded Python tool designed to scan web applications, JavaScript files, and configuration endpoints for exposed credentials, API keys, tokens, and other sensitive information. The scanner automatically discovers and analyzes JavaScript resources and common configuration file paths while respecting rate limits to avoid detection.

## Features

**Comprehensive Secret Detection**
- AWS Access Keys and Secret Keys
- Google, GitHub, GitLab API tokens
- Stripe, OpenAI, Heroku credentials
- JWT tokens and private keys
- Firebase URLs and database credentials
- Generic API keys, secrets, and tokens

**Intelligent Scanning**
- Automatic discovery of JavaScript files from HTML pages
- Common configuration path enumeration (.env, config.json, credentials files)
- Multi-threaded concurrent scanning with configurable workers
- Thread-safe operations with proper locking mechanisms
- Built-in rate limiting to avoid IP bans

**False Positive Filtering**
- Pattern-based exclusion of example/test credentials
- Length and format validation
- Context-aware filtering

**Output Options**
- Colored terminal output with timestamps
- JSON file export for integration with other tools
- Detailed statistics on URLs discovered vs scanned
- Verbose mode for debugging

## Installation

**Requirements:**
- Python 3.7+
- requests
- beautifulsoup4

**Install dependencies:**
```bash
pip3 install requests beautifulsoup4
```

Or using the project virtual environment:
```bash
.venv/bin/pip install requests beautifulsoup4
```

## Usage

**Basic scan:**
```bash
python3 leakhound.py -u https://example.com
```

**Scan with JSON output:**
```bash
python3 leakhound.py -u https://example.com -o findings.json
```

**Scan multiple URLs:**
```bash
python3 leakhound.py -u https://example.com https://api.example.com -o results.json
```

**Verbose output:**
```bash
python3 leakhound.py -u https://example.com -v
```

**Custom threading and rate limit:**
```bash
python3 leakhound.py -u https://example.com -t 20 -r 0.2
```

## Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-u`, `--urls` | Target URLs to scan (required) | - |
| `-o`, `--output` | Output JSON file path | None |
| `-v`, `--verbose` | Enable verbose output | False |
| `-t`, `--threads` | Number of concurrent threads | 10 |
| `-r`, `--rate-limit` | Delay between requests in seconds | 0.1 |
| `--timeout` | Request timeout in seconds | 10 |

## How It Works

1. **Initial Scan**: Fetches the provided URL and scans content for secrets
2. **Resource Discovery**: Parses HTML to find JavaScript file references
3. **Path Enumeration**: Tests common configuration file paths (.env, config.json, etc.)
4. **Concurrent Processing**: Uses thread pool to scan discovered resources
5. **Continuous Discovery**: New URLs found during scanning are added to the queue
6. **Safe Termination**: All tasks complete before scanner exits

## Secret Detection Patterns

The scanner uses regex patterns to identify:

**Cloud Services:**
- AWS (AKIA keys, secret access keys)
- Google Cloud (AIza API keys)
- DigitalOcean (dop_v1 tokens)
- Heroku (UUID format keys)

**Version Control:**
- GitHub (ghp/gho/ghu/ghr/ghs/ghe tokens)
- GitLab (glpat tokens)

**Payment:**
- Stripe (sk_live/sk_test keys, pk_live/pk_test)

**AI/ML:**
- OpenAI (sk- format keys)

**General:**
- JWT tokens (eyJ format)
- RSA/EC/DSA private keys
- Generic API key/secret/token assignments
- Firebase database URLs
- Email addresses and IP addresses

## Configuration File Paths

Automatically tests for:
- .env, .env.local, .env.production, .env.development, .env.staging
- config.json, credentials.json, secrets.json
- database.yml, application.properties, config.yml
- wp-config.php, web.config
- .git/config
- debug.log, error.log, access.log
- settings.py

## Output Format

**Terminal Output:**
```
[20:23:59] Starting scan with 10 threads...
[20:23:59] Initial URLs to scan: 1
[20:24:01] Scanning [1/35]: https://example.com/
[20:24:02] Scanning [2/35]: https://example.com/app.js
[20:24:05] Found GitHub Token
    Value: ghp_1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r
    Source: https://example.com/config.js
```

**JSON Output:**
```json
{"timestamp": "2025-12-14T20:24:05.123456", "source": "https://example.com/config.js", "type": "GitHub Token", "value": "ghp_1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r"}
```

## Technical Details

**Thread Safety:**
- Per-thread request sessions to avoid connection pool conflicts
- Mutex locks on shared resources (visited URLs, file writes)
- Thread-safe deque for URL queue management

**Performance:**
- Configurable worker threads (default: 10)
- Rate limiting to avoid triggering WAF/IDS
- Efficient duplicate URL detection
- Continuous task submission as new URLs are discovered

**Error Handling:**
- Graceful handling of connection timeouts
- SSL verification disabled for flexibility (use with caution)
- Failed requests logged without stopping scan

## Known Limitations

- Currently discovers resources from HTML only (no JavaScript parsing)
- Configuration paths tested recursively (may generate excessive requests)
- No crawling depth limit for .git paths (can be verbose)
- No support for authenticated scanning
- No proxy support

## Integration with Reconnaissance Pipeline

LeakHound can be integrated into larger reconnaissance workflows:

```bash
# Scan all alive domains from httprobe
cat alive.txt | while read domain; do
    python3 leakhound.py -u "$domain" -o "secrets_${domain//[^a-zA-Z0-9]/_}.json"
done
```

```bash
# Scan JavaScript files discovered by hakrawler
cat js_files.txt | python3 leakhound.py -u $(cat -) -o js_secrets.json -t 20
```

## Comparison with Similar Tools

**vs. truffleHog:** LeakHound focuses on live web scanning rather than git history
**vs. gitrob:** LeakHound scans running applications, not repositories
**vs. SecretScanner:** LeakHound includes automatic resource discovery

## Security Considerations

This tool is designed for authorized security testing only. Usage scenarios include:

- Bug bounty programs (with proper authorization)
- Penetration testing engagements
- Internal security audits
- Red team exercises

**Do not use this tool:**
- Against systems you do not own or have permission to test
- To extract credentials for malicious purposes
- In violation of computer fraud laws in your jurisdiction

Rate limiting is included by default to minimize service impact.

## Troubleshooting

**No secrets found on known-vulnerable site:**
- Check that JavaScript files are being discovered (use -v flag)
- Verify the secret patterns match your target's format
- Confirm false positive filters aren't excluding valid findings

**Scanner exits before completing:**
- Increase timeout value with --timeout
- Reduce thread count if hitting rate limits
- Check network connectivity

**High false positive rate:**
- Review the FALSE_POSITIVE_STRINGS list
- Adjust minimum value length in is_false_positive()
- Filter results by secret type in post-processing

## Development

**Project Structure:**
```
leakhound.py          # Main scanner implementation
LEAKHOUND_README.md   # This file
```

**Key Classes:**
- `SecretPatterns`: Regex pattern definitions
- `LeakHound`: Main scanner engine with threading
- `Colors`: ANSI terminal color codes

**Core Functions:**
- `find_secrets()`: Pattern matching against content
- `_process_url()`: Per-URL scanning logic
- `scan_urls()`: Thread pool management

## Changelog

**v1.1 (Current)**
- Fixed critical race condition in thread pool
- Added thread-safe session management
- Implemented file write locking
- Added rate limiting support
- Improved verbose output
- Added scan statistics (URLs found/scanned)
- Removed non-functional crawl parameter
- Enhanced false positive detection

**v1.0 (Original)**
- Initial release with basic scanning
- Multi-threading support
- JSON output format
- Pattern-based secret detection

## License

MIT License

## Credits

Based on reconnaissance methodologies from the bug bounty community. Enhanced for production security testing with proper thread safety and rate limiting.

## Support

For issues, feature requests, or contributions, refer to the CVE-Hunters Recon project documentation.

