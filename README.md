
# LeakHound

LeakHound is an enterprise-grade, automated security scanner engineered to detect and validate exposed secrets across web infrastructures and local codebases. It operates as a command-line interface (CLI) tool, designed for security professionals, penetration testers, and development teams to proactively identify sensitive information leaks before they can be exploited.

## Core Functionality

LeakHound performs deep scans of specified targets, which can be web URLs or local files. It analyzes the content using a comprehensive library of regular expressions tailored to match the unique formats of secrets, API keys, and sensitive credentials from a wide range of services. When configured to do so, it can also attempt to validate the authenticity of certain secrets by making non-intrusive API calls, providing immediate feedback on the risk level of a finding.

### Key Features

*   **Multi-Target Scanning:** Capable of scanning both remote web endpoints and local files in a single operation.
*   **Extensive Signature Database:** Includes over 20 proprietary regex patterns to detect secrets from services like AWS, Google, GitHub, Stripe, OpenAI, and more.
*   **Automated Validation:** Optional feature to validate found secrets (e.g., API keys) against their respective services to confirm their active status and risk level.
*   **Intelligent Crawling:** A built-in crawler can discover and analyze linked JavaScript files and common configuration file paths (e.g., `.env`, `config.json`) from a starting URL.
*   **False Positive Reduction:** Employs a heuristic engine to filter out common non-sensitive matches, such as example keys or documentation strings, reducing noise.
*   **Concurrent Operations:** Utilizes a multi-threaded architecture for high-performance scanning of multiple targets simultaneously.
*   **Structured Output:** Reports findings in real-time to the console and can save all results in a structured JSON format for further analysis or integration into other security workflows.
*   **Detailed Categorization:** Findings are automatically categorized (e.g., 'cloud', 'payment', 'ci_cd') and summarized at the end of the scan for quick assessment.

## Installation

### Prerequisites

*   Python 3.7 or higher.
*   `pip` package manager.

### Dependencies

LeakHound requires the following Python libraries:

*   `requests`
*   `beautifulsoup4`

### Setup

1.  Clone the repository or download the `leakhound.py` script to your local machine.
2.  Install the necessary dependencies using pip:

    ```bash
    pip install requests beautifulsoup4
    ```

3.  Make the script executable (optional, for Unix-like systems):

    ```bash
    chmod +x leakhound.py
    ```

## Usage

The tool is operated via the command line. The primary mode of action is specified by using either the `-u` (URL) or `-f` (file) flags.

### Command-Line Options

| Option | Description |
|---|---|
| `-u`, `--urls` | A space-separated list of one or more URLs to scan. |
| `-f`, `--files` | A space-separated list of one or more local file paths to scan. |
| `-t`, `--timeout` | Sets the request timeout in seconds for web requests. Default: `10`. |
| `-th`, `--threads` | Specifies the number of concurrent threads to use. Default: `10`. |
| `-v`, `--verbose` | Enables verbose output, providing detailed logs of the scanning process. |
| `-o`, `--output` | Path to an output file where all findings will be saved in JSON format. |
| `--no-js` | Disables the automatic discovery and scanning of linked JavaScript files. |
| `--no-config` | Disables the checking for common configuration files (e.g., `.env`, `config.json`). |
| `--crawl` | Enables web crawling. When used with `-u`, LeakHound will follow links to JS and config files on the same domain. |
| `--validate` | Attempts to validate found secrets against their respective APIs. This is an active check and will generate network traffic. |
| `--version` | Displays the current version of LeakHound and exits. |

### Examples

#### Basic URL Scan

Scan a single URL for secrets without validation or crawling.

```bash
python3 leakhound.py -u https://example.com
```

#### Advanced URL Scan with Crawling and Validation

Scan a URL, enable crawling to find linked assets, and attempt to validate any discovered secrets. Save the output to a file.

```bash
python3 leakhound.py -u https://app.target.com --crawl --validate -o findings.json
```

#### Scanning Local Files

Scan a directory of source code files for hardcoded secrets.

```bash
python3 leakhound.py -f ./src/main.py ./config/settings.json
```

#### High-Performance Multi-Target Scan

Scan multiple URLs and multiple local files concurrently, using a higher thread count for faster execution.

```bash
python3 leakhound.py -u https://api.service1.com https://docs.service2.com -f ./src/ --threads 20 -v
```

## Output

### Console Output

LeakHound provides real-time feedback directly to the console. Each potential secret found is logged with a timestamp, the secret type, the source location, and, if validation is enabled, its status (VALID/INVALID).

At the conclusion of the scan, a summary is printed, categorizing all findings and providing a total count.

### JSON Output

When the `-o` flag is used, every finding is recorded as a JSON object in the specified output file. Each object contains the following fields:

*   `timestamp`: The ISO 8601 formatted time when the secret was found.
*   `source`: The URL or file path where the secret was located.
*   `type`: The name of the secret pattern that matched (e.g., 'GitHub Token').
*   `value`: The actual secret value that was detected.
*   `context_snippet`: A snippet of the surrounding content (up to 400 characters) for context.
*   `valid`: (Boolean, if `--validate` is used) `true` if the secret was successfully validated, otherwise `false`.
*   `risk_level`: (String, if `--validate` is used) An assessment of the risk (e.g., 'CRITICAL', 'MEDIUM').
*   `details`: (Object, if `--validate` is used) A detailed response or error message from the validation attempt.
*   `curl_command`: (String, if `--validate` is used) The cURL command equivalent to the validation check, for manual reproduction.

## Security and False Positives

While LeakHound is designed for accuracy, no automated tool is perfect. It is strongly recommended to:

1.  **Manually Verify Findings:** Always review the context of any reported secret to confirm its legitimacy and exposure.
2.  **Understand Validation:** The `--validate` flag makes active API calls. Use it judiciously to avoid triggering rate limits or security alerts on target services. The provided `curl_command` allows for safe, manual verification.

## Contributing

This tool is provided as-is for security research and testing purposes. Contributions to expand the pattern database, improve false positive detection, or enhance functionality are welcome. Please ensure any pull requests adhere to the existing code style and include appropriate testing.
