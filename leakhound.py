#!/usr/bin/env python3
"""
LeakHound - An enterprise-grade, automated security scanner engineered
to detect and validate exposed secrets across web infrastructures.
"""

import argparse
import json
import os
import re
import sys
import time
import threading
import collections
from datetime import datetime
from typing import Dict, List, Set, Optional, Tuple
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from bs4 import BeautifulSoup

try:
    requests.packages.urllib3.disable_warnings()
except AttributeError:
    pass

TOOL_VERSION = '1.0'

# --- ANSI Color Codes ---
class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# --- Secret Patterns ---
class SecretPatterns:
    """
    Proprietary regex patterns for detecting a wide range of secrets.
    Patterns are defined as a class dictionary for clarity and maintainability.
    """
    PATTERNS = {
        'AWS Access Key': 'AKIA[0-9A-Z]{16}',
        'AWS Secret Key': '(?i)aws_secret_access_key["\']?\\s*[:=]\\s*["\']?([A-Za-z0-9/+=]{40})',
        'Google API Key': 'AIza[0-9A-Za-z\\-_]{35}',
        'Heroku API Key': '(?i)heroku.*([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})',
        'DigitalOcean Token': 'dop_v1_[a-f0-9]{64}',
        'GitHub Token': 'gh[pousr]_[0-9a-zA-Z]{36}',
        'GitLab Token': 'glpat-[0-9a-zA-Z_-]{20}',
        'Stripe Secret Key': 'sk_(live|test)_[a-zA-Z0-9]{24,}',
        'Stripe Public Key': 'pk_(live|test)_[a-zA-Z0-9]{24,}',
        'OpenAI API Key': 'sk-[a-zA-Z0-9]{48}',
        'Algolia API Key': '(?i)algolia.*([a-f0-9]{32})',
        'Shopify Token': 'shpat_[a-fA-F0-9]{32}',
        'JWT Token': 'eyJ[a-zA-Z0-9_-]*\\.eyJ[a-zA-Z0-9_-]*\\.[a-zA-Z0-9_-]*',
        'Datadog API Key': '(?i)datadog.*([a-f0-9]{32})',
        'Private Key': '-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
        'Firebase URL': 'https://([a-zA-Z0-9-]+)\\.firebaseio\\.com',
        'IP Address': '["\'](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:/[^^"\']*)?["\']',
        'IP with Port': '["\'](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5})(?:/[^^"\']*)?["\']',
        'Domain Name': '["\']((https?://)?[A-Za-z0-9.\-]+\.[A-Za-z]{2,})["\']',
        'API Path': '["\'](?:/[^^/\s$$$$\{\},\'\"\$$+)+["\']',
        'Email Address': '["\']([A-Za-z0-9._\-]+@[A-Za-z0-9.\-]{1,63}\.[A-Za-z]{2,})["\']',
        'Crypto Algorithm Usage': '\W(Base64\.encode|Base64\.decode|btoa|atob|CryptoJS\.AES|CryptoJS\.DES|JSEncrypt|rsa|KJUR|\$\.md5|md5|sha1|sha256|sha512)[$$\.]',
        'Generic API Key': '["\']?api[_-]?key["\']?\s*[:=]\s*["\']?([\w-]+)["\']?',
        'Generic Secret': '["\']?secret["\']?\s*[:=]\s*["\']?([\w-]+)["\']?',
        'Generic Token': '["\']?token["\']?\s*[:=]\s*["\']?([\w-]+)["\']?',
    }

    @classmethod
    def get_compiled_patterns(cls) -> Dict[str, re.Pattern]:
        """Return compiled regex patterns"""
        return {name: re.compile(pattern) for name, pattern in cls.PATTERNS.items()}

# --- False Positive Detection ---
# Common false positive strings to ignore
FALSE_POSITIVE_STRINGS = [
    'YOUR_API_KEY', 'YOUR_SECRET_KEY', 'API_KEY_GOES_HERE', 'SECRET_KEY_GOES_HERE',
    '1234567890abcdef', 'abcdef1234567890', 'xxxxxxxxxxxxxxxxxxxx', 'test_key',
    'example_key', 'dummy_secret', 'fake_token', 'sk_test_1234567890abcdef',
    'ghp_1234567890abcdef1234567890abcdef123456', 'AKIATEST1234567890AB',
]

def is_false_positive(value: str, context: str) -> bool:
    """
    Analyzes a string and its context to determine if it's likely a false positive.
    """
    value_lower = value.lower()
    # Check against common placeholder strings
    if value_lower in [s.lower() for s in FALSE_POSITIVE_STRINGS]:
        return True

    # Original logic
    if len(value) == 32 and re.fullmatch(r'[a-f0-9]+', value) and re.search(r'[-/]' + re.escape(value) + r'\.(svg|png|jpg|js|css|woff|gif)', context, re.IGNORECASE):
        return True
    if re.search(r'^^[vlhvcsqtaz\d.\s\-]+$', value, re.IGNORECASE):
        return True
    if value.count('-') > 5:
        return True
    if 'abcdef' in value_lower or '123456' in value_lower:
        return True
    
    return False

# --- Common Configuration File Paths ---
class ConfigFilePaths:
    """Common configuration file paths to check"""
    PATHS = [
        '.env', '.env.local', '.env.production', '.env.development', '.env.staging',
        'config.json', 'credentials.json', 'secrets.json', 'database.yml',
        'wp-config.php', '.git/config', 'web.config', 'debug.log', 'error.log',
        'access.log', 'settings.py', 'application.properties', 'config.yml'
    ]

# --- Secret Validator (Continuação) ---
class SecretValidator:
    """Comprehensive validator class for various services."""
    def __init__(self, timeout: int = 10, verbose: bool = False):
        self.timeout = timeout
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'})

    def validate_secret(self, secret_type: str, value: str, source_url: str, full_content: str) -> Dict:
        result = {'type': secret_type, 'value': value, 'valid': False, 'risk_level': 'Unknown', 'details': None, 'curl_command': None}

        if 'GitHub' in secret_type:
            return self._validate_generic_bearer('https://api.github.com/user', value, result, 'CRITICAL', scheme='token')
        if 'Stripe' in secret_type:
            return self._validate_stripe(value, result)
        if 'Heroku' in secret_type:
            return self._validate_generic_bearer('https://api.heroku.com/account', value, result, 'CRITICAL')
        if 'DigitalOcean' in secret_type:
            return self._validate_generic_bearer('https://api.digitalocean.com/v2/account', value, result, 'CRITICAL')
        if 'Slack' in secret_type: # Assuming Slack token pattern
             return self._validate_generic_bearer('https://slack.com/api/auth.test', value, result, 'CRITICAL', method='POST')
        if 'OpenAI' in secret_type:
            return self._validate_generic_bearer('https://api.openai.com/v1/models', value, result, 'CRITICAL')
        if 'Datadog' in secret_type:
            return self._validate_generic_bearer('https://api.datadoghq.com/api/v1/validate', value, result, 'HIGH', scheme='DD-API-KEY')
        
        result['note'] = 'Automatic validation not implemented for this type.'
        return result

    def _validate_generic_bearer(self, url: str, token: str, result: Dict, risk: str, scheme: str = 'Bearer', method: str = 'GET', version: Optional[str] = None) -> Dict:
        headers = {'Authorization': f'{scheme} {token}'}
        if version:
            headers['Notion-Version'] = version
        
        curl_headers = ' '.join([f'-H "{k}: {v}"' for k, v in headers.items()])
        result['curl_command'] = f'curl -X {method} {url} {curl_headers}'
        
        try:
            req_method = self.session.get if method == 'GET' else self.session.post
            response = req_method(url, headers=headers, timeout=self.timeout)
            if response.status_code == 200:
                # Some APIs return 200 with an error body
                if response.json().get('ok') or response.json().get('id') or response.json().get('login'):
                    result['valid'] = True
                    result['risk_level'] = risk
                else:
                    result['details'] = {'error': 'Invalid token (API returned error in 200 response)'}
            else:
                result['details'] = {'error': f'Invalid (Status: {response.status_code})'}
        except requests.exceptions.RequestException as e:
            result['details'] = {'error': f'Request failed: {e}'}
        except json.JSONDecodeError:
            result['details'] = {'error': 'Invalid (Non-JSON response)'}
            
        return result

    def _validate_stripe(self, key: str, result: Dict) -> Dict:
        result['curl_command'] = f'curl https://api.stripe.com/v1/balance -u {key}:'
        try:
            response = self.session.get('https://api.stripe.com/v1/balance', auth=(key, ''), timeout=self.timeout)
            if response.status_code == 200:
                result['valid'] = True
                result['risk_level'] = 'CRITICAL' if 'sk_live' in key else 'MEDIUM'
            else:
                result['details'] = {'error': f'Invalid (Status: {response.status_code})'}
        except requests.exceptions.RequestException as e:
            result['details'] = {'error': f'Request failed: {e}'}
        return result

# --- Main Secret Hunting Engine ---
class LeakHound:
    """Main secret hunting engine"""
    def __init__(self, timeout: int = 10, verbose: bool = False, threads: int = 10, validate: bool = False, output_file: Optional[str] = None):
        self.timeout = timeout
        self.verbose = verbose
        self.threads = threads
        self.validate = validate
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'})
        self.patterns = SecretPatterns.get_compiled_patterns()
        self.validator = SecretValidator(timeout=timeout, verbose=verbose) if validate else None
        self.output_file = output_file
        self.file_lock = threading.Lock()
        self.found_secrets_cache = set()
        self.seen_values = set()
        self.summary_data = collections.defaultdict(lambda: collections.defaultdict(int))
        self.visited_urls = set()
        self.url_queue = collections.deque()

    def log(self, message: str, color: str = ''):
        timestamp = datetime.now().strftime('%H:%M:%S')
        print(f'{color}[{timestamp}] {message}{Colors.ENDC}')

    def verbose_log(self, message: str):
        if self.verbose:
            self.log(message, Colors.OKCYAN)

    def categorize_finding(self, secret_type: str) -> str:
        """Categorize findings for better organization"""
        categories = {
            'infrastructure': ['IP Address', 'IP with Port', 'Domain Name', 'API Path', 'Firebase URL'],
            'personal': ['Email Address'],
            'authentication': ['JWT Token', 'Generic Token', 'Generic Secret', 'Generic API Key'],
            'cloud': ['AWS Access Key', 'AWS Secret Key', 'Google API Key', 'DigitalOcean Token', 'Heroku API Key', 'Datadog API Key'],
            'payment': ['Stripe Secret Key', 'Stripe Public Key'],
            'ci_cd': ['GitHub Token', 'GitLab Token'],
            'crypto': ['Private Key', 'Crypto Algorithm Usage'],
        }
        for category, keywords in categories.items():
            if any(keyword in secret_type for keyword in keywords):
                return category
        return 'other'

    def update_summary(self, finding: Dict):
        """Updates the summary data in a thread-safe way."""
        with self.file_lock:
            secret_type = finding['type']
            category = self.categorize_finding(secret_type)
            self.summary_data[category][secret_type] += 1

    def save_finding(self, finding: Dict):
        """Saves a finding to the output file in a thread-safe way."""
        if self.output_file:
            with self.file_lock:
                with open(self.output_file, 'a') as f:
                    f.write(json.dumps(finding) + '\n')

    def find_secrets(self, url: str, content: str):
        """Finds secrets in the given content and validates them."""
        for name, pattern in self.patterns.items():
            for match in pattern.finditer(content):
                value = match.group(1) if match.groups() else match.group(0)
                
                if not value or len(value) < 8 or value in self.seen_values:
                    continue
                if is_false_positive(value, content):
                    continue
                
                self.seen_values.add(value)
                
                start, end = match.span()
                context = content[max(0, start - 200):end + 200]
                
                finding = {
                    'timestamp': datetime.now().isoformat(),
                    'source': url,
                    'type': name,
                    'value': value,
                    'context_snippet': context.replace('\n', ' ').strip()
                }

                if self.validator:
                    validation_result = self.validator.validate_secret(name, value, url, content)
                    finding.update(validation_result)
                    status = f"({Colors.OKGREEN}VALID{Colors.ENDC})" if finding.get('valid') else f"({Colors.WARNING}INVALID{Colors.ENDC})"
                else:
                    status = ""
                
                self.log(f'{Colors.OKGREEN}✓ Found potential secret: {Colors.BOLD}{name}{Colors.ENDC} in {url} {status}', Colors.OKGREEN)
                self.save_finding(finding)
                self.update_summary(finding)


    def _process_url(self, url: str, analyze_js: bool = True, check_configs: bool = True):
        """Internal method to process a single URL."""
        if url in self.visited_urls:
            return
        self.visited_urls.add(url)

        self.verbose_log(f'Scanning URL: {url}')
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            response.raise_for_status()
            content_type = response.headers.get('Content-Type', '').lower()

            # Scan the content regardless of type
            self.find_secrets(url, response.text)

            # If HTML, parse for more resources
            if 'html' in content_type:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                if analyze_js:
                    for script in soup.find_all('script', src=True):
                        script_url = urljoin(url, script['src'])
                        self.url_queue.append(script_url)

                if check_configs:
                    for path in ConfigFilePaths.PATHS:
                        config_url = urljoin(url, path)
                        self.url_queue.append(config_url)

        except requests.exceptions.RequestException as e:
            self.verbose_log(f'Could not fetch {url}: {e}')

    def scan_urls(self, urls: List[str], crawl: bool = False):
        """Scans a list of URLs for secrets, optionally with crawling."""
        initial_urls = [url for url in urls if url.startswith(('http://', 'https://'))]
        if not initial_urls:
            self.log(f'{Colors.WARNING}No valid URLs provided to scan.{Colors.ENDC}')
            return

        self.log(f'{Colors.OKBLUE}Starting scan of {len(initial_urls)} URLs...{Colors.ENDC}')
        
        # Add initial URLs to the queue
        for url in initial_urls:
            self.url_queue.append(url)

        # Process the queue
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = set()
            while self.url_queue:
                try:
                    # Get a URL from the queue
                    url = self.url_queue.popleft()
                    
                    # If crawling is disabled, only process the initial URLs
                    if not crawl and url not in initial_urls:
                        continue
                    
                    # Submit the URL for processing
                    future = executor.submit(self._process_url, url)
                    futures.add(future)

                except IndexError:
                    # Queue is empty, just wait for remaining tasks
                    pass
                except Exception as e:
                    self.log(f'Error managing URL queue: {e}', Colors.FAIL)

                # Clean up completed futures to prevent memory buildup
                done_futures = [f for f in futures if f.done()]
                for f in done_futures:
                    futures.remove(f)
                    try:
                        f.result()  # To catch and log any exceptions from the thread
                    except Exception as exc:
                        # Error is already logged inside _process_url, but we can log it here too if needed
                        pass
            
            # Wait for any remaining futures to complete
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as exc:
                    pass # Error already logged

    def scan_local_files(self, file_paths: List[str]):
        """Scans a list of local files for secrets using a thread pool."""
        if not file_paths:
            self.log(f'{Colors.WARNING}No valid local files provided to scan.{Colors.ENDC}')
            return

        self.log(f'{Colors.OKBLUE}Starting scan of {len(file_paths)} local files...{Colors.ENDC}')
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_file = {executor.submit(self.scan_local_file, path): path for path in file_paths}
            for future in as_completed(future_to_file):
                path = future_to_file[future]
                try:
                    future.result()
                except Exception as exc:
                    self.log(f'File "{path}" generated an exception: {exc}', Colors.FAIL)

    def scan_local_file(self, file_path: str):
        """Scans a single local file for secrets."""
        if not os.path.isfile(file_path):
            self.log(f'File not found: {file_path}', Colors.WARNING)
            return
            
        self.verbose_log(f'Scanning file: {file_path}')
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            self.find_secrets(f'file://{file_path}', content)
        except Exception as e:
            self.log(f'Could not read file {file_path}: {e}', Colors.FAIL)

    def print_summary(self):
        """Prints a summary of the findings."""
        print('\n==================================================')
        print(f'{Colors.HEADER}Scan Summary{Colors.ENDC}')
        print('==================================================')
        total_secrets = sum(counts for types in self.summary_data.values() for count in types.values())
        print(f"Total potential secrets found: {Colors.BOLD}{total_secrets}{Colors.ENDC}")

        if not self.summary_data:
            print('No secrets found.')
            return

        for category, types in sorted(self.summary_data.items()):
            print(f'\n{Colors.BOLD}{category.title()}{Colors.ENDC}')
            for type_name, count in sorted(types.items()):
                print(f' - {type_name}: {count}')
        print('==================================================')

    def save_results(self):
        """Saves the full results to the specified output file."""
        if self.output_file:
            self.log(f'Results saved to {self.output_file}', Colors.OKGREEN)

# --- Main Execution ---
def main():
    parser = argparse.ArgumentParser(
        description='LeakHound - An enterprise-grade secret scanner.',
        epilog="Example: python3 leakhound.py -u https://example.com --files ./src/ -o results.json --validate"
    )
    parser.add_argument('-u', '--urls', nargs='+', help='List of URLs to scan.')
    parser.add_argument('-f', '--files', nargs='+', help='List of local files to scan for secrets.')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Request timeout in seconds (default: 10).')
    parser.add_argument('-th', '--threads', type=int, default=10, help='Number of concurrent threads (default: 10).')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output.')
    parser.add_argument('-o', '--output', help='Output file to save results (JSON format).')
    parser.add_argument('--no-js', action='store_true', help='Skip JavaScript file analysis.')
    parser.add_argument('--no-config', action='store_true', help='Skip common config file checks.')
    parser.add_argument('--crawl', action='store_true', help='Enable web crawling for secret discovery from the given URLs.')
    parser.add_argument('--validate', action='store_true', help='Attempt to validate found secrets against their respective APIs.')
    parser.add_argument('--version', action='version', version=f'LeakHound v{TOOL_VERSION}')

    args = parser.parse_args()

    if not args.urls and not args.files:
        parser.print_help()
        sys.exit(1)

    hunter = LeakHound(
        timeout=args.timeout,
        verbose=args.verbose,
        threads=args.threads,
        validate=args.validate,
        output_file=args.output
    )

    if args.urls:
        hunter.scan_urls(args.urls, crawl=args.crawl)

    if args.files:
        hunter.scan_local_files(args.files)

    hunter.print_summary()
    hunter.save_results()
    hunter.log(f'{Colors.OKGREEN}Scan finished.{Colors.ENDC}')


if __name__ == '__main__':
    main()
