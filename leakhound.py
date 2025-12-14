#!/usr/bin/env python3
"""
LeakHound - Automated security scanner for detecting exposed secrets
across web infrastructures.
"""

import argparse
import json
import os
import re
import sys
import time
import threading
import collections
import concurrent.futures
import hashlib
import tempfile
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Set, Optional, Tuple
from urllib.parse import urljoin, urlparse, quote
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright, Browser, Page
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich.layout import Layout
from rich.text import Text
from rich import box
import colorama

try:
    requests.packages.urllib3.disable_warnings()
except AttributeError:
    pass

colorama.init()

TOOL_VERSION = '1.1'

# Monokai Color Scheme
class MonokaiColors:
    BACKGROUND = "#272822"
    FOREGROUND = "#F8F8F2"
    CYAN = "#66D9EF"        # Keywords
    GREEN = "#A6E22E"       # Strings
    ORANGE = "#FD971F"      # Numbers
    PINK = "#F92672"        # Functions
    PURPLE = "#AE81FF"      # Constants
    YELLOW = "#E6DB74"      # Comments

# Rich Console with Monokai theme
console = Console()

# --- Secret Patterns (TODOS OS ORIGINAIS RESTAURADOS) ---
class SecretPatterns:
    PATTERNS = {
        'AWS Access Key': r'AKIA[0-9A-Z]{16}',
        'AWS Secret Key': r'(?i)aws_secret_access_key["\']?\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})',
        'Google API Key': r'AIza[0-9A-Za-z\-_]{35}',
        'Heroku API Key': r'(?i)heroku.*([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})',
        'DigitalOcean Token': r'dop_v1_[a-f0-9]{64}',
        'GitHub Token': r'\bgh(?:p|o|u|r|s|e)_[0-9A-Za-z]{36}\b',
        'GitLab Token': r'\bglpat-[0-9a-zA-Z_-]{20}\b',
        'Stripe Secret Key': r'\bsk_(?:live|test)_[A-Za-z0-9]{24,}\b',
        'Stripe Public Key': r'\bpk_(?:live|test)_[A-Za-z0-9]{24,}\b',
        'OpenAI API Key': r'\bsk-[A-Za-z0-9]{48}\b',
        'Algolia API Key': r'(?i)algolia.*([a-f0-9]{32})',
        'Shopify Token': r'\bshpat_[A-Fa-f0-9]{32}\b',
        'JWT Token': r'\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\b',
        'Datadog API Key': r'(?i)datadog.*([a-f0-9]{32})',
        'Private Key': r'-----BEGIN (?:RSA|EC|DSA|OPENSSH)?\s*PRIVATE KEY-----',
        'Crypto Algorithm Usage': r'\b(?:Base64\.encode|Base64\.decode|btoa|atob|CryptoJS\.AES|CryptoJS\.DES|JSEncrypt|rsa|KJUR|(?:md5|sha1|sha256|sha512))\b',
        'Firebase URL': r'https://([a-zA-Z0-9-]+)\.firebaseio\.com',
        'IP Address': r'["\']((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})(?:/\d{1,2})?["\']',
        'IP with Port': r'["\']((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}:\d{1,5})(?:/\S*)?["\']',
        'Domain Name': r'["\']((?:https?://)?[A-Za-z0-9.\-]+\.[A-Za-z]{2,})(?:[/:][^"\']*)?["\']',
        'API Path': r'["\'](\/[^\s\'"]{1,512})["\']',
        'Email Address': r'["\']([A-Za-z0-9._\-]+@[A-Za-z0-9.\-]{1,63}\.[A-Za-z]{2,})["\']',
        'Generic API Key': r'["\']?api[_-]?key["\']?\s*[:=]\s*["\']?([\w-]{8,256})["\']?',
        'Generic Secret': r'["\']?secret["\']?\s*[:=]\s*["\']?([\w-]{8,256})["\']?',
        'Generic Token': r'["\']?token["\']?\s*[:=]\s*["\']?([\w-]{8,256})["\']?',
    }

    @classmethod
    def get_compiled_patterns(cls) -> Dict[str, re.Pattern]:
        compiled = {}
        for name, pattern in cls.PATTERNS.items():
            compiled[name] = re.compile(pattern)
        return compiled

# --- False Positives ---
FALSE_POSITIVE_STRINGS = [
    'YOUR_API_KEY','YOUR_SECRET_KEY','API_KEY_GOES_HERE','SECRET_KEY_GOES_HERE',
    '1234567890abcdef','abcdef1234567890','xxxxxxxxxxxxxxxxxxxx','test_key',
    'example_key','dummy_secret','fake_token','sk_test_1234567890abcdef',
    'ghp_1234567890abcdef1234567890abcdef123456','AKIATEST1234567890AB',
    'example.com','example.org','localhost','127.0.0.1',
]

def is_false_positive(value: str, context: str) -> bool:
    if not value:
        return True

    v_lower = value.lower()
    if v_lower in {s.lower() for s in FALSE_POSITIVE_STRINGS}:
        return True

    if len(value) < 8:
        return True

    if value.count('-') > 6:
        return True

    if 'abcdef' in v_lower or '123456' in v_lower or 'test' in v_lower:
        return True

    if 'example' in v_lower or 'placeholder' in v_lower or 'replace' in v_lower:
        return True

    return False

# --- Config Paths ---
class ConfigFilePaths:
    PATHS = [
        '.env','.env.local','.env.production','.env.development','.env.staging',
        'config.json','credentials.json','secrets.json','database.yml',
        'wp-config.php','.git/config','web.config','debug.log','error.log',
        'access.log','settings.py','application.properties','config.yml'
    ]

# --- LeakHound Engine ---
class LeakHound:
    def __init__(self, timeout=10, verbose=False, threads=10, output_file=None, rate_limit=0.1, headless=False):
        self.timeout = timeout
        self.verbose = verbose
        self.threads = threads
        self.rate_limit = rate_limit
        self.headless = headless
        self.patterns = SecretPatterns.get_compiled_patterns()
        self.output_file = output_file
        self.file_lock = threading.Lock()
        self.visited_lock = threading.Lock()
        self.seen_values = set()
        self.summary_data = collections.defaultdict(lambda: collections.defaultdict(list))
        self.visited_urls = set()
        self.urls_to_scan = []
        self.total_urls_found = 0
        self.total_urls_scanned = 0
        self.playwright = None
        self.browser = None

    def log(self, msg, color=MonokaiColors.FOREGROUND):
        ts = datetime.now().strftime("%H:%M:%S")
        console.print(f"[{color}][{ts}] {msg}[/{color}]")

    def display_secret(self, secret_type, value, source):
        """Display secret in beautiful Monokai-styled panel"""
        table = Table(box=box.ROUNDED, show_header=False, border_style=MonokaiColors.CYAN)
        table.add_column("Key", style=MonokaiColors.ORANGE)
        table.add_column("Value", style=MonokaiColors.GREEN)

        table.add_row("Type", secret_type)
        table.add_row("Value", value[:100] + "..." if len(value) > 100 else value)
        table.add_row("Source", source)

        panel = Panel(
            table,
            title=f"[{MonokaiColors.PINK}]Found Secret[/{MonokaiColors.PINK}]",
            border_style=MonokaiColors.PURPLE,
            box=box.DOUBLE
        )
        console.print(panel)

    def find_secrets(self, url, content):
        for name, pattern in self.patterns.items():
            for match in pattern.finditer(content):

                value = match.group(1) if match.groups() else match.group(0)

                if not value or len(value) < 6:
                    continue

                if value in self.seen_values:
                    continue

                if is_false_positive(value, content):
                    continue

                self.seen_values.add(value)

                finding = {
                    "timestamp": datetime.now().isoformat(),
                    "source": url,
                    "type": name,
                    "value": value
                }

                # Group by category
                self.summary_data[name]["findings"].append(finding)

                # Display immediately
                self.display_secret(name, value, url)

                # Write to file with lock
                if self.output_file:
                    with self.file_lock:
                        with open(self.output_file, "a") as f:
                            f.write(json.dumps(finding) + "\n")

    def _process_url(self, url):
        # Thread-safe visited check
        with self.visited_lock:
            if url in self.visited_urls:
                return
            self.visited_urls.add(url)

        try:
            if self.rate_limit > 0:
                time.sleep(self.rate_limit)

            # Per-thread session
            session = requests.Session()
            session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })

            r = session.get(url, timeout=self.timeout, verify=False)
            self.total_urls_scanned += 1

            if self.verbose:
                self.log(f"Scanning [{self.total_urls_scanned}/{self.total_urls_found}]: {url}", MonokaiColors.CYAN)

            content = r.text
            self.find_secrets(url, content)

            if "html" in r.headers.get("Content-Type", ""):
                soup = BeautifulSoup(content, "html.parser")
                for script in soup.find_all("script", src=True):
                    js_url = urljoin(url, script["src"])
                    if js_url not in self.visited_urls:
                        self.urls_to_scan.append(js_url)
                        self.total_urls_found += 1

                for path in ConfigFilePaths.PATHS:
                    cfg_url = urljoin(url, path)
                    if cfg_url not in self.visited_urls:
                        self.urls_to_scan.append(cfg_url)
                        self.total_urls_found += 1

        except Exception as e:
            if self.verbose:
                self.log(f"Error fetching {url}: {e}", MonokaiColors.PINK)

    def save_resource(self, url, content, cache_dir):
        """Save resource to cache directory"""
        try:
            # Create safe filename from URL
            url_hash = hashlib.md5(url.encode()).hexdigest()[:12]
            parsed = urlparse(url)
            path_parts = parsed.path.strip('/').split('/')
            filename = path_parts[-1] if path_parts and path_parts[-1] else 'index.html'

            # Limit filename length
            if len(filename) > 100:
                ext = Path(filename).suffix
                filename = filename[:100] + ext

            safe_filename = f"{url_hash}_{filename}"
            filepath = cache_dir / safe_filename

            # Save content
            with open(filepath, 'wb') as f:
                if isinstance(content, str):
                    f.write(content.encode('utf-8', errors='ignore'))
                else:
                    f.write(content)

            return filepath
        except Exception as e:
            if self.verbose:
                self.log(f"Failed to save {url}: {e}", MonokaiColors.PINK)
            return None

    def scan_with_playwright(self, url):
        """Open browser ONCE, download ALL resources, scan offline (faster, stealthier)"""
        try:
            self.log(f"Opening browser for: {url}", MonokaiColors.CYAN)

            # Create cache directory
            domain = urlparse(url).netloc
            cache_dir = Path(tempfile.gettempdir()) / 'leakhound_cache' / domain
            cache_dir.mkdir(parents=True, exist_ok=True)

            saved_files = []
            resources_captured = []

            with sync_playwright() as p:
                browser = p.chromium.launch(headless=self.headless)
                page = browser.new_page()

                # Intercept ALL responses (like a real browser)
                def handle_response(response):
                    try:
                        url_resp = response.url
                        content_type = response.headers.get('content-type', '')

                        # Save files that typically contain secrets
                        if any(ext in url_resp for ext in ['.js', '.json', '.xml', '.html', '.css', '.txt', '.env', '.yml', '.yaml', '.config', '.properties']):
                            resources_captured.append(url_resp)
                            # Download resource content
                            try:
                                body = response.body()
                                filepath = self.save_resource(url_resp, body, cache_dir)
                                if filepath:
                                    saved_files.append((url_resp, filepath))
                            except:
                                pass
                    except:
                        pass

                page.on('response', handle_response)

                self.log(f"Loading {url} (capturing all resources)...", MonokaiColors.GREEN)
                page.goto(url, timeout=30000, wait_until="networkidle")

                # Also save main page content
                main_content = page.content()
                main_file = self.save_resource(url, main_content, cache_dir)
                if main_file:
                    saved_files.append((url, main_file))

                # Get additional URLs from DOM (for config paths)
                discovered_urls = page.evaluate(r"""
                    () => {
                        let urls = [];
                        performance.getEntriesByType('resource').forEach(r => urls.push(r.name));
                        return urls;
                    }
                """)

                self.log(f"Captured {len(saved_files)} files, closing browser...", MonokaiColors.GREEN)
                time.sleep(1)  # Brief pause for user to see
                browser.close()

            # Now scan all saved files OFFLINE (much faster!)
            self.log(f"Scanning {len(saved_files)} files offline...", MonokaiColors.CYAN)
            for source_url, filepath in saved_files:
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        self.find_secrets(source_url, content)
                        self.total_urls_scanned += 1
                except:
                    pass

            # Add config paths to test
            for path in ConfigFilePaths.PATHS:
                cfg_url = urljoin(url, path)
                if cfg_url not in self.visited_urls:
                    self.urls_to_scan.append(cfg_url)
                    self.total_urls_found += 1

            # Add discovered resources to scan queue
            for resource_url in discovered_urls:
                if resource_url and not resource_url.startswith('data:'):
                    if resource_url not in self.visited_urls:
                        self.urls_to_scan.append(resource_url)
                        self.total_urls_found += 1

        except Exception as e:
            self.log(f"Playwright error: {e}, falling back to requests...", MonokaiColors.PINK)
            # Fallback to requests
            try:
                session = requests.Session()
                session.headers.update({
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                })
                r = session.get(url, timeout=30, verify=False)
                content = r.text
                self.find_secrets(url, content)
                self.total_urls_scanned += 1

                # Parse JS files
                soup = BeautifulSoup(content, "html.parser")
                for script in soup.find_all("script", src=True):
                    js_url = urljoin(url, script["src"])
                    if js_url not in self.visited_urls:
                        self.urls_to_scan.append(js_url)
                        self.total_urls_found += 1

                # Add config paths
                for path in ConfigFilePaths.PATHS:
                    cfg_url = urljoin(url, path)
                    if cfg_url not in self.visited_urls:
                        self.urls_to_scan.append(cfg_url)
                        self.total_urls_found += 1
            except Exception as e2:
                self.log(f"Fallback also failed: {e2}", MonokaiColors.PINK)

    def scan_urls(self, urls):
        # Normalize URLs (add https:// if missing)
        normalized_urls = []
        for url in urls:
            if not url.startswith("http://") and not url.startswith("https://"):
                url = "https://" + url
            normalized_urls.append(url)

        self.urls_to_scan = normalized_urls
        self.total_urls_found = len(normalized_urls)

        console.print(Panel(
            f"[{MonokaiColors.GREEN}]Starting LeakHound v{TOOL_VERSION}[/{MonokaiColors.GREEN}]\n"
            f"[{MonokaiColors.CYAN}]Threads: {self.threads}[/{MonokaiColors.CYAN}]\n"
            f"[{MonokaiColors.CYAN}]Initial URLs: {self.total_urls_found}[/{MonokaiColors.CYAN}]",
            title="[bold]LeakHound Scanner[/bold]",
            border_style=MonokaiColors.PURPLE,
            box=box.DOUBLE
        ))

        # Use playwright for initial URLs
        for url in normalized_urls:
            self.scan_with_playwright(url)
            with self.visited_lock:
                self.visited_urls.add(url)

        # Now scan discovered resources with threading (FIXED RACE CONDITION)
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {}

            while self.urls_to_scan or futures:
                # Submit tasks up to thread limit
                while self.urls_to_scan and len(futures) < self.threads:
                    url = self.urls_to_scan.pop(0)
                    future = executor.submit(self._process_url, url)
                    futures[future] = url

                # Wait for tasks to complete
                if futures:
                    done, _ = concurrent.futures.wait(
                        futures.keys(),
                        timeout=0.1,
                        return_when=concurrent.futures.FIRST_COMPLETED
                    )

                    for future in done:
                        futures.pop(future)

        self.log(f"Scan complete. Scanned {self.total_urls_scanned} URLs total.", MonokaiColors.GREEN)

    def print_summary(self):
        """Display summary grouped by category"""
        total = sum(len(data["findings"]) for data in self.summary_data.values())

        # Summary table
        summary_table = Table(box=box.DOUBLE, border_style=MonokaiColors.CYAN)
        summary_table.add_column("Metric", style=MonokaiColors.ORANGE)
        summary_table.add_column("Value", style=MonokaiColors.GREEN, justify="right")

        summary_table.add_row("URLs Discovered", str(self.total_urls_found))
        summary_table.add_row("URLs Scanned", str(self.total_urls_scanned))
        summary_table.add_row("Total Secrets Found", str(total))

        console.print(Panel(
            summary_table,
            title="[bold]Scan Summary[/bold]",
            border_style=MonokaiColors.PURPLE,
            box=box.DOUBLE
        ))

        if total > 0:
            # Category breakdown
            category_table = Table(box=box.ROUNDED, border_style=MonokaiColors.CYAN)
            category_table.add_column("Secret Type", style=MonokaiColors.ORANGE)
            category_table.add_column("Count", style=MonokaiColors.GREEN, justify="right")

            for secret_type, data in sorted(self.summary_data.items(), key=lambda x: len(x[1]["findings"]), reverse=True):
                count = len(data["findings"])
                category_table.add_row(secret_type, str(count))

            console.print(Panel(
                category_table,
                title="[bold]Secrets by Category[/bold]",
                border_style=MonokaiColors.PURPLE,
                box=box.ROUNDED
            ))

# --- Main ---
def main():
    parser = argparse.ArgumentParser(
        description='LeakHound - Automated secret scanner with visual browser',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("-u","--urls", nargs="+", required=True, help="URLs to scan")
    parser.add_argument("-v","--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-o","--output", help="Output JSON file")
    parser.add_argument("-t","--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("-r","--rate-limit", type=float, default=0.1, help="Rate limit between requests in seconds (default: 0.1)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--headless", action="store_true", help="Run browser in headless mode")

    args = parser.parse_args()

    h = LeakHound(
        timeout=args.timeout,
        verbose=args.verbose,
        threads=args.threads,
        output_file=args.output,
        rate_limit=args.rate_limit,
        headless=args.headless
    )

    h.scan_urls(args.urls)
    h.print_summary()
    h.log("Scan finished.", MonokaiColors.GREEN)

if __name__ == "__main__":
    main()
