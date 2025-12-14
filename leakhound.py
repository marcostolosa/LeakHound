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

TOOL_VERSION = '1.1'

# --- ANSI Color Codes ---
class Colors:
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
        'Firebase URL': r'https://([a-zA-Z0-9-]+)\.firebaseio\.com',
        'IP Address': r'["\']((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})(?:/\d{1,2})?["\']',
        'IP with Port': r'["\']((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}:\d{1,5})(?:/\S*)?["\']',
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
    def __init__(self, timeout=10, verbose=False, threads=10, output_file=None, rate_limit=0.1):
        self.timeout = timeout
        self.verbose = verbose
        self.threads = threads
        self.rate_limit = rate_limit
        self.patterns = SecretPatterns.get_compiled_patterns()
        self.output_file = output_file
        self.file_lock = threading.Lock()
        self.visited_lock = threading.Lock()
        self.seen_values = set()
        self.summary_data = collections.defaultdict(lambda: collections.defaultdict(int))
        self.visited_urls = set()
        self.urls_to_scan = []
        self.total_urls_found = 0
        self.total_urls_scanned = 0

    def log(self, msg, color=""):
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"{color}[{ts}] {msg}{Colors.ENDC}")

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

                self.summary_data["secrets"][name] += 1

                if self.verbose:
                    self.log(
                        f"Found {name}\n"
                        f"    Value: {Colors.WARNING}{value}{Colors.ENDC}\n"
                        f"    Source: {url}",
                        Colors.OKGREEN
                    )

                if self.output_file:
                    with self.file_lock:
                        with open(self.output_file, "a") as f:
                            f.write(json.dumps(finding) + "\n")

    def _process_url(self, url):
        with self.visited_lock:
            if url in self.visited_urls:
                return
            self.visited_urls.add(url)

        try:
            if self.rate_limit > 0:
                time.sleep(self.rate_limit)

            session = requests.Session()
            session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })

            r = session.get(url, timeout=self.timeout, verify=False)
            self.total_urls_scanned += 1

            if self.verbose:
                self.log(f"Scanning [{self.total_urls_scanned}/{self.total_urls_found}]: {url}", Colors.OKCYAN)

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
                self.log(f"Error fetching {url}: {e}", Colors.FAIL)

    def scan_urls(self, urls):
        self.urls_to_scan = list(urls)
        self.total_urls_found = len(urls)

        self.log(f"Starting scan with {self.threads} threads...", Colors.OKBLUE)
        self.log(f"Initial URLs to scan: {self.total_urls_found}", Colors.OKBLUE)

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {}

            while self.urls_to_scan or futures:
                while self.urls_to_scan and len(futures) < self.threads:
                    url = self.urls_to_scan.pop(0)
                    future = executor.submit(self._process_url, url)
                    futures[future] = url

                if futures:
                    done, _ = concurrent.futures.wait(
                        futures.keys(),
                        timeout=0.1,
                        return_when=concurrent.futures.FIRST_COMPLETED
                    )

                    for future in done:
                        futures.pop(future)

        self.log(f"Scan complete. Scanned {self.total_urls_scanned} URLs total.", Colors.OKGREEN)

    def print_summary(self):
        print("\n" + "="*60)
        print("SCAN SUMMARY")
        print("="*60)

        total = sum(
            count
            for category in self.summary_data.values()
            for count in category.values()
        )

        print(f"Total URLs discovered: {self.total_urls_found}")
        print(f"Total URLs scanned: {self.total_urls_scanned}")
        print(f"Total secrets found: {total}")

        if total > 0:
            for cat, types in self.summary_data.items():
                print(f"\n{cat.upper()}:")
                for t, count in sorted(types.items(), key=lambda x: x[1], reverse=True):
                    print(f"  {t}: {count}")

        print("="*60)

# --- Main ---
def main():
    parser = argparse.ArgumentParser(
        description='LeakHound - Automated secret scanner for web infrastructure',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("-u","--urls", nargs="+", required=True, help="URLs to scan")
    parser.add_argument("-v","--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-o","--output", help="Output JSON file")
    parser.add_argument("-t","--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("-r","--rate-limit", type=float, default=0.1, help="Rate limit between requests in seconds (default: 0.1)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")

    args = parser.parse_args()

    h = LeakHound(
        timeout=args.timeout,
        verbose=args.verbose,
        threads=args.threads,
        output_file=args.output,
        rate_limit=args.rate_limit
    )

    h.scan_urls(args.urls)
    h.print_summary()
    h.log("Scan finished.", Colors.OKGREEN)

if __name__ == "__main__":
    main()
