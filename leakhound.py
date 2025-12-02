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

    return False

# --- Config Paths ---
class ConfigFilePaths:
    PATHS = [
        '.env','.env.local','.env.production','.env.development','.env.staging',
        'config.json','credentials.json','secrets.json','database.yml',
        'wp-config.php','.git/config','web.config','debug.log','error.log',
        'access.log','settings.py','application.properties','config.yml'
    ]

# --- Validator (mantido) ---
class SecretValidator:
    def __init__(self, timeout=10, verbose=False):
        self.timeout = timeout
        self.verbose = verbose
        self.session = requests.Session()

    def validate_secret(self, secret_type, value, source_url, full_content):
        return {
            "type": secret_type,
            "value": value,
            "valid": False,
        }

# --- LeakHound Engine ---
class LeakHound:
    def __init__(self, timeout=10, verbose=False, threads=10, validate=False, output_file=None):
        self.timeout = timeout
        self.verbose = verbose
        self.threads = threads
        self.validate = validate
        self.patterns = SecretPatterns.get_compiled_patterns()
        self.validator = SecretValidator() if validate else None
        self.output_file = output_file
        self.file_lock = threading.Lock()
        self.seen_values = set()
        self.summary_data = collections.defaultdict(lambda: collections.defaultdict(int))
        self.visited_urls = set()
        self.url_queue = collections.deque()
        self.session = requests.Session()

    def log(self, msg, color=""):
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"{color}[{ts}] {msg}{Colors.ENDC}")

    def find_secrets(self, url, content):
        """Agora mostra o valor **completo** encontrado na tela"""
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

                self.summary_data["infrastructure"][name] += 1

                # 🔥 Exibe o valor na tela
                self.log(
                    f"✓ Found potential secret: {name}\n"
                    f"    Value: {Colors.WARNING}{value}{Colors.ENDC}\n"
                    f"    Source: {url}",
                    Colors.OKGREEN
                )

                if self.output_file:
                    with open(self.output_file, "a") as f:
                        f.write(json.dumps(finding) + "\n")

    def _process_url(self, url):
        if url in self.visited_urls:
            return
        self.visited_urls.add(url)

        try:
            r = self.session.get(url, timeout=self.timeout, verify=False)
            content = r.text
            self.find_secrets(url, content)

            if "html" in r.headers.get("Content-Type", ""):
                soup = BeautifulSoup(content, "html.parser")
                for script in soup.find_all("script", src=True):
                    js_url = urljoin(url, script["src"])
                    self.url_queue.append(js_url)

                for path in ConfigFilePaths.PATHS:
                    cfg_url = urljoin(url, path)
                    self.url_queue.append(cfg_url)

        except Exception as e:
            self.log(f"Error fetching {url}: {e}", Colors.FAIL)

    def scan_urls(self, urls, crawl=False):
        for u in urls:
            self.url_queue.append(u)

        with ThreadPoolExecutor(max_workers=self.threads) as exe:
            while self.url_queue:
                url = self.url_queue.popleft()
                exe.submit(self._process_url, url)

    def print_summary(self):
        print("\n==================================================")
        print("Scan Summary")
        print("==================================================")

        # BUG FIX
        total = sum(
            count
            for category in self.summary_data.values()
            for count in category.values()
        )

        print(f"Total potential secrets found: {total}")

        for cat, types in self.summary_data.items():
            print(f"\n{cat.upper()}")
            for t, count in types.items():
                print(f" - {t}: {count}")
        print("==================================================")

# --- Main ---
def main():
    p = argparse.ArgumentParser()
    p.add_argument("-u","--urls", nargs="+")
    p.add_argument("-v","--verbose", action="store_true")
    p.add_argument("-o","--output")
    p.add_argument("--crawl", action="store_true")

    args = p.parse_args()

    if not args.urls:
        p.print_help()
        sys.exit(1)

    h = LeakHound(verbose=args.verbose, output_file=args.output)
    h.scan_urls(args.urls, crawl=args.crawl)
    h.print_summary()
    h.log("Scan finished.", Colors.OKGREEN)

if __name__ == "__main__":
    main()
