
import os
import subprocess
import requests
import re
from urllib.parse import urlparse
import concurrent.futures
import time
import sys
import urllib3

# Suppress InsecureRequestWarning from verify=False requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from utility import console, status_msg, success_msg, error_msg, warning_msg, info_msg, get_progress_bar, make_table


class WebScanner:
    def __init__(self, data_dir):
        self.data_dir = data_dir
        self.tool_dirs = {}
        self.setup_tool_dirs()

        # Curated API paths — focused, no bloat
        self.api_paths = [
            '/api', '/api/v1', '/api/v2', '/api/v3', '/graphql', '/rest',
            '/swagger', '/swagger-ui', '/swagger-ui.html', '/swagger.json',
            '/openapi', '/openapi.json', '/docs', '/redoc', '/v1', '/v2',
            '/wp-json', '/wp-json/wp/v2/posts',
        ]

        self.admin_paths = [
            '/admin', '/administrator', '/wp-admin', '/wp-login.php',
            '/login', '/signin', '/dashboard', '/cp', '/manager',
        ]

        self.sensitive_paths = [
            '/robots.txt', '/sitemap.xml', '/.env', '/.git/config',
            '/.git/HEAD', '/.svn/entries', '/config.php.bak',
            '/backup.zip', '/dump.sql', '/phpinfo.php',
            '/server-status', '/server-info',
            '/.well-known/security.txt',
        ]

        self.framework_paths = [
            '/actuator/health', '/actuator/info', '/actuator/env',
            '/storage/logs/laravel.log', '/_profiler/phpinfo',
            '/rails/info/routes', '/debug', '/console',
        ]

    def setup_tool_dirs(self):
        tools = ['gobuster', 'whatweb', 'api_checks', 'vuln_scans']
        for tool in tools:
            tool_dir = os.path.join(self.data_dir, tool)
            os.makedirs(tool_dir, exist_ok=True)
            self.tool_dirs[tool] = tool_dir

    def get_safe_filename(self, url):
        safe = url.replace('://', '_').replace(':', '_').replace('/', '_')
        safe = re.sub(r'[^a-zA-Z0-9._-]', '', safe)
        return safe[:100]

    # ─── WORDLIST DETECTION ──────────────────────────────────
    def check_wordlists(self):
        wordlists = {
            'common': '/usr/share/wordlists/dirb/common.txt',
            'small': '/usr/share/wordlists/dirb/small.txt',
            'seclists': '/usr/share/seclists/Discovery/Web-Content/common.txt',
        }

        available = {}
        for name, path in wordlists.items():
            if os.path.exists(path):
                available[name] = path

        if not available:
            minimal = [
                'admin', 'api', 'login', 'test', 'backup', 'config',
                'wp-admin', 'dashboard', 'uploads', 'images', 'css', 'js',
                '.env', '.git', 'robots.txt', 'sitemap.xml'
            ]
            minimal_path = '/tmp/minimal_wordlist.txt'
            with open(minimal_path, 'w') as f:
                f.write('\n'.join(minimal))
            available['minimal'] = minimal_path

        return available

    # ─── GOBUSTER ────────────────────────────────────────────
    def run_gobuster(self, url, timeout=90):
        wordlists = self.check_wordlists()
        if not wordlists:
            return []

        safe_name = self.get_safe_filename(url)
        results = []

        # Only use first available wordlist to save time
        wl_name, wl_path = next(iter(wordlists.items()))

        output_file = os.path.join(
            self.tool_dirs['gobuster'],
            f"gobuster_{safe_name}_{wl_name}.txt"
        )

        cmd = f"gobuster dir -u {url} -w {wl_path} -t 20 -q -o {output_file} --no-error"

        try:
            subprocess.run(
                cmd, shell=True,
                timeout=timeout,
                capture_output=True, text=True
            )

            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    for line in f:
                        if 'Status:' in line:
                            parts = line.strip().split()
                            if len(parts) >= 3:
                                path = parts[0]
                                status = parts[2]
                                # ── FILTER: skip 404, 403, 500 ──
                                try:
                                    status_code = int(status.strip('()'))
                                    if status_code >= 400:
                                        continue
                                except ValueError:
                                    continue

                                classification = self.classify_path(path)
                                results.append({
                                    'path': path,
                                    'status': status,
                                    'classification': classification,
                                    'wordlist': wl_name
                                })

        except (subprocess.TimeoutExpired, Exception):
            pass

        return results[:100]

    def classify_path(self, path):
        path_lower = path.lower()

        if any(word in path_lower for word in ['admin', 'login', 'auth', 'dashboard', 'control']):
            return 'authentication'
        elif any(word in path_lower for word in ['api', 'rest', 'graphql', 'soap', 'json']):
            return 'api'
        elif any(word in path_lower for word in ['backup', 'dump', 'sql', 'database', '.sql', '.bak']):
            return 'data_exposure'
        elif any(word in path_lower for word in ['config', 'setup', 'install', 'update', '.env']):
            return 'configuration'
        elif any(word in path_lower for word in ['test', 'dev', 'debug', 'console', 'shell']):
            return 'development'
        elif any(word in path_lower for word in ['upload', 'file', 'image', 'media']):
            return 'file_upload'
        else:
            return 'general'

    # ─── WHATWEB ─────────────────────────────────────────────
    def run_whatweb(self, url, timeout=30):
        safe_name = self.get_safe_filename(url)
        output_file = os.path.join(
            self.tool_dirs['whatweb'],
            f"whatweb_{safe_name}.txt"
        )

        cmd = f"whatweb {url} --color=never -a 3 --log-verbose={output_file}"

        try:
            subprocess.run(
                cmd, shell=True,
                timeout=timeout,
                capture_output=True, text=True
            )
            tech_data = self.parse_whatweb_output(output_file, url)
            return tech_data

        except Exception as e:
            error_msg(f"WhatWeb error: {e}")

        return {'url': url, 'technologies': []}

    def parse_whatweb_output(self, output_file, url):
        tech_data = {
            'url': url,
            'technologies': [],
            'server': '',
            'framework': '',
            'cms': '',
            'language': '',
            'details': {}
        }

        if not os.path.exists(output_file):
            return tech_data

        try:
            with open(output_file, 'r') as f:
                content = f.read()

            lines = content.split('\n')
            for line in lines:
                if ']' in line and '[' in line:
                    tech_match = re.search(r'\[(.*?)\]', line)
                    if tech_match:
                        techs = [t.strip() for t in tech_match.group(1).split(',')]
                        for tech in techs:
                            if tech and tech not in tech_data['technologies']:
                                tech_data['technologies'].append(tech)

                                tech_lower = tech.lower()
                                if any(w in tech_lower for w in ['nginx', 'apache', 'iis', 'lighttpd', 'server']):
                                    tech_data['server'] = tech
                                elif any(w in tech_lower for w in ['wordpress', 'joomla', 'drupal', 'magento']):
                                    tech_data['cms'] = tech
                                elif any(w in tech_lower for w in ['laravel', 'django', 'flask', 'rails', 'spring', 'express']):
                                    tech_data['framework'] = tech
                                elif any(w in tech_lower for w in ['php', 'python', 'ruby', 'java', 'node.js']):
                                    tech_data['language'] = tech

                if ':' in line and '[' not in line:
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        key = parts[0].strip()
                        value = parts[1].strip()
                        tech_data['details'][key] = value

        except Exception as e:
            error_msg(f"Error parsing WhatWeb output: {e}")

        return tech_data

    # ─── API ENDPOINT DISCOVERY (REFACTORED) ─────────────────
    def check_api_endpoints(self, url, timeout=3):
        """Discover API endpoints with noise filtering.
        Only returns endpoints with status < 400 and meaningful content.
        """
        safe_name = self.get_safe_filename(url)
        output_file = os.path.join(
            self.tool_dirs['api_checks'],
            f"api_{safe_name}.txt"
        )

        all_paths = self.api_paths + self.admin_paths + self.framework_paths
        endpoints = []
        checked = set()

        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
            futures = []
            for path in all_paths:
                full_url = url.rstrip('/') + path
                if full_url not in checked:
                    checked.add(full_url)
                    futures.append(executor.submit(
                        self._check_endpoint, url, path, timeout
                    ))

            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result(timeout=timeout + 2)
                    if result:
                        endpoints.append(result)
                except Exception:
                    continue

        # Sort by status code (2xx first) then by classification importance
        priority = {'api': 0, 'authentication': 1, 'configuration': 2, 'data_exposure': 3, 'general': 9}
        endpoints.sort(key=lambda x: (
            0 if 200 <= x['status'] < 300 else 1,
            priority.get(x.get('classification', 'general'), 9)
        ))

        # Save results
        with open(output_file, 'w') as f:
            for ep in endpoints[:50]:
                f.write(f"{ep['status']} | {ep['endpoint']} | {ep['info']}\n")

        return endpoints[:50]

    def _check_endpoint(self, base_url, path, timeout):
        full_url = base_url.rstrip('/') + path

        try:
            response = requests.get(
                full_url, timeout=timeout, verify=False,
                allow_redirects=False,
                headers={'User-Agent': 'Mozilla/5.0 (NullProtocol Scanner)'}
            )

            # ── NOISE FILTER: Skip 404, 500+, and tiny error pages ──
            if response.status_code >= 400:
                return None

            content_type = response.headers.get('Content-Type', '').lower()
            content_length = len(response.text)

            # Skip nearly empty responses (likely default error pages)
            if content_length < 50 and response.status_code != 204:
                return None

            info = self._classify_response(path, response, content_type, content_length)
            classification = self.classify_path(path)

            return {
                'endpoint': path,
                'url': full_url,
                'status': response.status_code,
                'length': content_length,
                'content_type': content_type,
                'info': info,
                'classification': classification,
                'redirect': response.headers.get('Location', '') if response.status_code in [301, 302] else ''
            }

        except Exception:
            return None

    def _classify_response(self, path, response, content_type, content_length):
        """Create a human-readable info string for discovered endpoints."""
        if response.status_code in [301, 302]:
            location = response.headers.get('Location', 'unknown')
            return f"Redirects -> {location}"

        if 'json' in content_type:
            try:
                data = response.json()
                if isinstance(data, dict):
                    keys = list(data.keys())[:5]
                    return f"JSON API ({', '.join(keys)})"
                elif isinstance(data, list):
                    return f"JSON Array ({len(data)} items)"
            except Exception:
                pass
            return "JSON endpoint"

        if 'html' in content_type:
            text = response.text.lower()
            if '<form' in text and ('login' in text or 'password' in text):
                return "Login/Auth page"
            elif '<form' in text:
                return "Page with form"
            elif 'admin' in path.lower():
                return "Admin interface"
            return f"HTML page ({content_length} bytes)"

        if 'xml' in content_type:
            return "XML data"

        return f"Accessible ({content_length} bytes)"

    # ─── VULNERABILITY SCAN ──────────────────────────────────
    def quick_vuln_scan(self, url, timeout=45):
        safe_name = self.get_safe_filename(url)
        output_file = os.path.join(
            self.tool_dirs['vuln_scans'],
            f"vuln_{safe_name}.txt"
        )

        findings = []

        # Categorized checks with severity rating
        checks = [
            # (Name, Path, Severity)
            ("Git Config", "/.git/config", "critical"),
            ("Git HEAD", "/.git/HEAD", "critical"),
            ("Environment File", "/.env", "critical"),
            ("Environment Backup", "/.env.bak", "critical"),
            ("Docker Compose", "/docker-compose.yml", "high"),
            ("Dockerfile", "/Dockerfile", "high"),
            ("SQL Dump", "/dump.sql", "critical"),
            ("DB Backup", "/db.sql.gz", "critical"),
            ("SQLite DB", "/database.sqlite", "critical"),
            ("Config Backup", "/config.php.bak", "high"),
            ("Zip Backup", "/backup.zip", "high"),
            ("AWS Credentials", "/.aws/credentials", "critical"),
            ("Kube Config", "/.kube/config", "critical"),
            ("Laravel Log", "/storage/logs/laravel.log", "high"),
            ("Spring Actuator Env", "/actuator/env", "high"),
            ("Spring Actuator Heap", "/actuator/heapdump", "critical"),
            ("Swagger JSON", "/swagger.json", "medium"),
            ("OpenAPI Spec", "/openapi.json", "medium"),
            ("GraphQL", "/graphql", "medium"),
            ("PHPMyAdmin", "/phpmyadmin/setup/index.php", "high"),
            ("Adminer", "/adminer.php", "high"),
            ("Robots.txt", "/robots.txt", "info"),
            ("Sitemap", "/sitemap.xml", "info"),
            ("Security.txt", "/.well-known/security.txt", "info"),
            ("Package.json", "/package.json", "low"),
            ("Composer JSON", "/composer.json", "low"),
            ("WP Config Backup", "/wp-config.php.txt", "critical"),
            ("htpasswd", "/.htpasswd", "high"),
            ("Bash History", "/.bash_history", "critical"),
            ("SSH Key", "/.ssh/id_rsa.pub", "high"),
        ]

        with open(output_file, 'w') as f:
            f.write(f"Vulnerability Scan for: {url}\n")
            f.write("=" * 60 + "\n\n")

            for check_name, path, severity in checks:
                full_url = url.rstrip('/') + path
                try:
                    response = requests.get(
                        full_url, timeout=2,
                        verify=False, allow_redirects=False
                    )

                    if response.status_code == 200 and len(response.text) > 20:
                        findings.append({
                            'type': check_name.lower().replace(' ', '_'),
                            'path': path,
                            'severity': severity,
                            'description': f"{check_name} exposed at {path}",
                            'response_length': len(response.text)
                        })

                        icon = {'critical': '[!!]', 'high': '[!]', 'medium': '[~]', 'low': '[-]', 'info': '[.]'}.get(severity, '[.]')
                        f.write(f"{icon} [{severity.upper()}] {check_name}: {full_url}\n")

                except Exception:
                    continue

            # Security headers check
            # Security headers check - DISABLED to reduce noise
            # try:
            #     response = requests.head(url, timeout=3, verify=False)
            #     headers = response.headers

            #     f.write("\n\nSecurity Headers Analysis:\n")
            #     f.write("-" * 40 + "\n")
            #     security_checks = {
            #         'X-Frame-Options': ('Missing clickjacking protection', 'medium'),
            #         'X-Content-Type-Options': ('Missing MIME sniffing protection', 'low'),
            #         'Content-Security-Policy': ('Missing CSP header', 'medium'),
            #         'Strict-Transport-Security': ('Missing HSTS header', 'medium'),
            #     }

            #     missing = []
            #     for header, (message, sev) in security_checks.items():
            #         if header not in headers:
            #             missing.append(message)
            #             f.write(f"  [x] {message}\n")
            #         else:
            #             f.write(f"  [+] {header} present\n")

            #     if missing:
            #         findings.append({
            #             'type': 'missing_security_headers',
            #             'severity': 'medium',
            #             'description': f"Missing {len(missing)} security headers",
            #             'details': missing
            #         })

            # except Exception:
            #     f.write("[!] Could not check security headers\n")

        # Sort by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        findings.sort(key=lambda x: severity_order.get(x['severity'], 5))

        return findings
