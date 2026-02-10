#!/usr/bin/env python3
"""
Crawler Tool -- Crawls a website to find pages with parameters
susceptible to SQL injection (for use with SQLMap).
"""

import requests
import re
import os
import sys
import urllib3
from urllib.parse import urlparse, urljoin, parse_qs
from collections import deque

# Suppress InsecureRequestWarning from verify=False requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from utility import console, status_msg, success_msg, error_msg, warning_msg, info_msg, get_progress_bar


class SQLiCrawler:
    """Crawls a website and finds URLs with query parameters and forms
    that could be tested with SQLMap."""

    def __init__(self, data_dir, max_pages=100, timeout=5):
        self.data_dir = data_dir
        self.max_pages = max_pages
        self.timeout = timeout
        self.tool_dir = os.path.join(data_dir, 'crawler')
        os.makedirs(self.tool_dir, exist_ok=True)

        self.visited = set()
        self.param_urls = []       # URLs with query parameters
        self.form_targets = []     # Forms found on pages
        self.potential_sqli = []   # High-priority SQLi targets
        self._seen_param_keys = set()  # Dedup: (path, sorted_params)
        self._seen_form_keys = set()   # Dedup: (action_path, sorted_fields)

        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0'
        })

    def crawl(self, start_url):
        """Crawl the website starting from start_url."""
        parsed = urlparse(start_url)
        base_domain = parsed.netloc
        scheme = parsed.scheme

        queue = deque([start_url])
        self.visited.add(start_url)
        pages_crawled = 0

        status_msg(f"Crawling {start_url} (max {self.max_pages} pages)...")

        while queue and pages_crawled < self.max_pages:
            url = queue.popleft()
            pages_crawled += 1

            try:
                resp = self.session.get(url, timeout=self.timeout, verify=False, allow_redirects=True)

                if resp.status_code != 200:
                    continue

                content_type = resp.headers.get('Content-Type', '')
                if 'html' not in content_type.lower():
                    continue

                html = resp.text

                # 1. Find URLs with parameters
                self._extract_param_urls(html, url, base_domain)

                # 2. Find forms
                self._extract_forms(html, url)

                # 3. Find new links to crawl
                links = self._extract_links(html, url, base_domain)
                for link in links:
                    if link not in self.visited:
                        self.visited.add(link)
                        queue.append(link)

            except requests.exceptions.Timeout:
                continue
            except Exception:
                continue

        success_msg(f"Crawled {pages_crawled} pages, found {len(self.param_urls)} parameterized URLs, {len(self.form_targets)} forms")

        # Identify high-priority SQLi targets
        self._identify_sqli_targets()

        return {
            'pages_crawled': pages_crawled,
            'param_urls': self.param_urls,
            'form_targets': self.form_targets,
            'potential_sqli': self.potential_sqli
        }

    def _extract_links(self, html, current_url, base_domain):
        """Extract all links on the page within the same domain."""
        links = set()
        href_pattern = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)

        for match in href_pattern.finditer(html):
            href = match.group(1).strip()

            # Skip non-http links
            if href.startswith(('#', 'mailto:', 'tel:', 'javascript:')):
                continue

            full_url = urljoin(current_url, href)
            parsed = urlparse(full_url)

            # Stay on same domain
            if parsed.netloc == base_domain:
                # Remove fragments
                clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                if parsed.query:
                    clean_url += f"?{parsed.query}"
                links.add(clean_url)

        return links

    def _extract_param_urls(self, html, current_url, base_domain):
        """Find URLs with query parameters (prime SQLi targets)."""
        urls_to_check = []

        # Check current URL
        parsed = urlparse(current_url)
        if parsed.query:
            urls_to_check.append((current_url, 'direct'))

        # Find links with parameters in the HTML
        href_pattern = re.compile(r'href=["\']([^"\']*\?[^"\']+)["\']', re.IGNORECASE)
        for match in href_pattern.finditer(html):
            href = match.group(1)
            full_url = urljoin(current_url, href)
            p = urlparse(full_url)
            if p.netloc == base_domain and p.query:
                urls_to_check.append((full_url, 'link'))

        for url, source in urls_to_check:
            p = urlparse(url)
            params = sorted(parse_qs(p.query).keys())
            # Dedup key: path + sorted param names (ignores scheme, host, param values)
            dedup_key = (p.path, tuple(params))
            if dedup_key not in self._seen_param_keys:
                self._seen_param_keys.add(dedup_key)
                self.param_urls.append({
                    'url': url,
                    'params': params,
                    'source': source
                })

    def _extract_forms(self, html, current_url):
        """Extract forms from HTML (POST forms are great SQLi targets)."""
        form_pattern = re.compile(
            r'<form[^>]*>(.*?)</form>',
            re.IGNORECASE | re.DOTALL
        )
        action_pattern = re.compile(r'action=["\']([^"\']*)["\']', re.IGNORECASE)
        method_pattern = re.compile(r'method=["\']([^"\']*)["\']', re.IGNORECASE)
        input_pattern = re.compile(
            r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>',
            re.IGNORECASE
        )
        select_pattern = re.compile(
            r'<select[^>]*name=["\']([^"\']+)["\'][^>]*>',
            re.IGNORECASE
        )
        textarea_pattern = re.compile(
            r'<textarea[^>]*name=["\']([^"\']+)["\'][^>]*>',
            re.IGNORECASE
        )

        for form_match in form_pattern.finditer(html):
            form_html = form_match.group(0)
            form_content = form_match.group(1)

            # Extract action
            action_match = action_pattern.search(form_html)
            action = action_match.group(1) if action_match else current_url
            action_url = urljoin(current_url, action)

            # Extract method
            method_match = method_pattern.search(form_html)
            method = method_match.group(1).upper() if method_match else 'GET'

            # Extract input fields
            fields = []
            for pat in [input_pattern, select_pattern, textarea_pattern]:
                fields.extend(pat.findall(form_content))

            if fields:
                # Dedup key: action path + sorted unique field names
                action_path = urlparse(action_url).path
                dedup_key = (action_path, tuple(sorted(set(fields))))
                if dedup_key not in self._seen_form_keys:
                    self._seen_form_keys.add(dedup_key)
                    self.form_targets.append({
                        'action': action_url,
                        'method': method,
                        'fields': fields,
                        'page': current_url
                    })

    def _identify_sqli_targets(self):
        """Score and rank targets for SQL injection potential."""
        sqli_keywords = ['id', 'user', 'uid', 'name', 'search', 'query', 'q',
                         'category', 'cat', 'page', 'item', 'product', 'order',
                         'sort', 'type', 'view', 'action', 'file', 'path',
                         'table', 'select', 'report', 'role', 'update', 'login',
                         'email', 'pass', 'password', 'username']

        raw_targets = []

        for entry in self.param_urls:
            score = 0
            for param in entry['params']:
                if param.lower() in sqli_keywords:
                    score += 3
                elif any(kw in param.lower() for kw in sqli_keywords):
                    score += 1

            if score > 0:
                raw_targets.append({
                    'url': entry['url'],
                    'params': entry['params'],
                    'sqli_score': score,
                    'type': 'get_param'
                })

        for form in self.form_targets:
            score = 0
            for field in form['fields']:
                if field.lower() in sqli_keywords:
                    score += 3
                elif any(kw in field.lower() for kw in sqli_keywords):
                    score += 1

            # POST forms are higher priority for SQLi
            if form['method'] == 'POST':
                score += 2

            if score > 0:
                raw_targets.append({
                    'url': form['action'],
                    'method': form['method'],
                    'fields': form['fields'],
                    'sqli_score': score,
                    'type': 'form'
                })

        # ── Final dedup: collapse HTTP/HTTPS and IP variants ──
        # Key on (path, sorted params/fields, type) — keep highest score
        best = {}  # dedup_key -> target
        for t in raw_targets:
            parsed = urlparse(t['url'])
            if t['type'] == 'get_param':
                key = (parsed.path, tuple(sorted(t.get('params', []))), 'get_param')
            else:
                key = (parsed.path, tuple(sorted(set(t.get('fields', [])))), 'form')

            if key not in best or t['sqli_score'] > best[key]['sqli_score']:
                best[key] = t

        self.potential_sqli = sorted(best.values(), key=lambda x: x['sqli_score'], reverse=True)

    def save_results(self, domain):
        """Save crawler results to files."""
        # Save parameterized URLs for SQLMap
        sqlmap_file = os.path.join(self.tool_dir, f'sqlmap_targets_{domain}.txt')
        with open(sqlmap_file, 'w') as f:
            f.write(f"# SQLMap Targets for {domain}\n")
            f.write(f"# Generated by NullProtocol Crawler\n")
            f.write(f"# Usage: sqlmap -m {sqlmap_file} --batch\n\n")

            for target in self.potential_sqli:
                if target['type'] == 'get_param':
                    f.write(f"{target['url']}\n")
                elif target['type'] == 'form':
                    params = '&'.join([f"{field}=test" for field in target['fields']])
                    f.write(f"# POST: {target['url']} (fields: {', '.join(target['fields'])})\n")

        # Save full results as JSON
        results_file = os.path.join(self.tool_dir, f'crawl_results_{domain}.json')
        import json
        with open(results_file, 'w') as f:
            json.dump({
                'param_urls': self.param_urls,
                'form_targets': self.form_targets,
                'potential_sqli': self.potential_sqli
            }, f, indent=2)

        success_msg(f"SQLMap targets saved to: {sqlmap_file}")
        success_msg(f"Full crawl results saved to: {results_file}")

        return sqlmap_file
