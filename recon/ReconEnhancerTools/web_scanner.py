
import os
import subprocess
import requests
import re
from urllib.parse import urlparse
import concurrent.futures
import time

class WebScanner:
    def __init__(self, data_dir):
        self.data_dir = data_dir
        self.tool_dirs = {}
        self.setup_tool_dirs()
        
        # Common paths 
        # REally unoptimized
        self.common_paths = [
            # API endpoints
            '/api', '/api/v1', '/api/v2', '/api/v3', '/graphql', '/rest', '/soap',
            '/json', '/xml', '/admin/api', '/wp-json', '/swagger', '/swagger-ui',
            '/openapi', '/docs', '/redoc', '/v1', '/v2', '/v3',
            
            # Admin interfaces
            '/admin', '/administrator', '/wp-admin', '/wp-login', '/login', '/signin',
            '/dashboard', '/cp', '/controlpanel', '/manager', '/manage',
            
            # Configuration files
            '/config', '/configuration', '/settings', '/setup', '/install',
            '/update', '/upgrade', '/backup', '/backups', '/dump', '/sql',
            
            # Development files
            '/test', '/testing', '/dev', '/development', '/staging', '/stage',
            '/debug', '/console', '/shell', '/terminal',
            
            # Common directories
            '/uploads', '/downloads', '/files', '/assets', '/static', '/media',
            '/images', '/img', '/css', '/js', '/scripts', '/styles',
            
            # Authentication
            '/auth', '/oauth', '/oauth2', '/sso', '/account', '/user', '/users',
            '/profile', '/register', '/signup', '/logout',
            
            # Database/admin
            '/phpmyadmin', '/adminer', '/db', '/database', '/mysql', '/pgsql',
            '/mongodb', '/redis', '/memcache',
            
            # Monitoring/logs
            '/status', '/health', '/ping', '/metrics', '/monitor', '/logs',
            '/log', '/access.log', '/error.log',
            
            # Framework specific
            '/laravel', '/symfony', '/django', '/flask', '/rails', '/spring',
            '/wordpress', '/joomla', '/drupal', '/magento'
        ]
    # Folder setup
    def setup_tool_dirs(self):
        tools = ['gobuster', 'whatweb', 'nikto', 'api_checks', 'vuln_scans']
        for tool in tools:
            tool_dir = os.path.join(self.data_dir, tool)
            os.makedirs(tool_dir, exist_ok=True)
            self.tool_dirs[tool] = tool_dir
    
    def get_safe_filename(self, url):
        safe = url.replace('://', '_').replace(':', '_').replace('/', '_') # clearning 
        safe = re.sub(r'[^a-zA-Z0-9._-]', '', safe)
        return safe[:100]  # Limit length

    # Wordlists that comes with tools needs more work
    def check_wordlists(self):
        wordlists = {
            'common': '/usr/share/wordlists/dirb/common.txt',
            'small': '/usr/share/wordlists/dirb/small.txt',
            'big': '/usr/share/wordlists/dirb/big.txt',
            'medium': '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt',
            'apache': '/usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt',
            'quick': '/usr/share/seclists/Discovery/Web-Content/quick.txt',
            'common_dirs': '/usr/share/seclists/Discovery/Web-Content/common.txt'
        }
        
        available = {}
        for name, path in wordlists.items():
            if os.path.exists(path):
                available[name] = path
        
        if not available:
            # Create minimal wordlist fall back if doesn't exsists
            minimal = ['admin', 'api', 'login', 'test', 'backup', 'config', 'wp-admin']
            minimal_path = '/tmp/minimal_wordlist.txt'
            with open(minimal_path, 'w') as f:
                f.write('\n'.join(minimal))
            available['minimal'] = minimal_path
        
        return available

    # RUn OG gobuster
    def run_gobuster(self, url, timeout=90):
        wordlists = self.check_wordlists()
        if not wordlists:
            return []
        
        safe_name = self.get_safe_filename(url)
        output_files = []
        results = []
        
        # Try different wordlists
        for wl_name, wl_path in wordlists.items():
            if len(results) > 100:  # Stop if we have enough results
                break
            
            output_file = os.path.join(self.tool_dirs['gobuster'], 
                                      f"gobuster_{safe_name}_{wl_name}.txt")
            output_files.append(output_file)
            
            cmd = f"gobuster dir -u {url} -w {wl_path} -t 20 -q -o {output_file}"
            
            try:
                subprocess.run(
                    cmd,
                    shell=True,
                    timeout=timeout/len(wordlists),  # Divide timeout among wordlists
                    capture_output=True,
                    text=True
                )
                
                # Parse results
                if os.path.exists(output_file):
                    with open(output_file, 'r') as f:
                        for line in f:
                            if 'Status:' in line:
                                parts = line.strip().split()
                                if len(parts) >= 3:
                                    path = parts[0]
                                    status = parts[2]
                                    
                                    # Classify finding
                                    classification = self.classify_path(path)
                                    
                                    results.append({
                                        'path': path,
                                        'status': status,
                                        'classification': classification,
                                        'wordlist': wl_name
                                    })
                
            except (subprocess.TimeoutExpired, Exception):
                continue
        
        return results[:200]  # Return top 200 results
    
    def classify_path(self, path):
        path_lower = path.lower()
        
        if any(word in path_lower for word in ['admin', 'login', 'auth', 'dashboard', 'control']):
            return 'authentication'
        elif any(word in path_lower for word in ['api', 'rest', 'graphql', 'soap', 'json']):
            return 'api'
        elif any(word in path_lower for word in ['backup', 'dump', 'sql', 'database', '.sql']):
            return 'data_exposure'
        elif any(word in path_lower for word in ['config', 'setup', 'install', 'update', '.env']):
            return 'configuration'
        elif any(word in path_lower for word in ['test', 'dev', 'debug', 'console', 'shell']):
            return 'development'
        elif any(word in path_lower for word in ['upload', 'file', 'image', 'media']):
            return 'file_upload'
        else:
            return 'general'

    # Whatweb
    def run_whatweb(self, url, timeout=30):
        safe_name = self.get_safe_filename(url)
        output_file = os.path.join(self.tool_dirs['whatweb'], 
                                  f"whatweb_{safe_name}.txt")
        
        cmd = f"whatweb {url} --color=never -a 3 --log-verbose={output_file}"
        
        try:
            subprocess.run(
                cmd,
                shell=True,
                timeout=timeout,
                capture_output=True,
                text=True
            )
            
            # Parse results
            tech_data = self.parse_whatweb_output(output_file, url)
            return tech_data
            
        except Exception as e:
            print(f"[!] WhatWeb error: {e}")
        
        return {'url': url, 'technologies': []}
    
    def parse_whatweb_output(self, output_file, url):
        """Parse whatweb output file."""
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
            
            # Parse technologies
            lines = content.split('\n')
            for line in lines:
                if ']' in line and '[' in line:
                    tech_match = re.search(r'\[(.*?)\]', line)
                    if tech_match:
                        techs = [t.strip() for t in tech_match.group(1).split(',')]
                        for tech in techs:
                            if tech and tech not in tech_data['technologies']:
                                tech_data['technologies'].append(tech)
                                
                                # Classify technology
                                tech_lower = tech.lower()
                                if any(word in tech_lower for word in ['nginx', 'apache', 'iis', 'lighttpd', 'server']):
                                    tech_data['server'] = tech
                                elif any(word in tech_lower for word in ['wordpress', 'joomla', 'drupal', 'magento']):
                                    tech_data['cms'] = tech
                                elif any(word in tech_lower for word in ['laravel', 'django', 'flask', 'rails', 'spring']):
                                    tech_data['framework'] = tech
                                elif any(word in tech_lower for word in ['php', 'python', 'ruby', 'java', 'node.js']):
                                    tech_data['language'] = tech
                
                # Parse detailed information
                if ':' in line and '[' not in line:
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        key = parts[0].strip()
                        value = parts[1].strip()
                        tech_data['details'][key] = value
            
        except Exception as e:
            print(f"[!] Error parsing WhatWeb output: {e}")
        
        return tech_data
    # API ENDPOINTS
    def check_api_endpoints(self, url, timeout=3):
        safe_name = self.get_safe_filename(url)
        output_file = os.path.join(self.tool_dirs['api_checks'], 
                                  f"api_{safe_name}.txt")
        
        endpoints = []
        checked_paths = set()
        
        # Check common paths in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            futures = []
            for path in self.common_paths:
                full_url = url.rstrip('/') + path
                if full_url not in checked_paths:
                    checked_paths.add(full_url)
                    futures.append(executor.submit(
                        self.check_single_endpoint, 
                        url, path, timeout
                    ))
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result(timeout=timeout+1)
                    if result:
                        endpoints.append(result)
                except:
                    continue
        
        # Save results to file
        with open(output_file, 'w') as f:
            for endpoint in endpoints[:100]:  # Save top 100
                f.write(f"{endpoint['status']} | {endpoint['endpoint']} | {endpoint['info']}\n")
        
        return endpoints[:100]
    
    def check_single_endpoint(self, base_url, path, timeout):
        full_url = base_url.rstrip('/') + path
        
        try:
            response = requests.get(
                full_url,
                timeout=timeout,
                verify=False,
                allow_redirects=False,
                headers={'User-Agent': 'Mozilla/5.0'}
            )
            
            info = ""
            content_type = response.headers.get('Content-Type', '').lower()
            
            # Analyze response
            if response.status_code < 400:
                if 'json' in content_type:
                    info = "JSON API endpoint"
                elif 'admin' in path.lower() or 'login' in path.lower():
                    info = "Admin interface"
                elif response.status_code in [301, 302]:
                    info = f"Redirects to: {response.headers.get('Location', '')}"
                elif len(response.text) > 10000:
                    info = "Large response (possible data)"
                else:
                    info = "Accessible endpoint"
            
            return {
                'endpoint': path,
                'url': full_url,
                'status': response.status_code,
                'length': len(response.text),
                'content_type': content_type,
                'info': info,
                'redirect': response.headers.get('Location', '') if response.status_code in [301, 302] else ''
            }
            
        except Exception:
            return None
    # Vuln chcking through requests and common vulnrable directory
    def quick_vuln_scan(self, url, timeout=45):
        safe_name = self.get_safe_filename(url)
        output_file = os.path.join(self.tool_dirs['vuln_scans'], 
                                  f"vuln_{safe_name}.txt")
        
        findings = []
        
        # Quick checks really unoptimized
        checks = [
           # --- 1. Version Control & Dev Exposure (CRITICAL) ---
                ("Git Config", "/.git/config"),
                ("Git Index", "/.git/index"),
                ("Git Pack", "/.git/objects/pack/"),
                ("SVN Config", "/.svn/all-wcprops"),
                ("Mercurial repo", "/.hg/"),
                ("Bazaar repo", "/.bzr/"),
                ("Docker Compose", "/docker-compose.yml"),
                ("Dockerfile", "/Dockerfile"),
            
                # --- 2. Configuration & Secrets (CRITICAL) ---
                ("Environment Backup", "/.env.bak"),
                ("Environment Example", "/.env.example"),
                ("Environment Production", "/.env.production"),
                ("Node Modules Log", "/npm-debug.log"),
                ("Yarn Lock", "/yarn.lock"),
                ("Web Config", "/web.config"),
                ("PHP Config", "/php.ini"),
                ("Apache Info", "/.htpasswd"),
                ("Nginx Config", "/nginx.conf"),
                ("Terraform State", "/terraform.tfstate"),
            
                # --- 3. Database & Backups (HIGH) ---
                ("SQL Dump", "/dump.sql"),
                ("DB Backup", "/db.sql.gz"),
                ("Postgres Log", "/postgresql.log"),
                ("Mongo Export", "/mongo.json"),
                ("SQLite DB", "/database.sqlite"),
                ("Config Backup", "/config.php.bak"),
                ("Zip Backup", "/backup.zip"),
                ("Tarball Backup", "/site.tar.gz"),
                ("Old Files", "/old/"),
            
                # --- 4. Cloud & Infrastructure (HIGH) ---
                ("AWS Credentials", "/.aws/credentials"),
                ("AWS Config", "/.aws/config"),
                ("S3 Config", "/.s3cfg"),
                ("GCreds", "/.gcat/"),
                ("Kube Config", "/.kube/config"),
                ("Azure CLI", "/.azure/accessTokens.json"),
            
                # --- 5. Framework Specific (MEDIUM) ---
                ("Laravel Log", "/storage/logs/laravel.log"),
                ("Symfony Profiler", "/_profiler/phpinfo"),
                ("Django Settings", "/settings.py"),
                ("Rails Routes", "/rails/info/routes"),
                ("Spring Boot Info", "/actuator/info"),
                ("Spring Boot Health", "/actuator/health"),
                ("Spring Boot Env", "/actuator/env"),
                ("Spring Boot Heap", "/actuator/heapdump"),
                ("WordPress Config", "/wp-config.php.txt"),
                ("Drupal Services", "/sites/default/services.yml"),
            
                # --- 6. API & Documentation (MEDIUM) ---
                ("Swagger UI", "/swagger-ui.html"),
                ("Swagger JSON", "/swagger.json"),
                ("OpenAPI Spec", "/openapi.json"),
                ("GraphQL Playground", "/graphql"),
                ("Apollo Sandbox", "/_sandbox"),
                ("WSDL File", "/service.wsdl"),
            
                # --- 7. Security & Logs (LOW/INFO) ---
                ("Security.txt", "/.well-known/security.txt"),
                ("Robots.txt", "/robots.txt"),
                ("Sitemap", "/sitemap.xml"),
                ("Audit Log", "/audit.log"),
                ("Error Log", "/error_log"),
                ("MySQL History", "/.mysql_history"),
                ("Bash History", "/.bash_history"),
                ("SSH Public Key", "/.ssh/id_rsa.pub"),
            
                # --- 8. Java/JS/Misc (MEDIUM) ---
                ("Web XML", "/WEB-INF/web.xml"),
                ("Pom XML", "/pom.xml"),
                ("Package.json", "/package.json"),
                ("Bower.json", "/bower.json"),
                ("Composer JSON", "/composer.json"),
                ("Heap Dump", "/heapdump"),
                ("Core Dump", "/core"),
                ("Crossdomain XML", "/crossdomain.xml"),
                ("Client Access XML", "/clientaccesspolicy.xml"),
            
                # --- 9. Common Installers/Tools ---
                ("PHPMyAdmin", "/phpmyadmin/setup/index.php"),
                ("Adminer", "/adminer.php"),
                ("CPanel Log", "/.cpanel/logs"),
                ("Magento Release", "/RELEASE_NOTES.txt"),
                ("Joomla Config", "/configuration.php-dist")
        ]
        
        with open(output_file, 'w') as f:
            f.write(f"Quick Vulnerability Scan for: {url}\n")
            f.write("=" * 60 + "\n\n")
            
            for check_name, path in checks:
                full_url = url + path
                try:
                    response = requests.get(
                        full_url,
                        timeout=2,
                        verify=False,
                        allow_redirects=False
                    )
                    
                    if response.status_code == 200:
                        severity = "low"
                        if '.git' in path or '.env' in path:
                            severity = "high"
                        elif 'config' in path or 'backup' in path:
                            severity = "medium"
                        
                        findings.append({
                            'type': check_name.lower().replace(' ', '_'),
                            'path': path,
                            'severity': severity,
                            'description': f"{check_name} exposed at {path}"
                        })
                        
                        f.write(f"[{severity.upper()}] {check_name}: {full_url}\n")
                        
                except:
                    continue
            
            # Check security headers
            try:
                response = requests.head(url, timeout=3, verify=False)
                headers = response.headers
                
                f.write("\nSecurity Headers Analysis:\n")
                security_checks = {
                    'X-Frame-Options': 'Missing clickjacking protection',
                    'X-Content-Type-Options': 'Missing MIME sniffing protection',
                    'X-XSS-Protection': 'Missing XSS protection',
                    'Content-Security-Policy': 'Missing CSP header',
                    'Strict-Transport-Security': 'Missing HSTS header'
                }
                
                missing = []
                for header, message in security_checks.items():
                    if header not in headers:
                        missing.append(message)
                        f.write(f"[-] {message}\n")
                
                if missing:
                    findings.append({
                        'type': 'missing_security_headers',
                        'severity': 'low',
                        'description': 'Missing security headers',
                        'details': missing
                    })
                else:
                    f.write("[+] All security headers present\n")
                    
            except:
                f.write("[!] Could not check security headers\n")
        
        return findings
