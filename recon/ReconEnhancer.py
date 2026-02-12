
import os
import json
import time
import warnings
from datetime import datetime
import concurrent.futures
import re
from collections import Counter
from urllib.parse import urlparse

# Suppress InsecureRequestWarning globally at the process level
# This catches warnings from ALL sources (urllib3, requests.packages.urllib3, etc.)
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

# Tool modules
from ReconEnhancerTools.web_scanner import WebScanner
from ReconEnhancerTools.exploit_searcher import EnhancedExploitSearcher
from ReconEnhancerTools.ip_analyzer import IPAnalyzer
from ReconEnhancerTools.ollama_handler import (
    is_ollama_available, interactive_ollama_check,
    analyze_findings_with_ollama, suggest_exploits_with_ollama
)
from ReconEnhancerTools.crawler import SQLiCrawler
from utility import (
    console, section_header, status_msg, success_msg,
    error_msg, warning_msg, info_msg, make_table, get_progress_bar
)

class ReconEnhancer:
    def __init__(self, domain, subdomain_file, nmap_json, ip_input):
        self.domain = domain
        self.subdomain_file = subdomain_file
        self.nmap_json = nmap_json
        self.ip_input = ip_input

        # Setup directories
        self.basedir = f'results/{domain}'
        self.data_dir = f'{self.basedir}/FinalReport'
        self.report_file = f'{self.data_dir}/report.txt'
        self.json_file = f'{self.data_dir}/enhanced.json'

        os.makedirs(self.data_dir, exist_ok=True)

        # Load data
        self.subdomains = self.load_subdomains()
        self.ips = self.load_ips()  # This might be empty if ip_input is not provided
        self.nmap_data = self.load_nmap_json()
        
        # Extract IPs from Nmap data if no IPs loaded
        if not self.ips:
            self.ips = self.extract_ips_from_nmap()

        # Initialize tools
        self.web_scanner = WebScanner(self.data_dir)
        self.exploit_searcher = EnhancedExploitSearcher(self.data_dir)
        self.ip_analyzer = IPAnalyzer(self.data_dir)
        self.crawler = SQLiCrawler(self.data_dir)

        # Ollama integration
        self.use_ollama = False
        self.ollama_model = None

        success_msg(f"Recon Enhancer initialized for {self.domain}")
        info_msg(f"Tools: WebScanner, ExploitSearcher, IPAnalyzer, SQLiCrawler")
        info_msg(f"IPs to analyze: {len(self.ips)}")

    def load_subdomains(self):
        """Load subdomains from file."""
        try:
            if os.path.exists(self.subdomain_file):
                with open(self.subdomain_file, 'r') as f:
                    subdomains = [line.strip() for line in f if line.strip()]
                    success_msg(f"Loaded {len(subdomains)} subdomains")
                    return subdomains
        except Exception as e:
            error_msg(f"Error loading subdomains: {e}")
        return []

    def load_ips(self):
        """Load IPs from input."""
        ips = []
        try:
            # Check if ip_input is a file path
            if isinstance(self.ip_input, str):
                if os.path.exists(self.ip_input):
                    with open(self.ip_input, 'r') as f:
                        ips = [line.strip() for line in f if line.strip()]
                else:
                    # Might be a comma-separated list of IPs
                    if ',' in self.ip_input:
                        ips = [ip.strip() for ip in self.ip_input.split(',') if ip.strip()]
                    else:
                        ips = [self.ip_input.strip()]
            elif isinstance(self.ip_input, list):
                ips = self.ip_input
        except Exception as e:
            error_msg(f"Error loading IPs: {e}")

        info_msg(f"Loaded {len(ips)} IPs from input")
        return ips

    def extract_ips_from_nmap(self):
        """Extract IPs from Nmap data."""
        ips = []
        try:
            if self.nmap_data and 'serviceDiscovery' in self.nmap_data:
                ips = list(self.nmap_data['serviceDiscovery'].keys())
                info_msg(f"Extracted {len(ips)} IPs from Nmap data")
        except Exception as e:
            error_msg(f"Error extracting IPs from Nmap: {e}")
        
        return ips

    def load_nmap_json(self):
        """Load Nmap JSON data."""
        try:
            if os.path.exists(self.nmap_json):
                with open(self.nmap_json, 'r') as f:
                    data = json.load(f)
                    success_msg("Nmap data loaded")
                    if 'serviceDiscovery' in data:
                        ips_with_ports = [ip for ip, hd in data['serviceDiscovery'].items() if hd.get('openPorts')]
                        info_msg(f"IPs with open ports: {len(ips_with_ports)}")
                    return data
        except Exception as e:
            error_msg(f"Error loading Nmap JSON: {e}")
        return {}

    def extract_all_targets(self):
        """Extract all targets from Nmap data AND subdomains."""
        targets = []
        
        if not self.nmap_data:
            warning_msg("No Nmap data available")
            return targets
        
        if 'serviceDiscovery' in self.nmap_data:
            for ip, host_data in self.nmap_data['serviceDiscovery'].items():
                open_ports = host_data.get('openPorts', [])
                
                if not open_ports:
                    # Add IP even if no open ports for analysis
                    targets.append({
                        'type': 'ip_only',
                        'ip': ip,
                        'port': '',
                        'service': 'no_open_ports'
                    })
                    continue
                
                for port_info in open_ports:
                    port = str(port_info.get('port', ''))
                    service = port_info.get('service', '').lower()
                    version = port_info.get('version', '')
                    
                    # Skip tcpwrapped ports (noise reduction for firewalls/Cloudflare)
                    if service == 'tcpwrapped':
                        continue
                    
                    # Web services
                    if service in ['http', 'https', 'http-proxy'] or port in ['80', '443', '8080', '8443', '3000', '5000', '8000']:
                        protocol = 'https' if port == '443' or service == 'https' else 'http'
                        
                        if port in ['80', '443']:
                            url = f"{protocol}://{ip}"
                        else:
                            url = f"{protocol}://{ip}:{port}"
                        
                        targets.append({
                            'type': 'web',
                            'ip': ip,
                            'port': port,
                            'url': url,
                            'service': service,
                            'version': version,
                            'raw_service': port_info.get('service', '')
                        })
                    
                    # Other interesting services
                    elif service in ['ssh', 'ftp', 'mysql', 'postgresql', 'redis', 'telnet',
                                     'smtp', 'smtps', 'dns', 'snmp', 'pop3', 'pop3s',
                                     'imap', 'imaps', 'rdp', 'ms-wbt-server',
                                     'domain', 'tcpwrapped']:
                        targets.append({
                            'type': 'service',
                            'ip': ip,
                            'port': port,
                            'service': service,
                            'version': version,
                            'raw_service': port_info.get('service', '')
                        })
                    
                    # Add all other open ports as generic services
                    elif port:
                        targets.append({
                            'type': 'service',
                            'ip': ip,
                            'port': port,
                            'service': service or 'unknown',
                            'version': version,
                            'raw_service': port_info.get('service', 'unknown')
                        })

        # ── Add subdomains as web targets ──────────────────────────
        # This ensures web scanning even if Nmap didn't find HTTP ports.
        # Subdomains like erp.domain.com, www.domain.com are likely web servers.
        subdomain_urls_added = set()

        # Always add the main domain
        if self.domain:
            for proto in ['http', 'https']:
                url = f"{proto}://{self.domain}"
                if url not in subdomain_urls_added:
                    subdomain_urls_added.add(url)
                    targets.append({
                        'type': 'web',
                        'ip': self.domain,
                        'port': '443' if proto == 'https' else '80',
                        'url': url,
                        'service': proto,
                        'version': '',
                        'raw_service': proto
                    })

        # Add all subdomains as web targets
        for sub in self.subdomains:
            sub = sub.strip()
            if not sub or sub.startswith('_') or sub == self.domain:
                continue  # Skip SRV records like _caldavs._tcp.domain
            for proto in ['http', 'https']:
                url = f"{proto}://{sub}"
                if url not in subdomain_urls_added:
                    subdomain_urls_added.add(url)
                    targets.append({
                        'type': 'web',
                        'ip': sub,
                        'port': '443' if proto == 'https' else '80',
                        'url': url,
                        'service': proto,
                        'version': '',
                        'raw_service': proto
                    })

        if subdomain_urls_added:
            info_msg(f"Added {len(subdomain_urls_added)} web targets from domain + subdomains")

        # ── Remove duplicates & Prioritize HTTPS ───────────────────
        # Group by (host, port) to find collisions
        # If we have http://example.com and https://example.com, prefer https
        
        unique_targets = []
        grouped = {}  # (host, port) -> list of targets
        
        for t in targets:
            # Use netloc (host:port) as key, but treat 80/443 specially for same domain
            parsed = urlparse(t.get('url', ''))
            host = parsed.hostname or t['ip']
            
            # Normalize key: (host, 'web') to group http/https variants
            # This is aggressive: if we see https://example.com, we skip http://example.com
            if t['type'] == 'web':
                key = (host, 'web_service')
            else:
                key = (host, t['port'])
                
            if key not in grouped:
                grouped[key] = []
            grouped[key].append(t)
            
        for key, group in grouped.items():
            if len(group) == 1:
                unique_targets.append(group[0])
            else:
                # Multiple targets for this key - pick best
                # Prefer HTTPS
                https_targets = [t for t in group if t.get('service') == 'https' or t.get('url', '').startswith('https://')]
                if https_targets:
                    # If multiple HTTPS (rare for same host), pick first
                    unique_targets.append(https_targets[0])
                else:
                    # No HTTPS, pick first available
                    unique_targets.append(group[0])

        web_count = len([t for t in unique_targets if t['type'] == 'web'])
        service_count = len([t for t in unique_targets if t['type'] == 'service'])
        ip_only_count = len([t for t in unique_targets if t['type'] == 'ip_only'])

        make_table(
            "Extracted Targets",
            [("Type", "cyan"), ("Count", "green")],
            [("Web", str(web_count)), ("Service", str(service_count)), ("IP-only", str(ip_only_count))]
        )
        
        return unique_targets

    def analyze_open_ports_for_ip(self, ip_address):
        """Analyze open ports for an IP."""
        port_analysis = []
        
        if 'serviceDiscovery' in self.nmap_data:
            if ip_address in self.nmap_data['serviceDiscovery']:
                host_data = self.nmap_data['serviceDiscovery'][ip_address]
                
                open_ports = host_data.get('openPorts', [])
                
                if not open_ports:
                    # Return info about no open ports
                    return [{
                        'port': 'none',
                        'service': 'no_open_ports',
                        'version': '',
                        'state': 'closed_or_filtered',
                        'potential_attacks': ["No open ports detected for scanning"]
                    }]
                
                for port_info in open_ports:
                    port = str(port_info.get('port', ''))
                    service = port_info.get('service', '').lower()
                    version = port_info.get('version', '')
                    state = port_info.get('state', 'open')
                    
                    # Get potential attacks for this service
                    potential_attacks = self.get_potential_attacks(service, port, version)
                    
                    port_analysis.append({
                        'port': port,
                        'service': service,
                        'version': version,
                        'state': state,
                        'potential_attacks': potential_attacks
                    })
        
        return port_analysis

    def get_potential_attacks(self, service, port, version):
        """Get potential attacks for a service."""
        attacks = []
        service_lower = service.lower()
        
        # SSH attacks
        if service_lower == 'ssh' or port == '22':
            attacks = [
                "Brute force attacks (hydra, medusa)",
                "Private key authentication testing",
                "SSH version-specific exploits",
                "SSH tunneling for pivoting",
                "Password spraying with common credentials"
            ]
            if version and 'openssh' in version.lower():
                attacks.append("OpenSSH version-specific vulnerabilities")
        
        # HTTP/HTTPS attacks
        elif service_lower in ['http', 'https', 'http-proxy'] or port in ['80', '443', '8080', '8443']:
            # Reduced noise: don't list generic "potential" checks for standard web ports
            attacks = []
            if 'nginx' in version.lower():
                attacks.append("Nginx-specific misconfigurations")
            elif 'apache' in version.lower():
                attacks.append("Apache module vulnerabilities")
        
        # DNS attacks (port 53)
        elif service_lower == 'dns' or port == '53':
            attacks = [
                "DNS zone transfer attempts",
                "DNS cache poisoning",
                "DNS amplification attacks",
                "DNS tunneling detection",
                "DNS reconnaissance (dig, nslookup)"
            ]
        
        # FTP attacks
        elif service_lower == 'ftp' or port == '21':
            attacks = [
                "Anonymous login attempts",
                "Brute force attacks",
                "FTP bounce attacks",
                "Directory traversal",
                "File upload/download testing"
            ]
            if 'pure-ftpd' in version.lower():
                attacks.append("Pure-FTPd specific vulnerabilities")
        
        # MySQL attacks
        elif service_lower == 'mysql' or port == '3306':
            attacks = [
                "Default credential testing (root:, root:root)",
                "SQL injection via MySQL functions",
                "Database enumeration",
                "Privilege escalation attempts",
                "File read via LOAD_FILE()"
            ]
        
        # Generic service attacks
        else:
            attacks = [
                "Banner grabbing for version detection",
                "Default credential testing",
                "Protocol-specific fuzzing",
                "Service-specific exploit search"
            ]
            if service_lower != 'unknown' and service_lower:
                attacks.append(f"Research {service_lower} specific vulnerabilities")
        
        return attacks

    def scan_web_target(self, target):
        """Scan a single web target."""
        status_msg(f"Scanning web target: {target['url']}")
        
        results = {
            'target': target,
            'technologies': {},
            'directories': [],
            'api_endpoints': [],
            'vulnerabilities': [],
            'exploits': []
        }
        
        # Technology detection
        try:
            tech_data = self.web_scanner.run_whatweb(target['url'])
            results['technologies'] = tech_data
        except Exception as e:
            warning_msg(f"WhatWeb failed: {e}")
        
        # Directory scanning
        try:
            dir_results = self.web_scanner.run_gobuster(target['url'])
            results['directories'] = dir_results[:50]
        except Exception as e:
            warning_msg(f"Gobuster failed: {e}")
        
        # API endpoint discovery
        try:
            api_results = self.web_scanner.check_api_endpoints(target['url'])
            results['api_endpoints'] = api_results[:30]
        except Exception as e:
            warning_msg(f"API check failed: {e}")
        
        # Vulnerability scan
        try:
            vuln_results = self.web_scanner.quick_vuln_scan(target['url'])
            results['vulnerabilities'] = vuln_results
        except Exception as e:
            warning_msg(f"Vulnerability scan failed: {e}")
        
        # Exploit search
        try:
            exploit_results = self.exploit_searcher.search_exploits(
                target.get('raw_service', target['service']),
                target.get('version', ''),
                target['ip'],
                target.get('url', '')
            )
            results['exploits'] = exploit_results[:10]
        except Exception as e:
            warning_msg(f"Exploit search failed: {e}")
        
        return results

    def analyze_service_target(self, target):
        """Analyze a non-web service target."""
        status_msg(f"Analyzing service: {target['ip']}:{target['port']} ({target['service']})")
        
        results = {
            'target': target,
            'exploits': [],
            'potential_attacks': self.get_potential_attacks(
                target['service'],
                target['port'],
                target.get('version', '')
            )
        }
        
        # Exploit search for service
        try:
            exploit_results = self.exploit_searcher.search_exploits(
                target.get('raw_service', target['service']),
                target.get('version', ''),
                target['ip'],
                ''
            )
            results['exploits'] = exploit_results[:10]
        except Exception as e:
            warning_msg(f"Exploit search failed: {e}")
        
        return results

    def analyze_ip_with_ports(self, ip_address):
        """Analyze IP with port information."""
        status_msg(f"Analyzing IP: {ip_address}")
        
        try:
            # Get IP geolocation info
            ip_info = self.ip_analyzer.analyze_ip(ip_address)
            
            # Get open ports analysis
            port_analysis = self.analyze_open_ports_for_ip(ip_address)
            
            return {
                'ip_info': ip_info,
                'port_analysis': port_analysis,
                'open_ports_count': len(port_analysis),
                'services_found': [p['service'] for p in port_analysis if p['service']]
            }
            
        except Exception as e:
            warning_msg(f"IP analysis failed for {ip_address}: {e}")
            return {
                'ip': ip_address,
                'error': str(e),
                'port_analysis': [],
                'open_ports_count': 0
            }

    def write_report_header(self):
        """Write report header."""
        with open(self.report_file, 'w') as f:
            f.write("=" * 100 + "\n")
            f.write("RECONNAISSANCE REPORT\n")
            f.write("=" * 100 + "\n")
            f.write(f"Target Domain: {self.domain}\n")
            f.write(f"Scan Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("\n")

    def write_section_header(self, section_title):
        """Write section header to report."""
        with open(self.report_file, 'a') as f:
            f.write("\n" + "=" * 80 + "\n")
            f.write(f"{section_title.upper()}\n")
            f.write("=" * 80 + "\n\n")

    def write_web_target_results(self, results):
        """Write web target results to report."""
        with open(self.report_file, 'a') as f:
            target = results['target']
            f.write(f"Target: {target['url']} ({target['ip']})\n")
            f.write("-" * 60 + "\n")
            
            # Technologies
            if results['technologies']:
                tech = results['technologies']
                f.write("Technologies:\n")
                if tech.get('server'):
                    f.write(f"  Server: {tech['server']}\n")
                if tech.get('cms'):
                    f.write(f"  CMS: {tech['cms']}\n")
                if tech.get('framework'):
                    f.write(f"  Framework: {tech['framework']}\n")
                if tech.get('language'):
                    f.write(f"  Language: {tech['language']}\n")
                if tech.get('technologies'):
                    f.write(f"  Other: {', '.join(tech['technologies'][:8])}\n")
            
            # Directories
            if results['directories']:
                f.write("\nInteresting Directories:\n")
                interesting_dirs = [d for d in results['directories'] 
                                  if d['classification'] in ['authentication', 'api', 'data_exposure', 'configuration']]
                
                for i, directory in enumerate(interesting_dirs[:8], 1):
                    f.write(f"  {i}. {directory['path']} (Status: {directory['status']}, Type: {directory['classification']})\n")
            
            # API Endpoints
            if results['api_endpoints']:
                f.write("\nAPI Endpoints:\n")
                for i, endpoint in enumerate(results['api_endpoints'][:10], 1):
                    f.write(f"  {i}. {endpoint['endpoint']} (Status: {endpoint['status']}, Info: {endpoint.get('info', '')})\n")
            
            # Vulnerabilities
            if results['vulnerabilities']:
                f.write("\nVulnerabilities:\n")
                for vuln in results['vulnerabilities'][:5]:
                    f.write(f"  [{vuln['severity'].upper()}] {vuln['type'].replace('_', ' ').title()} - {vuln['description']}\n")
            
            # Exploits
            if results['exploits']:
                f.write("\nRelevant Exploits:\n")
                for i, exploit in enumerate(results['exploits'][:5], 1):
                    f.write(f"  {i}. {exploit['title']}\n")
                    f.write(f"     Attack Vector: {exploit['attack_vector'].replace('_', ' ').title()}, Severity: {exploit['severity'].upper()}\n")
                    if exploit.get('payload_hints'):
                        f.write(f"     Payload Hints:\n")
                        for hint in exploit['payload_hints'][:2]:
                            f.write(f"       - {hint}\n")
                    if exploit.get('cve'):
                        f.write(f"     CVE: {exploit['cve']}\n")
            
            f.write("\n")

    def write_service_target_results(self, results):
        """Write service target results to report."""
        with open(self.report_file, 'a') as f:
            target = results['target']
            f.write(f"Service: {target['ip']}:{target['port']} ({target['service']})\n")
            f.write("-" * 60 + "\n")
            
            if target.get('version'):
                f.write(f"Version: {target['version']}\n")
            
            # Potential attacks
            if results.get('potential_attacks'):
                f.write("\nPotential Attack Vectors:\n")
                for i, attack in enumerate(results['potential_attacks'][:5], 1):
                    f.write(f"  {i}. {attack}\n")
            
            # Exploits
            if results['exploits']:
                f.write("\nRelevant Exploits:\n")
                for i, exploit in enumerate(results['exploits'][:5], 1):
                    f.write(f"  {i}. {exploit['title']}\n")
                    f.write(f"     Attack Vector: {exploit['attack_vector'].replace('_', ' ').title()}, Severity: {exploit['severity'].upper()}\n")
                    if exploit.get('payload_hints'):
                        f.write(f"     Payload Hints:\n")
                        for hint in exploit['payload_hints'][:2]:
                            f.write(f"       - {hint}\n")
                    if exploit.get('cve'):
                        f.write(f"     CVE: {exploit['cve']}\n")
            else:
                f.write("\nNo relevant exploits found.\n")
            
            f.write("\n")

    def write_ip_analysis_results(self, ip_data):
        """Write IP analysis results to report."""
        with open(self.report_file, 'a') as f:
            ip_info = ip_data.get('ip_info', {})
            port_analysis = ip_data.get('port_analysis', [])
            
            f.write(f"IP: {ip_info.get('ip', 'Unknown')}\n")
            f.write("-" * 60 + "\n")
            
            # Geolocation
            geo = ip_info.get('geolocation', {})
            if geo:
                location_parts = []
                if geo.get('city'):
                    location_parts.append(geo['city'])
                if geo.get('region'):
                    location_parts.append(geo['region'])
                if geo.get('country'):
                    location_parts.append(geo['country'])
                
                if location_parts:
                    f.write(f"Location: {', '.join(location_parts)}\n")
            
            # Organization/ISP
            asn = ip_info.get('asn_info', {})
            if asn:
                org = asn.get('org') or asn.get('isp', 'Unknown')
                if org != 'Unknown':
                    f.write(f"Organization: {org}")
                    if asn.get('asn'):
                        f.write(f" (ASN: {asn['asn']})")
                    f.write("\n")
            
            # Open Ports Analysis
            if port_analysis:
                f.write("\nOpen Ports Analysis:\n")
                f.write(f"  Total Open Ports: {len(port_analysis)}\n")
                
                for port_info in port_analysis[:10]:
                    if port_info['port'] == 'none':
                        f.write(f"  No open ports detected\n")
                        if port_info['potential_attacks']:
                            f.write(f"    Note: {port_info['potential_attacks'][0]}\n")
                    else:
                        f.write(f"  Port {port_info['port']}: {port_info['service']} ({port_info['version'] if port_info['version'] else 'no version'})\n")
                        
                        if port_info['potential_attacks']:
                            f.write(f"    Potential Attacks:\n")
                            for i, attack in enumerate(port_info['potential_attacks'][:3], 1):
                                f.write(f"      {i}. {attack}\n")
            
            # Threat Indicators
            threats = ip_info.get('threat_intelligence', {})
            if threats.get('indicators'):
                f.write("\nThreat Indicators:\n")
                for indicator in threats['indicators']:
                    f.write(f"  - {indicator}\n")
            
            f.write("\n")

    def run_comprehensive_scan(self):
        """Run comprehensive reconnaissance scan with Ollama & Crawler integration."""
        section_header(f"COMPREHENSIVE SCAN -- {self.domain}")
        
        start_time = time.time()
        
        # Initialize report
        self.write_report_header()
        
        all_results = {
            'domain': self.domain,
            'timestamp': datetime.now().isoformat(),
            'subdomains_count': len(self.subdomains),
            'ips_count': len(self.ips),
            'web_targets': [],
            'service_targets': [],
            'ip_analyses': [],
            'summary': {}
        }
        
        # 1. Extract all targets
        section_header("Step 1/7 -- Extracting Targets")
        targets = self.extract_all_targets()
        
        web_targets = [t for t in targets if t['type'] == 'web']
        service_targets = [t for t in targets if t['type'] == 'service']
        
        all_results['web_targets_count'] = len(web_targets)
        all_results['service_targets_count'] = len(service_targets)
        
        # 2. Scan web targets (parallelized for speed)
        if web_targets:
            section_header(f"Step 2/7 -- Scanning {len(web_targets)} Web Targets")
            self.write_section_header("WEB TARGETS")
            
            with get_progress_bar() as progress:
                task_id = progress.add_task("Web scan", total=len(web_targets))
                with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                    future_to_target = {executor.submit(self.scan_web_target, t): t for t in web_targets}
                    for future in concurrent.futures.as_completed(future_to_target):
                        target = future_to_target[future]
                        try:
                            result = future.result()
                            self.write_web_target_results(result)
                            all_results['web_targets'].append(result)
                        except Exception as e:
                            error_msg(f"Failed: {target['url']}: {e}")
                        progress.update(task_id, advance=1)
        else:
            self.write_section_header("WEB TARGETS")
            with open(self.report_file, 'a') as f:
                f.write("No web targets found for scanning.\n")
        
        # 3. Analyze service targets
        if service_targets:
            section_header(f"Step 3/7 -- Analyzing {len(service_targets)} Services")
            self.write_section_header("SERVICE TARGETS")
            
            with get_progress_bar() as progress:
                task_id = progress.add_task("Service scan", total=len(service_targets))
                with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
                    future_to_target = {executor.submit(self.analyze_service_target, t): t for t in service_targets}
                    for future in concurrent.futures.as_completed(future_to_target):
                        target = future_to_target[future]
                        try:
                            result = future.result()
                            self.write_service_target_results(result)
                            all_results['service_targets'].append(result)
                        except Exception as e:
                            error_msg(f"Failed: {target['ip']}:{target['port']}: {e}")
                        progress.update(task_id, advance=1)
        else:
            self.write_section_header("SERVICE TARGETS")
            with open(self.report_file, 'a') as f:
                f.write("No service targets found for scanning.\n")
        
        # 4. Analyze IP addresses
        section_header(f"Step 4/7 -- Analyzing {len(self.ips)} IPs")
        self.write_section_header("IP ANALYSIS")
        
        ip_analyses = []
        if self.ips:
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
                future_to_ip = {executor.submit(self.analyze_ip_with_ports, ip): ip for ip in self.ips}
                for future in concurrent.futures.as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    try:
                        ip_data = future.result()
                        ip_analyses.append(ip_data)
                        self.write_ip_analysis_results(ip_data)
                    except Exception as e:
                        error_msg(f"Failed for {ip}: {e}")
        else:
            with open(self.report_file, 'a') as f:
                f.write("No IP addresses available for analysis.\n")
        
        all_results['ip_analyses'] = ip_analyses

        # 5. Crawler -- Find SQLi targets on web services
        section_header("Step 5/7 -- Crawling for SQLi Targets")
        all_results['crawler'] = {}
        if web_targets:
            try:
                # Smart crawl: crawl by domain URL, not by IP.
                # Multiple IPs often serve the same site, so crawling each IP
                # would just re-discover the same pages and parameters.
                seen_crawl_domains = set()
                crawl_targets = []
                for target in web_targets:
                    url = target['url']
                    parsed = urlparse(url)
                    # Use netloc (host) as dedup key — skip if already crawling same host
                    if parsed.netloc not in seen_crawl_domains:
                        seen_crawl_domains.add(parsed.netloc)
                        crawl_targets.append(url)

                # Also add the main domain if not already covered
                if self.domain:
                    for proto in ['http', 'https']:
                        d_url = f"{proto}://{self.domain}"
                        d_parsed = urlparse(d_url)
                        if d_parsed.netloc not in seen_crawl_domains:
                            seen_crawl_domains.add(d_parsed.netloc)
                            crawl_targets.append(d_url)

                info_msg(f"Crawling {len(crawl_targets)} unique hosts (deduplicated from {len(web_targets)} targets)")

                for url in crawl_targets[:8]:  # Cap at 8 unique hosts
                    crawl_data = self.crawler.crawl(url)
                    all_results['crawler'][url] = crawl_data
                self.crawler.save_results(self.domain)
                
                total_sqli = sum(
                    len(c.get('potential_sqli', [])) for c in all_results['crawler'].values()
                )
                if total_sqli > 0:
                    success_msg(f"Found {total_sqli} potential SQLi targets")
                    self.write_section_header("SQL INJECTION TARGETS")
                    with open(self.report_file, 'a') as f:
                        for url, data in all_results['crawler'].items():
                            for sqli in data.get('potential_sqli', []):
                                f.write(f"  [{sqli['sqli_score']}] {sqli['url']}\n")
                                f.write(f"       Params: {', '.join(sqli.get('params', sqli.get('fields', [])))}\n")
                else:
                    info_msg("No SQL injection targets identified")
            except Exception as e:
                warning_msg(f"Crawler error: {e}")
        else:
            info_msg("No web targets to crawl")

        # 6. Ollama AI Analysis
        section_header("Step 6/7 -- AI-Powered Analysis")
        all_results['ollama_analysis'] = None
        if self.use_ollama and self.ollama_model:
            try:
                status_msg(f"Sending findings to Ollama ({self.ollama_model})...")
                analysis = analyze_findings_with_ollama(
                    all_results, model=self.ollama_model
                )
                if analysis:
                    all_results['ollama_analysis'] = analysis
                    success_msg("AI analysis complete")
                    
                    self.write_section_header("AI-POWERED ANALYSIS (OLLAMA)")
                    with open(self.report_file, 'a') as f:
                        f.write(analysis + "\n")
                    
                    # Also try per-service exploit suggestions
                    svc_targets = service_targets[:5]
                    for idx, target in enumerate(svc_targets, 1):
                        status_msg(f"Generating exploit suggestions [{idx}/{len(svc_targets)}]: {target['service']} on {target['ip']}...")
                        suggestion = suggest_exploits_with_ollama(
                            target['service'],
                            target.get('version', ''),
                            [t['port'] for t in service_targets if t['ip'] == target['ip']],
                            model=self.ollama_model
                        )
                        if suggestion:
                            with open(self.report_file, 'a') as f:
                                f.write(f"\n--- Exploit Suggestions for {target['service']} on {target['ip']} ---\n")
                                f.write(suggestion + "\n")
                            success_msg(f"Suggestions complete for {target['service']}")
            except Exception as e:
                warning_msg(f"Ollama analysis failed: {e}")
        else:
            info_msg("Ollama not enabled -- skipping AI analysis")
        
        # 7. Generate comprehensive summary
        section_header("Step 7/7 -- Generating Summary")
        elapsed = time.time() - start_time
        
        self.write_section_header("SCAN SUMMARY")
        
        # Count stats
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        total_vulns = 0
        for web_result in all_results.get('web_targets', []):
            for vuln in web_result.get('vulnerabilities', []):
                sev = vuln.get('severity', 'low').lower()
                if sev in severity_counts:
                    severity_counts[sev] += 1
                    total_vulns += 1
        
        exploit_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        total_exploits = 0
        for src in ['web_targets', 'service_targets']:
            for result in all_results.get(src, []):
                for exploit in result.get('exploits', []):
                    sev = exploit.get('severity', 'low').lower()
                    if sev in exploit_counts:
                        exploit_counts[sev] += 1
                        total_exploits += 1
        
        total_open_ports = sum(ip_data.get('open_ports_count', 0) for ip_data in ip_analyses)
        
        all_services = []
        for ip_data in ip_analyses:
            all_services.extend(ip_data.get('services_found', []))
        service_counter = Counter(all_services)
        
        # Write summary to report file
        with open(self.report_file, 'a') as f:
            f.write(f"Scan Duration: {elapsed:.1f} seconds\n")
            f.write(f"Total Targets: {len(targets)}\n")
            f.write(f"  Web: {len(web_targets)}, Service: {len(service_targets)}, IPs: {len(self.ips)}\n")
            f.write(f"Vulnerabilities: {total_vulns}\n")
            f.write(f"Exploits: {total_exploits}\n")
            f.write(f"Open Ports: {total_open_ports}\n")
            if service_counter:
                f.write("Common Services: " + ", ".join(f"{s}({c})" for s, c in service_counter.most_common(5)) + "\n")
            f.write(f"\nOutput: {self.data_dir}/\n")
        
        # Save JSON
        with open(self.json_file, 'w') as f:
            json.dump(all_results, f, indent=2)
        
        # Beautiful console summary
        summary_rows = [
            ("Duration", f"{elapsed:.1f}s"),
            ("Web Targets", str(len(web_targets))),
            ("Service Targets", str(len(service_targets))),
            ("IPs Analyzed", str(len(self.ips))),
            ("Open Ports", str(total_open_ports)),
            ("Vulnerabilities", str(total_vulns)),
            ("Exploits Found", str(total_exploits)),
            ("Ollama Analysis", "Yes" if all_results.get('ollama_analysis') else "No"),
        ]
        make_table(
            "SCAN COMPLETE",
            [("Metric", "cyan"), ("Value", "green")],
            summary_rows
        )
        success_msg(f"Results saved to: {self.data_dir}")
        
        return all_results


def main(domain, subdomain_file, nmap_json, ip_input):
    """Main function with Ollama integration."""
    section_header("RECON ENHANCER v2.0")
    info_msg(f"Target: {domain}")
    
    # Check required files
    for file_path in [subdomain_file, nmap_json]:
        if not os.path.exists(file_path):
            error_msg(f"File not found: {file_path}")
            return None
    
    # Create enhancer
    enhancer = ReconEnhancer(domain, subdomain_file, nmap_json, ip_input)
    
    # Check Ollama availability
    use_ollama, model = interactive_ollama_check()
    enhancer.use_ollama = use_ollama
    enhancer.ollama_model = model
    
    # Run comprehensive scan
    results = enhancer.run_comprehensive_scan()
    
    return results


