
import os
import json
import time
from datetime import datetime
import concurrent.futures
import re  # Added import
from collections import Counter

# Tool modules
from ReconEnhancerTools.web_scanner import WebScanner
from ReconEnhancerTools.exploit_searcher import EnhancedExploitSearcher
from ReconEnhancerTools.ip_analyzer import IPAnalyzer

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

        print(f"[+] Recon Enhancer initialized for {self.domain}")
        print(f"[+] Tools loaded: WebScanner, EnhancedExploitSearcher, IPAnalyzer")
        print(f"[+] IPs to analyze: {len(self.ips)}")

    def load_subdomains(self):
        """Load subdomains from file."""
        try:
            if os.path.exists(self.subdomain_file):
                with open(self.subdomain_file, 'r') as f:
                    subdomains = [line.strip() for line in f if line.strip()]
                    print(f"[+] Loaded {len(subdomains)} subdomains")
                    return subdomains
        except Exception as e:
            print(f"[!] Error loading subdomains: {e}")
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
            print(f"[!] Error loading IPs: {e}")

        print(f"[+] Loaded {len(ips)} IPs from input")
        return ips

    def extract_ips_from_nmap(self):
        """Extract IPs from Nmap data."""
        ips = []
        try:
            if self.nmap_data and 'serviceDiscovery' in self.nmap_data:
                ips = list(self.nmap_data['serviceDiscovery'].keys())
                print(f"[+] Extracted {len(ips)} IPs from Nmap data")
        except Exception as e:
            print(f"[!] Error extracting IPs from Nmap: {e}")
        
        return ips

    def load_nmap_json(self):
        """Load Nmap JSON data."""
        try:
            if os.path.exists(self.nmap_json):
                with open(self.nmap_json, 'r') as f:
                    data = json.load(f)
                    print("[+] Nmap data loaded successfully")
                    
                    # Debug: Show IPs with open ports
                    if 'serviceDiscovery' in data:
                        ips_with_ports = []
                        for ip, host_data in data['serviceDiscovery'].items():
                            open_ports = host_data.get('openPorts', [])
                            if open_ports:
                                ips_with_ports.append(ip)
                        print(f"[+] IPs with open ports: {len(ips_with_ports)}")
                        if ips_with_ports:
                            print(f"[+] Example: {ips_with_ports[:3]}")
                    
                    return data
        except Exception as e:
            print(f"[!] Error loading Nmap JSON: {e}")
        return {}

    def extract_all_targets(self):
        """Extract all targets from Nmap data."""
        targets = []
        
        if not self.nmap_data:
            print("[!] No Nmap data available")
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
                    elif service in ['ssh', 'ftp', 'mysql', 'postgresql', 'redis', 'telnet', 'smtp', 'dns', 'snmp']:
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

        # Remove duplicates
        unique_targets = []
        seen = set()
        
        for target in targets:
            key = (target['ip'], target['port'], target.get('url', ''))
            if key not in seen:
                seen.add(key)
                unique_targets.append(target)

        print(f"[+] Extracted {len(unique_targets)} unique targets")
        
        # Show breakdown
        web_count = len([t for t in unique_targets if t['type'] == 'web'])
        service_count = len([t for t in unique_targets if t['type'] == 'service'])
        ip_only_count = len([t for t in unique_targets if t['type'] == 'ip_only'])
        
        print(f"[+] Breakdown: {web_count} web, {service_count} service, {ip_only_count} IP-only targets")
        
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
            attacks = [
                "Directory brute-forcing (gobuster, dirb)",
                "SQL injection testing",
                "XSS payload testing",
                "File upload vulnerabilities",
                "Authentication bypass attempts",
                "API endpoint discovery",
                "Technology fingerprinting"
            ]
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
        print(f"  Scanning web target: {target['url']}")
        
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
            print(f"    [!] WhatWeb failed: {e}")
        
        # Directory scanning
        try:
            dir_results = self.web_scanner.run_gobuster(target['url'])
            results['directories'] = dir_results[:50]
        except Exception as e:
            print(f"    [!] Gobuster failed: {e}")
        
        # API endpoint discovery
        try:
            api_results = self.web_scanner.check_api_endpoints(target['url'])
            results['api_endpoints'] = api_results[:30]
        except Exception as e:
            print(f"    [!] API check failed: {e}")
        
        # Vulnerability scan
        try:
            vuln_results = self.web_scanner.quick_vuln_scan(target['url'])
            results['vulnerabilities'] = vuln_results
        except Exception as e:
            print(f"    [!] Vulnerability scan failed: {e}")
        
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
            print(f"    [!] Exploit search failed: {e}")
        
        return results

    def analyze_service_target(self, target):
        """Analyze a non-web service target."""
        print(f"  Analyzing service: {target['ip']}:{target['port']} ({target['service']})")
        
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
            print(f"    [!] Exploit search failed: {e}")
        
        return results

    def analyze_ip_with_ports(self, ip_address):
        """Analyze IP with port information."""
        print(f"  Analyzing IP with ports: {ip_address}")
        
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
            print(f"    [!] IP analysis failed: {e}")
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
        """Run comprehensive reconnaissance scan."""
        print("\n" + "=" * 100)
        print(f"COMPREHENSIVE RECONNAISSANCE SCAN - {self.domain}")
        print("=" * 100)
        
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
        print("\n[1/5] Extracting targets from Nmap data...")
        targets = self.extract_all_targets()
        
        web_targets = [t for t in targets if t['type'] == 'web']
        service_targets = [t for t in targets if t['type'] == 'service']
        
        all_results['web_targets_count'] = len(web_targets)
        all_results['service_targets_count'] = len(service_targets)
        
        print(f"  Found {len(web_targets)} web targets")
        print(f"  Found {len(service_targets)} service targets")
        
        # 2. Scan web targets
        if web_targets:
            print(f"\n[2/5] Scanning {len(web_targets)} web targets...")
            
            self.write_section_header("WEB TARGETS")
            
            for i, target in enumerate(web_targets, 1):
                print(f"  [{i}/{len(web_targets)}] {target['url']}")
                
                try:
                    result = self.scan_web_target(target)
                    
                    # Write to report
                    self.write_web_target_results(result)
                    
                    # Add to all results
                    all_results['web_targets'].append(result)
                    
                except Exception as e:
                    print(f"    [!] Failed: {e}")
        else:
            self.write_section_header("WEB TARGETS")
            with open(self.report_file, 'a') as f:
                f.write("No web targets found for scanning.\n")
        
        # 3. Analyze service targets
        if service_targets:
            print(f"\n[3/5] Analyzing {len(service_targets)} service targets...")
            
            self.write_section_header("SERVICE TARGETS")
            
            for i, target in enumerate(service_targets, 1):
                print(f"  [{i}/{len(service_targets)}] {target['ip']}:{target['port']} ({target['service']})")
                
                try:
                    result = self.analyze_service_target(target)
                    
                    # Write to report
                    self.write_service_target_results(result)
                    
                    # Add to all results
                    all_results['service_targets'].append(result)
                    
                except Exception as e:
                    print(f"    [!] Failed: {e}")
        else:
            self.write_section_header("SERVICE TARGETS")
            with open(self.report_file, 'a') as f:
                f.write("No service targets found for scanning.\n")
        
        # 4. Analyze IP addresses with open ports
        print(f"\n[4/5] Analyzing {len(self.ips)} IP addresses with open ports...")
        
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
                        
                        # Write to report
                        self.write_ip_analysis_results(ip_data)
                        
                    except Exception as e:
                        print(f"    [!] Failed for {ip}: {e}")
        else:
            with open(self.report_file, 'a') as f:
                f.write("No IP addresses available for analysis.\n")
        
        all_results['ip_analyses'] = ip_analyses
        
        # 5. Generate comprehensive summary
        elapsed = time.time() - start_time
        
        self.write_section_header("SCAN SUMMARY")
        
        with open(self.report_file, 'a') as f:
            f.write(f"Scan Duration: {elapsed:.1f} seconds\n")
            f.write(f"Total Targets Analyzed: {len(targets)}\n")
            f.write(f"  - Web Targets: {len(web_targets)}\n")
            f.write(f"  - Service Targets: {len(service_targets)}\n")
            f.write(f"  - IP Addresses: {len(self.ips)}\n")
            
            # Count vulnerabilities by severity
            severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            total_vulns = 0
            
            for web_result in all_results.get('web_targets', []):
                for vuln in web_result.get('vulnerabilities', []):
                    severity = vuln.get('severity', 'low').lower()
                    if severity in severity_counts:
                        severity_counts[severity] += 1
                        total_vulns += 1
            
            f.write(f"\nVulnerabilities Found: {total_vulns}\n")
            if total_vulns > 0:
                f.write("  By Severity:\n")
                for severity, count in severity_counts.items():
                    if count > 0:
                        f.write(f"    {severity.upper()}: {count}\n")
            
            # Count exploits by severity
            exploit_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            total_exploits = 0
            
            # Count from web targets
            for web_result in all_results.get('web_targets', []):
                for exploit in web_result.get('exploits', []):
                    severity = exploit.get('severity', 'low').lower()
                    if severity in exploit_counts:
                        exploit_counts[severity] += 1
                        total_exploits += 1
            
            # Count from service targets
            for service_result in all_results.get('service_targets', []):
                for exploit in service_result.get('exploits', []):
                    severity = exploit.get('severity', 'low').lower()
                    if severity in exploit_counts:
                        exploit_counts[severity] += 1
                        total_exploits += 1
            
            f.write(f"\nRelevant Exploits Found: {total_exploits}\n")
            if total_exploits > 0:
                f.write("  By Severity:\n")
                for severity, count in exploit_counts.items():
                    if count > 0:
                        f.write(f"    {severity.upper()}: {count}\n")
            
            # Count open ports across all IPs
            total_open_ports = sum(ip_data.get('open_ports_count', 0) for ip_data in ip_analyses)
            f.write(f"\nTotal Open Ports Found: {total_open_ports}\n")
            
            # Most common services
            all_services = []
            for ip_data in ip_analyses:
                all_services.extend(ip_data.get('services_found', []))
            
            service_counter = Counter(all_services)
            if service_counter:
                f.write("\nMost Common Services:\n")
                for service, count in service_counter.most_common(5):
                    f.write(f"  {service}: {count} instances\n")
            
            f.write("\nOutput Files:\n")
            f.write(f"  Main Report: {self.report_file}\n")
            f.write(f"  JSON Data: {self.json_file}\n")
            f.write(f"  Tool Outputs: {self.data_dir}/\n")
        
        # Save all results to JSON
        with open(self.json_file, 'w') as f:
            json.dump(all_results, f, indent=2)
        
        print("\n" + "=" * 100)
        print("SCAN COMPLETE!")
        print(f"Duration: {elapsed:.1f} seconds")
        print(f"Web Targets: {len(web_targets)}")
        print(f"Service Targets: {len(service_targets)}")
        print(f"IP Addresses: {len(self.ips)}")
        print(f"Open Ports Found: {total_open_ports}")
        print(f"Output: {self.data_dir}")
        print("=" * 100)
        
        return all_results


def main(domain, subdomain_file, nmap_json, ip_input):
    """Main function."""
    print("\nRECON ENHANCER - Enhanced Edition")
    print(f"Target: {domain}")
    print("=" * 100)
    
    # Check required files
    for file_path in [subdomain_file, nmap_json]:
        if not os.path.exists(file_path):
            print(f"[!] File not found: {file_path}")
            return None
    
    # Create enhancer
    enhancer = ReconEnhancer(domain, subdomain_file, nmap_json, ip_input)
    
    # Run comprehensive scan
    results = enhancer.run_comprehensive_scan()
    
    return results


