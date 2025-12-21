import os 
import json
import subprocess

class ReconEnhancer:
    def __init__(self,domain,SubdomainFile,NmapJson,Ip):
        self.domain = domain
        self.SubdomainFile =SubdomainFile
        self.NmapJson = NmapJson
        self.Ip = Ip

        self.basedir = f'results/{domain}'
        self.data_dir = f'{basedir}/FinalReport'
        self.reportFile = f'{data_dir}/report.txt'
        self.jsonFile = f'{data_dir}/report.json'

        os.makedirs(self.data_dir, exist_ok=True)

        self.subdomains = self.load_subdomains()

        self.ips = self.load_ips()

        self.nmap_data = self.load_nmapJson()

        self.available_wordlists = {
            'dir_small': '/usr/share/wordlists/dirb/common.txt',
                        'dir_medium': '/usr/share/wordlists/dirb/big.txt',
                        'dir_large': '/usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt'
        }

        


    def load_subdomains(self):
        if not os.path.exists(self.SubdomainFile):
            print(f"!! Subdomain File not found: {self.SubdomainFile}")
            return []

        with open(self.SubdomainFile,'r') as f:
                    return [line.strip() for line in f if line.strip()]


    def load_ips(self):
        ips = []
        for ip in self.Ip:
            ips.append(ip)
            print(ip)
        return ips

    
    def load_nmapJson(self):
        if not os.path.exists(self.NmapJson):
            print("NmapJson File not Found")
            return {}

        try:
            with open(self.NmapJson,'r') as f:
                return json.load(f)

    


    def write_report(self,content):
        with open(self.reportFile, 'a') as f:
            f.write(content + '\n')

    def save_json(self,data,filename):
        with open(f'{self.data_dir}/{filename}','w') as f:
            json.dump(data,f, indent=2)


    def run_gobuster(self, url, wordlist_name='dir_small'):
        if wordlist_name not in self.available_wordlists:
            print(f'Word List Not Available : {wordlist_name}')
            return []

        wordlist = self.available_wordlists[wordlist_name]

        outputFile = f'{self.data_dir}/gobuster_{url.replace("://","-").replace(":","_")}.json'

        cmd = f'gobuster dir -u {url} -w {wordlist} -t 30 -q -o {output_file} --format json'

        print(f"[GOBUSTER] Scanning {url} with {wordlist_name}")



        try:
            results = subprocess.run(cmd, shell=True, timeout=300, capture_output=True, text=True)

            if results.returncode == 0 and os.path.exists(outputFile):
                with open(outputFile,'r') as f:
                    try:
                        lines = [json.loads(line) for line in f if line.strip()]
                        return lines

                    except:
                        return []
        except subprocess.TimeoutExpired:
            print("GoBuster Time out")


        except Exception as e:
            print("Error while using Gobuster",e)

        return []



    def find_web_targets(self):
        web_targets = []

        if not self.nmap_data:
            print("[!] No service discovery data in Nmap JSON")
            return web_targets
    
        service_discovery = self.nmap_data['serviceDiscovery']

        for ip,data in service_discovery.items():
            if 'openPorts' not in data:
                continue 
            for port_info in data['openPorts']:
                port = port_info.get('port', '')
                service = port_info.get('service', '')

                if port in ['80','443','8080','8443'] or 'http' in str(service).lower():
                    url = f'http://{ip}:{port}' if port != '443' else f'https://{ip}:{port}'

                    web_targets.append({
                        'ip' : ip,
                        'port': port,
                        'service': service,
                        'version': port_info.get('version', ''),
                        'state': port_info.get('state',''),
                        'url': url
                        
                    }) 

        print(f"Found {len(web_targets)} web targets")
        return web_targets



    def run_whatweb(self,url):
        safeurl = url.replace("://", "_").replace(":", "_").replace("/", "_")
        outputFile = f'{self.data_dir}/whatweb_{safe_url}.json'

        # imp
        cmd = f'whatweb {url} --color=never --log-json={outputFile}'

        print(f"Whatweb Analyzing {url}")

        try:
            subprocess.run(cmd, shell=True, timeout=300, capture_output=True)

            if os.path.exists(outputFile):
                with open(outputFile, 'r') as f:
                    try: 
                        return json.load(f)
                    except:
                        return {}

        except Exception as e:
            print(f"! Whatweb Error: {e}")

        return {}



    def run_nikto(self, url):
        safe_url = url.replace("://", "_").replace(":", "_").replace("/", "_")
        outputFile = f'{self.data_dir}/nikto_{safe_url}.txt'

        #imp 
        cmd = f'nikto -h {url} -Format txt -output {outputFile}'

        print(f'Running Nikto Scan')

        try:
            subprocess.run(cmd, shell=True, timeout=300 , capture_output=True)

            if os.path.exists(outputFile):
                with open(outputFile,'r') as f:
                    return f.read()

        except Exception as e:
            print('Nikto Error: ',e)


        return ''



    def check_api_endpoints(self , url):
        endpoints = {}
        common_paths = [
            '/api', '/api/v1', '/api/v2', '/graphql', '/rest', '/soap',
                        '/oauth', '/auth', '/login', '/register', '/users', '/admin',
                        '/wp-admin', '/wp-login', '/cpanel', '/administrator',
                        '/dashboard', '/manager', '/webadmin'
        ]

        print("api testing for url: ",url)


        for path in common_paths:
            full_url = f'{url}{path}'

            try:
                resp = requests.get(full_url, timeout=5, verify=False)
                if resp.status_code < 404:
                    endpoints.append({
                        'url': full_url,
                        'status': resp.status_code,
                        'length': len(resp.text)
                    })

            except Exception as e:
                pass

        return endpoints



    def search_exploits(self,service_name):
        if not service_name:
            print("Service name not found")
            return 0,''

        safename = service_name.replace(" ", "_").replace("/", "_")
        outputFile = f'{self.data_dir}/exploits_{safe_name}.txt'
        cmd = f'searchsploit {service_name} > {outputFile} 2>&1'

        print(f"[EXPLOITS] Searching for {service_name}")

        try:
            subprocess.run(cmd, shell=True, timeout=30)

            if os.path.exists(outputFile):
                with open(outputFile, 'r') as f:
                    content = f.read()

                    exploit_count = content.count('Exploit:')
                    return exploit_count, content[:1000] # for testing mf

        except Exception as e:
            print("Error in serach Exploit: ",e)

        return 0,''


    def free_ip_lookup(self,ip):
        try:
            resp = requests.get(f'http://ipwho.is/{ip}', timeout=10)
            if resp.status_code == 200:
                return resp.json()
        except Exception as e:
            print("Ip Lookup Error: ", e)

        return {}


    def get_os_info(self,ip):
        if not self.nmap_data or 'osDiscovery' not in self.nmap_data:
            return []

        os_data = self.nmap_data['osDiscovery']
        if ip in os_data and 'osMatches' in os_data[ip]:
            return os_data[ip]['osMatches']

        return []


    def generate_port_summary(self):
        port_summary = {}

        if not self.nmap_data or 'serviceDiscovery' not in self.nmap_data:
            return port_summary

        service_discovery = self.nmap_data['serviceDiscovery']

        for ip, data = service_discovery.items():
            if 'openPorts' in data:
                port_summary[ip] = {
                    'open_count': data.get('openCount',0),
                    'ports': data['openPorts']
                }

        return port_summary


    def run_enhancement(self):

        print('='*70)
        print("Recon Enhancement Start for domain: ",self.domain)
        print('='*70)

        self.write_report(f"{'='*70}")
        self.write_report(f"RECON ENHANCEMENT REPORT - {self.domain}")

        self.write_report(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self.write_report(f"{'='*70}\n")

        all_results = {
            'domain': self.domain,
            'timestamp': datetime.now().isoformat(),
            'subdomains': self.subdomains,
            'ips': self.ips,
            'port_summary': self.generate_port_summary(),
            'web_targets': [],
            'directory_scans': {},
            'vulnerability_scans': {},
            'api_endpoints': {},
            'exploits': {},
            'ip_info': {},
            'os_info': {}
        }

        self.write_report(f"- BASIC INFORMAION - ")
        self.write_report(f'Subdomain_Found : {len(self.subdomains)}')
        self.write_report(f"IP addresses: {len(self.ips)}")

        # Port
        print('Starting Port Summary')
        self.write_report('\nOpen Ports Summary: ')

        port_summary = self.generate_port_summary()
        for ip,data in port_summary.items():
            self.write_report(f"\n  {ip}:")
            self.write_report(f"    Open ports: {data['open_count']}")
            for port in data['ports']:
                self.write_report(f"    - {port['port']}/{port['service']} ({port.get('version', 'No version')})")


        # Web Target
        print("Starting Web_Target: ")
        web_targets = self.find_web_targets()

        self.write_report(f'\nWeb Target Found: {len(web_targets)}')

        for target in web_targets:
            self.write_report(f"  - {target['url']} ({target['ip']}:{target['port']}) - {target['service']} {target.get('version', '')}")

        all_results['web_targets'] = web_targets


        # Whatweb Tech Detection 

        print("Starting Tech Detection using WhatWeb")

        self.write(f'\nTechnology Detection')

        for target in web_targets:
            url = target['url']
            whatweb_data = self.run_whatweb(url)

            if whatweb_data:
                self.save_json(whatweb_data, f"whatweb_{url.replace('://', '_').replace(':', '_').replace('/', '_')}.json")            

                plugins = whatweb_data.get('plugins', {})
                tech_list = []

                for plugin, data in plugins.items():
                    if isinstance(data, dict):
                        version = data.get('version', [])
                        if version:
                            tech_list.append(f"{plugin} {version[0]}")
                        else:
                            tech_list.append(plugin)


                self.write_report(f'\n {url}: ')

                if tech_list:
                    self.write_report(f"    Technologies: {', '.join(tech_list)}")

                else:
                    self.write_report(f"    No Technologies Detected")


        # Directory Busting 

        print("Running Directory Busting: ")
        self.write_report(f'\nDirectory Busting Results')

        for target in web_targets:
            url = target['url']
            dir_results = self.run_gobuster(url, 'dir_small')

            if dir_results:
                all_results['directory_scans'][url] = dir_results
                self.write_report('\n {url}: ')
                self.write_report(f"    Found {len(dir_results)} directories")

                intresting = []

                for item in dir_results:
                    path = item.get('path','') or item.get('url','')
                    if any(word in str(path).lower() for word in ['admin', 'login', 'config', 'backup', 'api', 'wp-']):
                        interesting.append(path)

                if interesting:
                    self.write_report(f"    Inresting {', '.join(interesting[:5])}")



        # Api Endpoint Discovery

        print('Checking Api Endpoint: ')

        self.write_report(f'Api Endpoint Discovery')

        for target in web_targets:
            url = target['url']
            endpoints = self.check_api_endpoints(url)

            if endpoints:
                all_results['api_endpoints'][url] = endpoints
                self.write_report(f'\n {url}: ')
                self.write_report(f"    Found {len(endpoints)} endpoints")
                for endpoint in endpoints:
                    self.write_report(f"    - {endpoint['url']} (status: {endpoint['status']})")


        # Vulnerability Scanning 

        print("Starting Vulnerability Scanning")
        self.write_report("Starting Vulnerability Scans: ")

        for target in web_targets:
            url = target['url']
            nikto_results = self.run_nikto(url)

            if nikto_results:
                all_results['vulnerability_scans'][url] = nikto_results[:500]

                issue_count = nikto_results.count('+')
                self.write_report(f"\n  {url}:")
                self.write_report(f"    Issues found: {issue_count}")

                safe_url = url.replace("://", "_").replace(":", "_").replace("/", "_")
                with open(f'{self.data_dir}/nikto_full_{safe_url}.txt', 'w') as f:
                    f.write(nikto_results)


        # Exploit Search 
        print("Search for Exploit: ")
        self.write_report("\n Exploit Database Search ")

        services_found = set()

        for target in web_targets:
                    if target.get('service'):
                        services_found.add(target['service'])

        for service in list(services_found)[:5]:  
                    count, results = self.search_exploits(service)
                    if count > 0:
                        all_results['exploits'][service] = count
                        self.write_report(f"\n  {service}:")
                        self.write_report(f"    Found {count} potential exploits")

        # OS Information
        print("Gathering OS info")

        self.write_report("\n OS Detection")


        for ip in self.ips[:5]:  
                    os_matches = self.get_os_info(ip)
                    if os_matches:
                        all_results['os_info'][ip] = os_matches
                        self.write_report(f"\n  {ip}:")
                        for os_match in os_matches[:1]:  # Show top 1 OS matches
                            self.write_report(f"    - {os_match.get('name', 'Unknown')} (Accuracy: {os_match.get('accuracy', '0')}%)")
        

        # Ip Information
        print("Gathering IP information")
        self.write_report('\n Ip Information')

        for ip in self.ips[:5]:  # Limit to 5 IPs
                    ip_info = self.free_ip_lookup(ip)
                    if ip_info:
                        all_results['ip_info'][ip] = ip_info
                        self.write_report(f"\n  {ip}:")
                        self.write_report(f"    Organization: {ip_info.get('org', 'Unknown')}")
                        self.write_report(f"    ISP: {ip_info.get('isp', 'Unknown')}")
                        self.write_report(f"    Country: {ip_info.get('country', 'Unknown')}")
                        self.write_report(f"    City: {ip_info.get('city', 'Unknown')}")


        # Saving results to jspn
        self.save_json(all_results, 'enhanced.json')

        # Final Summary
        print("Final Summary Generation: ")
        self.write_report(f"\n{'='*70}")
        self.write_report(f" FINAL SUMMARY")
        self.write_report(f"{'='*70}")
        self.write_report(f"Total Subdomains: {len(self.subdomains)}")
        self.write_report(f"Total IP Addresses: {len(self.ips)}")
        self.write_report(f"Web Targets Found: {len(web_targets)}")
                
        total_ports = sum(data['open_count'] for data in port_summary.values())
        self.write_report(f"Total Open Ports: {total_ports}")
                
        self.write_report(f"Directory Scans Completed: {len(all_results['directory_scans'])}")
        self.write_report(f"API Endpoints Found: {sum(len(v) for v in all_results['api_endpoints'].values())}")
        self.write_report(f"Vulnerability Scans: {len(all_results['vulnerability_scans'])}")
        self.write_report(f"Potential Exploits: {sum(all_results['exploits'].values())}")
                
        self.write_report(f"\n Data saved in: {self.data_dir}/")
        self.write_report(f" Report: {self.reportFile}")
        self.write_report(f" JSON Data: {self.jsonFile}")
        self.write_report(f"{'='*70}")
                
        print(f"\n{'='*70}")
        print(f" ENHANCEMENT COMPLETE!")
        print(f"{'='*70}")
        print(f" Report saved to: {self.reportFile}")
        print(f" JSON data saved to: {self.jsonFile}")
        print(f" All files in: {self.data_dir}/")
        print(f"{'='*70}")
                
        return all_results

        
    
def main(domain,SubdmainFile,NmapJson,Ip):
    print(domain,SubdmainFile,NmapJson,Ip)

    print('='*70)

    mainObj = ReconEnhancer(domain,SubdomainFile,NmapJson,Ip)
    mainObj.run_enhancement()

    
