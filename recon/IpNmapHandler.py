import os
import json
import time
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
import xmltodict

class FastNmapHandler:
    
    def __init__(self):
        self.results = {
            'serviceDiscovery': {},
            'osDiscovery': {},
            'executionTimes': {}
        }
    
    def runCombinedScan(self, ip, outputDir):
        """Run single scan for both services and OS"""
        startTime = time.time()
        
        os.makedirs(outputDir, exist_ok=True)
        xmlFile = f"{outputDir}/{ip}_combined.xml"
        
        # Fast scan command with timing optimizations
        cmd = f"nmap -sS --top-ports 100 -T4 -A -O --osscan-guess -sV --version-intensity 3 {ip} -oX {xmlFile}"
        
        try:
            subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
        except subprocess.TimeoutExpired:
            print(f"[!] Scan timed out for {ip}")
            return None
        
        try:
            with open(xmlFile, 'r') as f:
                data = xmltodict.parse(f.read())
            
            # Extract data from XML
            serviceData = self.extractServiceData(data, ip)
            osData = self.extractOsData(data, ip)
            
            # Save readable text files
            self.saveServiceResults(ip, serviceData, f"{outputDir}/Service_Discovery")
            self.saveOsResults(ip, osData, f"{outputDir}/OS_Discovery")
            
            # Clean up XML file
            os.remove(xmlFile)
            
            execTime = time.time() - startTime
            self.results['executionTimes'][ip] = execTime
            
            return {'service': serviceData, 'os': osData, 'time': execTime}
            
        except Exception as e:
            print(f"[!] Error processing {ip}: {e}")
            return None
    
    def extractServiceData(self, data, ip):
        """Extract service info from XML"""
        host = data.get('nmaprun', {}).get('host', {})
        portsSection = host.get('ports', {})
        
        results = {
            'host': {'ip': ip},
            'openPorts': [],
            'openCount': 0
        }
        
        portsData = portsSection.get('port', [])
        if not isinstance(portsData, list):
            portsData = [portsData] if portsData else []
        
        for portInfo in portsData:
            if not isinstance(portInfo, dict):
                continue
            
            portId = portInfo.get('@portid', '')
            state = portInfo.get('state', {}).get('@state', '')
            
            if state != 'open':
                continue
            
            serviceInfo = portInfo.get('service', {})
            serviceName = serviceInfo.get('@name', 'unknown')
            serviceProduct = serviceInfo.get('@product', '')
            serviceVersion = serviceInfo.get('@version', '')
            
            version = f"{serviceProduct} {serviceVersion}".strip()
            
            portData = {
                'port': portId,
                'service': serviceName,
                'version': version,
                'state': state
            }
            
            results['openPorts'].append(portData)
            results['openCount'] += 1
        
        results['openPorts'].sort(key=lambda x: int(x['port']))
        return results
    
    def extractOsData(self, data, ip):
        """Extract OS info from XML"""
        host = data.get('nmaprun', {}).get('host', {})
        osSection = host.get('os', {})
        
        results = {
            'host': {'ip': ip},
            'osMatches': []
        }
        
        if osSection:
            osMatches = osSection.get('osmatch', [])
            if osMatches:
                if not isinstance(osMatches, list):
                    osMatches = [osMatches]
                
                # Get top 3 OS matches
                for match in osMatches[:3]:
                    name = match.get('@name', 'Unknown')
                    accuracy = match.get('@accuracy', '0')
                    
                    results['osMatches'].append({
                        'name': name,
                        'accuracy': accuracy
                    })
        
        return results
    
    def saveServiceResults(self, ip, data, outputDir):
        """Save service results to text file"""
        os.makedirs(outputDir, exist_ok=True)
        txtFile = f"{outputDir}/{ip}_service.txt"
        
        with open(txtFile, 'w') as f:
            f.write(f"Service Scan Results for {ip}\n")
            f.write("=" * 40 + "\n\n")
            
            if data.get('openPorts'):
                f.write("Open Ports Found:\n")
                f.write("-" * 30 + "\n")
                for port in data['openPorts']:
                    line = f"  • Port {port['port']}: {port['service']}"
                    if port['version']:
                        line += f" (Version: {port['version']})"
                    f.write(line + "\n")
                f.write(f"\nTotal: {data.get('openCount', 0)} open ports\n")
            else:
                f.write("No open ports found\n")
    
    def saveOsResults(self, ip, data, outputDir):
        """Save OS results to text file"""
        os.makedirs(outputDir, exist_ok=True)
        txtFile = f"{outputDir}/{ip}_os.txt"
        
        with open(txtFile, 'w') as f:
            f.write(f"OS Detection Results for {ip}\n")
            f.write("=" * 40 + "\n\n")
            
            if data.get('osMatches'):
                f.write("Detected Operating Systems:\n")
                f.write("-" * 30 + "\n")
                for match in data['osMatches']:
                    f.write(f"  - {match['name']} (Confidence: {match['accuracy']}%)\n")
            else:
                f.write("No OS information detected\n")
    
    def scanSingleIp(self, ip, baseDir):
        """Scan a single IP"""
        print(f"\nScanning {ip}...")
        startTime = time.time()
        
        if not baseDir.startswith('results'):
            baseDir = f"results/{baseDir}"
        
        nmapDir = f"{baseDir}/Nmap"
        
        result = self.runCombinedScan(ip, nmapDir)
        
        if result:
            self.results['serviceDiscovery'][ip] = result['service']
            self.results['osDiscovery'][ip] = result['os']
            
            scanTime = time.time() - startTime
            print(f"  [+] {ip} scanned in {scanTime:.1f}s")
        
        return result
    
    def scanMultipleIpsParallel(self, ips, baseDir, maxWorkers=10):
        """Scan multiple IPs in parallel"""
        print(f"\nStarting scan for {len(ips)} IP addresses")
        print(f"Running up to {maxWorkers} scans at once")
        print("-" * 50)
        
        startTime = time.time()
        
        if not baseDir.startswith('results'):
            baseDir = f"results/{baseDir}"
        
        nmapDir = f"{baseDir}/Nmap"
        os.makedirs(nmapDir, exist_ok=True)
        
        completedCount = 0
        totalIps = len(ips)
        
        with ThreadPoolExecutor(max_workers=maxWorkers) as executor:
            futureToIp = {
                executor.submit(self.runCombinedScan, ip, nmapDir): ip 
                for ip in ips
            }
            
            for future in as_completed(futureToIp):
                ip = futureToIp[future]
                completedCount += 1
                
                try:
                    result = future.result()
                    if result:
                        self.results['serviceDiscovery'][ip] = result['service']
                        self.results['osDiscovery'][ip] = result['os']
                        
                        # Show progress
                        progress = f"[{completedCount}/{totalIps}]"
                        print(f"{progress} {ip}: {result['time']:.1f}s")
                except Exception as e:
                    print(f"[{completedCount}/{totalIps}] {ip}: Error - {e}")
        
        totalTime = time.time() - startTime
        
        jsonFile = f"{nmapDir}/nmap_report.json"
        with open(jsonFile, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print("\n" + "=" * 50)
        print(f"Scan complete! All {totalIps} IPs scanned in {totalTime:.1f}s")
        print(f"Results saved to: {baseDir}/Nmap/")
        
        return {'Result': self.results, 'File_Location': jsonFile}

def main(ips, baseDir, maxWorkers=100):
    scanner = FastNmapHandler()
    return scanner.scanMultipleIpsParallel(ips, baseDir, maxWorkers)
