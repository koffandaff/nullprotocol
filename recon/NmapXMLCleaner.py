import xmltodict
import os

class NmapXMLCleaner:
    
    def parse_xml_file(self, xml_file):
        """Parse XML file and return data"""
        try:
            with open(xml_file, 'r') as f:
                content = f.read()
            return xmltodict.parse(content)
        except Exception as e:
            print(f'[!] Error parsing {xml_file}: {e}')
            return None
    
    def get_host_info(self, data):
        """Extract host information from parsed XML"""
        host = data.get('nmaprun', {}).get('host', {})
        
        # Get IP address
        address = host.get('address', {})
        if isinstance(address, list):
            ip = address[0].get('@addr', 'Unknown')
        else:
            ip = address.get('@addr', 'Unknown')
        
        # Get hostname if available
        hostname = 'Unknown'
        hostnames = host.get('hostnames', {})
        if hostnames:
            hostname_list = hostnames.get('hostname')
            if hostname_list:
                if isinstance(hostname_list, list):
                    hostname = hostname_list[0].get('@name', 'Unknown')
                else:
                    hostname = hostname_list.get('@name', 'Unknown')
        
        return {
            'ip': ip,
            'hostname': hostname,
            'state': host.get('status', {}).get('@state', 'unknown')
        }
    
    def parse_service_scan(self, xml_file):
        """Parse service discovery scan results"""
        data = self.parse_xml_file(xml_file)
        if not data:
            return {}
        
        host_info = self.get_host_info(data)
        host = data.get('nmaprun', {}).get('host', {})
        
        results = {
            'host': host_info,
            'open_ports': [],
            'filtered_ports': [],
            'closed_count': 0,
            'open_count': 0,
            'filtered_count': 0
        }
        
        # Get ports section
        ports_section = host.get('ports', {})
        
        # Get closed ports count from extraports
        extraports = ports_section.get('extraports')
        if extraports:
            results['closed_count'] = int(extraports.get('@count', 0))
        
        # Parse individual ports
        ports_data = ports_section.get('port', [])
        if not isinstance(ports_data, list):
            ports_data = [ports_data] if ports_data else []
        
        for port_info in ports_data:
            if not isinstance(port_info, dict):
                continue
            
            port_id = port_info.get('@portid', '')
            state_info = port_info.get('state', {})
            state = state_info.get('@state', '')
            protocol = port_info.get('@protocol', 'tcp')
            
            # Get service information
            service_info = port_info.get('service', {})
            service_name = service_info.get('@name', 'unknown')
            service_product = service_info.get('@product', '')
            service_version = service_info.get('@version', '')
            
            # Combine version info
            version = ''
            if service_product or service_version:
                version = f"{service_product} {service_version}".strip()
            
            port_data = {
                'port': port_id,
                'protocol': protocol,
                'state': state,
                'service': service_name,
                'version': version
            }
            
            # Categorize ports
            if state == 'open':
                results['open_ports'].append(port_data)
                results['open_count'] += 1
            elif state == 'filtered':
                results['filtered_ports'].append(port_data)
                results['filtered_count'] += 1
        
        # Sort ports by port number
        results['open_ports'].sort(key=lambda x: int(x['port']))
        results['filtered_ports'].sort(key=lambda x: int(x['port']))
        
        return results
    
    def parse_os_scan(self, xml_file):
        """Parse OS discovery scan results"""
        data = self.parse_xml_file(xml_file)
        if not data:
            return {}
        
        host_info = self.get_host_info(data)
        host = data.get('nmaprun', {}).get('host', {})
        
        results = {
            'host': host_info,
            'os_matches': [],
            'ports_used_for_os_detection': []
        }
        
        # Parse OS information
        os_section = host.get('os', {})
        if os_section:
            os_matches = os_section.get('osmatch', [])
            if os_matches:
                if not isinstance(os_matches, list):
                    os_matches = [os_matches]
                
                for match in os_matches:
                    name = match.get('@name', 'Unknown')
                    accuracy = match.get('@accuracy', '0')
                    
                    # Parse OS classes
                    os_type = "Unknown"
                    os_classes = match.get('osclass', [])
                    if os_classes:
                        if not isinstance(os_classes, list):
                            os_classes = [os_classes]
                        if os_classes:
                            os_type = os_classes[0].get('@type', 'Unknown')
                    
                    results['os_matches'].append({
                        'name': name,
                        'accuracy': accuracy,
                        'type': os_type
                    })
                
                # Sort by accuracy (highest first)
                results['os_matches'].sort(key=lambda x: int(x['accuracy']), reverse=True)
        
        # Get ports used for OS detection
        ports_section = host.get('ports', {})
        ports_used = ports_section.get('port', [])
        if ports_used:
            if not isinstance(ports_used, list):
                ports_used = [ports_used] if ports_used else []
            
            for port in ports_used:
                if isinstance(port, dict):
                    port_id = port.get('@portid', '')
                    state = port.get('state', {}).get('@state', '')
                    if state == 'open':
                        results['ports_used_for_os_detection'].append(port_id)
        
        return results
    
    def print_service_results(self, results, output_file=None):
        """Print service scan results"""
        output_lines = []
        
        output_lines.append(f"[+] Host: {results['host']['ip']} ({results['host']['hostname']})")
        output_lines.append("="*60)
        
        if results['open_ports']:
            output_lines.append("\nOPEN PORTS:")
            output_lines.append("-" * 60)
            output_lines.append(f"{'Port':<8} {'Service':<20} {'Version':<20} {'State':<10}")
            output_lines.append("-" * 60)
            for port in results['open_ports']:
                output_lines.append(f"{port['port']:<8} {port['service']:<20} {port['version']:<20} {port['state']:<10}")
        
        if results['filtered_ports']:
            output_lines.append(f"\nFILTERED PORTS ({results['filtered_count']}):")
            filtered_str = ", ".join([p['port'] for p in results['filtered_ports']])
            output_lines.append(f"  {filtered_str}")
        
        output_lines.append(f"\nSummary: {results['open_count']} open, {results['filtered_count']} filtered, {results['closed_count']} closed")
        
        output_text = "\n".join(output_lines)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(output_text)
        
        print(output_text)
        return output_text
    
    def print_os_results(self, results, output_file=None):
        """Print OS scan results"""
        output_lines = []
        
        output_lines.append(f"[+] Host: {results['host']['ip']} ({results['host']['hostname']})")
        output_lines.append("="*60)
        
        if results['os_matches']:
            output_lines.append("\nOS DETECTION RESULTS:")
            output_lines.append("-" * 60)
            output_lines.append(f"{'OS':<40} {'Accuracy':<10} {'Type':<10}")
            output_lines.append("-" * 60)
            for match in results['os_matches'][:5]:
                output_lines.append(f"{match['name'][:40]:<40} {match['accuracy'] + '%':<10} {match['type']:<10}")
            
            if results['ports_used_for_os_detection']:
                ports_str = ", ".join(results['ports_used_for_os_detection'])
                output_lines.append(f"\nPorts used for OS detection: {ports_str}")
        else:
            output_lines.append("\nNo OS information detected")
        
        output_text = "\n".join(output_lines)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(output_text)
        
        print(output_text)
        return output_text
