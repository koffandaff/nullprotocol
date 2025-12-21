#!/usr/bin/env python3
# ip_analyzer.py - IP analysis and geolocation

import requests
import json
import os
import re
import concurrent.futures
from datetime import datetime

class IPAnalyzer:
    def __init__(self, data_dir):
        self.data_dir = data_dir
        self.tool_dir = os.path.join(data_dir, 'ip_analysis')
        os.makedirs(self.tool_dir, exist_ok=True)
        
        # IP geolocation services
        self.geo_services = [
            self.get_ipapi_co,
            self.get_ip_api_com,
            self.get_ipwhois
        ]
    
    def analyze_ip(self, ip_address):
        """Analyze single IP address."""
        print(f"[IP-ANALYSIS] Analyzing {ip_address}")
        
        # Get geolocation from multiple services
        geo_data = self.get_geolocation(ip_address)
        
        # Get threat intelligence
        threat_data = self.get_threat_intel(ip_address)
        
        # Get ASN/ISP information
        asn_data = self.get_asn_info(ip_address)
        
        # Combine all data
        ip_info = {
            'ip': ip_address,
            'geolocation': geo_data,
            'threat_intelligence': threat_data,
            'asn_info': asn_data,
            'timestamp': datetime.now().isoformat()
        }
        
        # Save to individual file
        self.save_ip_report(ip_address, ip_info)
        
        return ip_info
    
    def get_geolocation(self, ip_address):
        """Get geolocation from multiple services."""
        geo_data = {}
        
        for service in self.geo_services:
            try:
                data = service(ip_address)
                if data:
                    geo_data.update(data)
                    break  # Use first successful service
            except:
                continue
        
        return geo_data
    
    def get_ipapi_co(self, ip_address):
        """Get geolocation from ipapi.co."""
        try:
            response = requests.get(
                f'https://ipapi.co/{ip_address}/json/',
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                
                return {
                    'country': data.get('country_name', ''),
                    'country_code': data.get('country_code', ''),
                    'region': data.get('region', ''),
                    'city': data.get('city', ''),
                    'latitude': data.get('latitude', ''),
                    'longitude': data.get('longitude', ''),
                    'timezone': data.get('timezone', ''),
                    'currency': data.get('currency', ''),
                    'languages': data.get('languages', ''),
                    'org': data.get('org', ''),
                    'asn': data.get('asn', '')
                }
        except:
            pass
        
        return {}
    
    def get_ip_api_com(self, ip_address):
        """Get geolocation from ip-api.com."""
        try:
            response = requests.get(
                f'http://ip-api.com/json/{ip_address}',
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                
                return {
                    'country': data.get('country', ''),
                    'country_code': data.get('countryCode', ''),
                    'region': data.get('regionName', ''),
                    'city': data.get('city', ''),
                    'latitude': data.get('lat', ''),
                    'longitude': data.get('lon', ''),
                    'timezone': data.get('timezone', ''),
                    'isp': data.get('isp', ''),
                    'org': data.get('org', ''),
                    'as': data.get('as', '')
                }
        except:
            pass
        
        return {}
    
    def get_ipwhois(self, ip_address):
        """Get geolocation from ipwhois.is."""
        try:
            response = requests.get(
                f'http://ipwho.is/{ip_address}',
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                
                return {
                    'country': data.get('country', ''),
                    'region': data.get('region', ''),
                    'city': data.get('city', ''),
                    'latitude': data.get('latitude', ''),
                    'longitude': data.get('longitude', ''),
                    'timezone': data.get('timezone', ''),
                    'org': data.get('org', ''),
                    'isp': data.get('isp', ''),
                    'asn': data.get('asn', '')
                }
        except:
            pass
        
        return {}
    
    def get_threat_intel(self, ip_address):
        """Get threat intelligence data."""
        threat_data = {}
        
        # Check AbuseIPDB (requires API key, but we can check reputation)
        try:
            # This is a simple check - in production you'd use the API
            response = requests.get(
                f'https://api.abuseipdb.com/api/v2/check',
                headers={'Key': ''},  # Add your API key here
                params={'ipAddress': ip_address, 'maxAgeInDays': '90'},
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json().get('data', {})
                threat_data['abuseipdb'] = {
                    'abuse_confidence_score': data.get('abuseConfidenceScore', 0),
                    'total_reports': data.get('totalReports', 0),
                    'last_reported': data.get('lastReportedAt', ''),
                    'is_whitelisted': data.get('isWhitelisted', False)
                }
        except:
            pass
        
        # Simple threat indicators based on IP range
        threat_data['indicators'] = self.check_ip_indicators(ip_address)
        
        return threat_data
    
    def check_ip_indicators(self, ip_address):
        """Check for basic threat indicators."""
        indicators = []
        
        # Check for private IP
        if ip_address.startswith(('10.', '172.16.', '192.168.', '169.254.')):
            indicators.append('private_ip')
        
        # Check for localhost
        if ip_address in ['127.0.0.1', '::1']:
            indicators.append('localhost')
        
        # Check for multicast
        if ip_address.startswith('224.') or ip_address.startswith('239.'):
            indicators.append('multicast_ip')
        
        # Check for documentation IPs
        if ip_address.startswith('192.0.2.') or ip_address in ['198.51.100.1', '203.0.113.1']:
            indicators.append('documentation_ip')
        
        return indicators
    
    def get_asn_info(self, ip_address):
        """Get ASN/ISP information."""
        asn_info = {}
        
        # Try multiple methods to get ASN info
        try:
            # Method 1: Use ipapi.co
            response = requests.get(f'https://ipapi.co/{ip_address}/json/', timeout=5)
            if response.status_code == 200:
                data = response.json()
                asn_info = {
                    'asn': data.get('asn', ''),
                    'asn_name': data.get('asn', '').split()[0] if data.get('asn') else '',
                    'org': data.get('org', ''),
                    'isp': data.get('org', ''),  # ipapi.co doesn't separate org/isp
                    'network': data.get('network', '')
                }
        except:
            pass
        
        # If first method failed, try alternative
        if not asn_info.get('asn'):
            try:
                # Method 2: Use ip-api.com
                response = requests.get(f'http://ip-api.com/json/{ip_address}', timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    asn_info = {
                        'asn': data.get('as', ''),
                        'asn_name': data.get('as', '').split()[0] if data.get('as') else '',
                        'org': data.get('org', ''),
                        'isp': data.get('isp', ''),
                        'country': data.get('country', '')
                    }
            except:
                pass
        
        return asn_info
    
    def save_ip_report(self, ip_address, ip_info):
        """Save individual IP report to file."""
        safe_ip = re.sub(r'[^a-zA-Z0-9]', '_', ip_address)
        filename = f"ip_{safe_ip}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        filepath = os.path.join(self.tool_dir, filename)
        
        with open(filepath, 'w') as f:
            f.write(f"IP Analysis Report\n")
            f.write(f"IP Address: {ip_address}\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")
            
            # Geolocation
            f.write("GEOLOCATION:\n")
            geo = ip_info.get('geolocation', {})
            if geo:
                f.write(f"  Country: {geo.get('country', 'Unknown')}\n")
                f.write(f"  Region: {geo.get('region', 'Unknown')}\n")
                f.write(f"  City: {geo.get('city', 'Unknown')}\n")
                f.write(f"  Coordinates: {geo.get('latitude', '')}, {geo.get('longitude', '')}\n")
                f.write(f"  Timezone: {geo.get('timezone', '')}\n")
            else:
                f.write("  No geolocation data available\n")
            
            f.write("\n")
            
            # ASN/ISP Info
            f.write("NETWORK INFORMATION:\n")
            asn = ip_info.get('asn_info', {})
            if asn:
                f.write(f"  ASN: {asn.get('asn', 'Unknown')}\n")
                f.write(f"  Organization: {asn.get('org', 'Unknown')}\n")
                f.write(f"  ISP: {asn.get('isp', 'Unknown')}\n")
            else:
                f.write("  No ASN information available\n")
            
            f.write("\n")
            
            # Threat Intelligence
            f.write("THREAT INDICATORS:\n")
            threats = ip_info.get('threat_intelligence', {})
            indicators = threats.get('indicators', [])
            
            if indicators:
                for indicator in indicators:
                    f.write(f"  - {indicator}\n")
            else:
                f.write("  No threat indicators detected\n")
