import os

class MetasploitHandler:
    """
    Handles the generation of Metasploit Resource Scripts (.rc) 
    based on discovered services.
    """
    
    def __init__(self):
        self.modules = {
            'ftp': [
                'auxiliary/scanner/ftp/ftp_version',
                'auxiliary/scanner/ftp/anonymous'
            ],
            'ssh': [
                'auxiliary/scanner/ssh/ssh_version',
                'auxiliary/scanner/ssh/ssh_login' # Be careful with brute force
            ],
            'smb': [
                'auxiliary/scanner/smb/smb_version',
                'auxiliary/scanner/smb/smb_login',
                'exploit/windows/smb/ms17_010_eternalblue'
            ],
            'http': [
                'auxiliary/scanner/http/http_version',
                'auxiliary/scanner/http/robots_txt',
                'auxiliary/scanner/http/dir_scanner',
                'auxiliary/scanner/http/title'
            ],
            'https': [
                'auxiliary/scanner/http/http_version',
                'auxiliary/scanner/http/robots_txt',
                'auxiliary/scanner/http/dir_scanner',
                'auxiliary/scanner/http/title',
                'auxiliary/scanner/http/ssl'
            ],
            'mysql': [
                'auxiliary/scanner/mysql/mysql_version',
                'auxiliary/scanner/mysql/mysql_login'
            ],
            'telnet': [
                'auxiliary/scanner/telnet/telnet_version',
                'auxiliary/scanner/telnet/telnet_login'
            ],
            'postgres': [
                'auxiliary/scanner/postgres/postgres_version',
                'auxiliary/scanner/postgres/postgres_login'
            ],
            'rdp': [
                'auxiliary/scanner/rdp/rdp_scanner',
                # 'auxiliary/scanner/rdp/cve_2019_0708_bluekeep' # Potentially dangerous
            ]
        }

    def generate_resource_script(self, target_ip, open_ports):
        """
        Generates a .rc file for msfconsole to run.
        open_ports: list of dicts {'port': 80, 'service': 'http'}
        """
        script_content = []
        script_content.append(f"workspace -a nullprotocol_scan_{target_ip}")
        script_content.append(f"workspace nullprotocol_scan_{target_ip}")
        
        # Keep track of services we've already added generic modules for
        # (though we might want to run per-port)
        
        for port_info in open_ports:
            port = port_info.get('port')
            service = port_info.get('service', '').lower()
            
            # Map 'http-proxy', 'http-alt' to 'http'
            if 'http' in service:
                service_key = 'https' if 'ssl' in service or port == 443 else 'http'
            else:
                service_key = service

            if service_key in self.modules:
                script_content.append(f"\n# Scanning {service} on port {port}")
                for module in self.modules[service_key]:
                    script_content.append(f"use {module}")
                    script_content.append(f"set RHOSTS {target_ip}")
                    script_content.append(f"set RPORT {port}")
                    
                    # Optimization settings
                    script_content.append("set THREADS 10")
                    script_content.append("set CONCURRENCY 10")
                    
                    # For specific modules
                    if 'dir_scanner' in module:
                        script_content.append("set DICTIONARY /usr/share/wordlists/dirb/common.txt")
                    
                    if 'login' in module:
                        # Don't go too crazy on login attempts in a general scan
                        script_content.append("set USER_AS_PASS true")
                        script_content.append("set BLANK_PASSWORDS true")
                        # script_content.append("set USER_FILE ...") # Maybe too heavy for auto scan?
                    
                    script_content.append("run")
        
        script_content.append("\nexit")
        
        filename = f"scan_{target_ip}.rc"
        with open(filename, 'w') as f:
            f.write('\n'.join(script_content))
            
        return os.path.abspath(filename)
