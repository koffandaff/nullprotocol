#!/usr/bin/env python3
"""
Brute Force Module — Automated attack chaining based on recon data.
Reads enhanced.json and chains attacks using Hydra, SQLMap, etc.
"""

import os
import sys
import json
import concurrent.futures
from urllib.parse import urlparse

# Add recon directory to path for utility imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'recon'))
from utility import (
    console, section_header, status_msg, success_msg,
    error_msg, warning_msg, info_msg, banner, make_table
)
from rich.prompt import Prompt, Confirm

# SQLite database support
try:
    from db_handler import DatabaseHandler
    DB_AVAILABLE = True
except ImportError:
    DB_AVAILABLE = False

from attack_chain import (
    hydra_ssh, hydra_ftp, hydra_http_form,
    hydra_smtp, hydra_mysql, hydra_rdp,
    hydra_telnet, hydra_pop3, hydra_imap,
    sqlmap_url, sqlmap_form, nmap_vulnscan,
    nikto_scan, dirb_scan, hping3_dos,
    run_metasploit_scan
)


def load_recon_data(results_dir):
    """Find and load scan data. Tries SQLite DB first, falls back to JSON."""
    if not os.path.exists(results_dir):
        error_msg(f"Results directory not found: {results_dir}")
        return None, None

    scans = []

    # ── Try SQLite databases first ──
    if DB_AVAILABLE:
        for domain_dir in sorted(os.listdir(results_dir)):
            db_path = os.path.join(results_dir, domain_dir, 'FinalReport', 'nullprotocol.db')
            if os.path.exists(db_path):
                try:
                    db = DatabaseHandler(db_path)
                    db_scans = db.get_all_scans()
                    for s in db_scans:
                        data = db.get_full_scan_as_dict(s['id'])
                        if data:
                            scans.append({
                                'dir': domain_dir,
                                'domain': data.get('domain', domain_dir),
                                'timestamp': data.get('timestamp', ''),
                                'path': db_path,
                                'data': data,
                                'source': 'db'
                            })
                    db.close()
                except Exception:
                    pass

    # ── JSON fallback for dirs not loaded from DB ──
    loaded_dirs = {s['dir'] for s in scans}
    for domain_dir in sorted(os.listdir(results_dir)):
        if domain_dir in loaded_dirs:
            continue
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
                    'data': data,
                    'source': 'json'
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
        src_tag = f" [dim][{scan.get('source', 'json')}][/dim]"
        console.print(f"  [cyan]{i}[/cyan] -- {scan['domain']} ({scan['timestamp'][:19]}){src_tag}")
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

    # ─── DoS Opportunity (Top Priority) ─────────────────────────
    # Pick the first valid IP or use domain
    dos_target = data.get('domain')
    for st in data.get('service_targets', []):
        ip = st.get('target', {}).get('ip')
        if ip:
            dos_target = ip
            break

    if dos_target:
        opportunities.append({
            'type': 'dos_flood',
            'tool': 'hping3',
            'ip': dos_target,
            'port': '80', 
            'mode': 'syn',
            'service': 'DoS Stress Test',
            'description': f'hping3 SYN Flood on {dos_target} (30s Stress Test)',
            'severity': 'critical',
            'func': hping3_dos
        })

    # Metasploit Auto Scan (High Priority)
    seen_ips_msf = set()
    for st in data.get('service_targets', []):
        target = st.get('target', {})
        ip = target.get('ip', '')
        if ip and ip not in seen_ips_msf:
            seen_ips_msf.add(ip)
            
            # Gather all open ports for this IP
            host_ports = []
            for sub_st in data.get('service_targets', []):
                 sub_target = sub_st.get('target', {})
                 if sub_target.get('ip') == ip:
                     host_ports.append({
                         'port': sub_target.get('port'), 
                         'service': sub_target.get('service')
                     })
            
            opportunities.append({
                'type': 'metasploit_auto',
                'tool': 'Metasploit',
                'ip': ip,
                'service': 'Targeted Scan',
                'description': f'Auto-generate & Run MSF Scan on {ip}',
                'severity': 'critical',
                'extra_data': host_ports,
                'func': run_metasploit_scan
            })

    # SSH targets
    for st in data.get('service_targets', []):
        target = st.get('target', {})
        service = target.get('service', '').lower()
        ip = target.get('ip', '')
        port = target.get('port', '')

        # Skip if port is missing to avoid defaulting to standard ports 
        # for services running on non-standard ports (if data was lost).
        if not port:
            continue

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

        elif service in ['smtp', 'smtps'] or port in ['25', '465', '587']:
            opportunities.append({
                'type': 'smtp_brute',
                'tool': 'Hydra',
                'ip': ip,
                'port': port or '25',
                'service': 'SMTP',
                'description': f'SMTP Brute Force on {ip}:{port or 25}',
                'severity': 'high',
                'func': hydra_smtp
            })

        elif service == 'mysql' or port == '3306':
            opportunities.append({
                'type': 'mysql_brute',
                'tool': 'Hydra',
                'ip': ip,
                'port': port or '3306',
                'service': 'MySQL',
                'description': f'MySQL Brute Force on {ip}:{port or 3306}',
                'severity': 'critical',
                'func': hydra_mysql
            })

        elif service in ['ms-wbt-server', 'rdp'] or port == '3389':
            opportunities.append({
                'type': 'rdp_brute',
                'tool': 'Hydra',
                'ip': ip,
                'port': port or '3389',
                'service': 'RDP',
                'description': f'RDP Brute Force on {ip}:{port or 3389}',
                'severity': 'high',
                'func': hydra_rdp
            })

        elif service == 'telnet' or port == '23':
            opportunities.append({
                'type': 'telnet_brute',
                'tool': 'Hydra',
                'ip': ip,
                'port': port or '23',
                'service': 'Telnet',
                'description': f'Telnet Brute Force on {ip}:{port or 23}',
                'severity': 'high',
                'func': hydra_telnet
            })

        elif service in ['pop3', 'pop3s'] or port in ['110', '995']:
            opportunities.append({
                'type': 'pop3_brute',
                'tool': 'Hydra',
                'ip': ip,
                'port': port or '110',
                'service': 'POP3',
                'description': f'POP3 Brute Force on {ip}:{port or 110}',
                'severity': 'medium',
                'func': hydra_pop3
            })

        elif service in ['imap', 'imaps'] or port in ['143', '993']:
            opportunities.append({
                'type': 'imap_brute',
                'tool': 'Hydra',
                'ip': ip,
                'port': port or '143',
                'service': 'IMAP',
                'description': f'IMAP Brute Force on {ip}:{port or 143}',
                'severity': 'medium',
                'func': hydra_imap
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

    # SQLi targets from crawler (deduplicated by path + params)
    crawler_data = data.get('crawler', {})
    seen_sqli = set()
    if isinstance(crawler_data, dict):
        for url, cdata in crawler_data.items():
            for sqli in cdata.get('potential_sqli', []):
                sqli_url = sqli.get('url', '')
                sqli_type = sqli.get('type', '')
                score = sqli.get('sqli_score', 0)

                if score >= 2:
                    # Dedup key: path + sorted params/fields + type
                    parsed = urlparse(sqli_url)
                    if sqli_type == 'get_param':
                        dedup_key = (parsed.path, tuple(sorted(sqli.get('params', []))), 'get')
                    else:
                        dedup_key = (parsed.path, tuple(sorted(set(sqli.get('fields', [])))), 'form')

                    if dedup_key in seen_sqli:
                        continue
                    seen_sqli.add(dedup_key)

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

    # Web scanning — Nikto + Directory brute force on web targets
    seen_web_hosts = set()
    for wt in data.get('web_targets', []):
        target = wt.get('target', {})
        url = target.get('url', '')
        ip = target.get('ip', '')

        host_key = f"{ip}:{target.get('port', '')}"
        if host_key not in seen_web_hosts:
            seen_web_hosts.add(host_key)
            opportunities.append({
                'type': 'nikto',
                'tool': 'Nikto',
                'url': url,
                'service': 'Web Vuln Scanner',
                'description': f'Nikto scan on {url}',
                'severity': 'medium',
                'func': nikto_scan
            })
            opportunities.append({
                'type': 'dirb',
                'tool': 'Dirb/Gobuster',
                'url': url,
                'service': 'Dir Brute Force',
                'description': f'Directory brute force on {url}',
                'severity': 'low',
                'func': dirb_scan
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

    # Results live at recon/results/<domain>/FinalReport/
    # When launched from recon/main.py, CWD = brute/ and __file__ = brute/main.py
    # So we need to check multiple locations:
    _candidates = [
        os.path.join(os.getcwd(), 'results'),                              # CWD/results (if run from recon/)
        os.path.join(os.path.dirname(__file__), '..', 'recon', 'results'), # brute/../recon/results (launched from brute/)
        os.path.join(os.path.dirname(__file__), 'results'),                # brute/results (unlikely but covered)
        os.path.join(os.path.dirname(__file__), '..', 'results'),          # fsociety/results (old layout)
    ]

    results_dir = None
    for candidate in _candidates:
        if os.path.isdir(candidate):
            results_dir = candidate
            break

    if not results_dir:
        # Fallback — show all paths tried for debugging
        error_msg(f"Results directory not found. Searched: {', '.join(_candidates)}")
        return
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
    max_threads = os.cpu_count() or 4
    section_header(f"Executing Attacks (Parallel: {max_threads} threads)")
    output_dir = os.path.join(results_dir, domain, 'BruteForce')
    os.makedirs(output_dir, exist_ok=True)

    results = []
    total = len(selected)
    
    # Run in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_map = {}
        for count, idx in enumerate(selected, 1):
            opp = opportunities[idx]
            # print status
            info_msg(f"Queued [{count}/{total}]: {opp['tool']} -- {opp['service']}")
            future = executor.submit(opp['func'], opp, output_dir)
            future_map[future] = opp
            
        # Collect results as they finish
        for future in concurrent.futures.as_completed(future_map):
            opp = future_map[future]
            try:
                result = future.result()
                results.append({'opportunity': opp['description'], 'result': result})

                if result.get('success'):
                    success_msg(f"COMPLETED: {opp['tool']} - {opp.get('service')} -- {result.get('message', 'Done')}")
                else:
                    warning_msg(f"COMPLETED: {opp['tool']} - {opp.get('service')} -- {result.get('message', 'No findings')}")

                if result.get('output_file'):
                    info_msg(f"Output saved: {result['output_file']}")

            except Exception as e:
                error_msg(f"Attack failed: {e}")
                results.append({'opportunity': opp['description'], 'error': str(e)})

    # Save results
    results_file = os.path.join(output_dir, 'brute_results.json')
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)

    # Summary table
    console.print()
    section_header("ATTACK RESULTS SUMMARY")
    summary_rows = []
    for r in results:
        desc = r['opportunity'][:55]
        if 'error' in r:
            status = "[red]FAILED[/red]"
            detail = r['error'][:30]
        elif r.get('result', {}).get('success'):
            status = "[green]SUCCESS[/green]"
            detail = r['result'].get('message', '')[:30]
        else:
            status = "[yellow]NO FINDINGS[/yellow]"
            detail = r.get('result', {}).get('message', '')[:30]
        summary_rows.append((desc, status, detail))

    make_table(
        "Results",
        [("Attack", "white"), ("Status", ""), ("Detail", "dim")],
        summary_rows
    )

    success_msg(f"All results saved to: {results_file}")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n  [bold red]Attacks aborted by user.[/bold red]")
