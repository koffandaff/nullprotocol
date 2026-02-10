import os
import json
import IpNmapHandler
from utility import (
    Validate_Ip, FileGenarator, Create_Domain_Directory,
    enrich_ip_info, console, section_header, status_msg,
    error_msg, success_msg, warning_msg, info_msg, make_table,
    get_progress_bar
)


def IpMasscan(ip_list, domain):
    """Run masscan on validated IPs — uses os.system() for proper sudo/terminal interaction."""
    ips = {}
    Dir = Create_Domain_Directory(domain, 'Ip')

    section_header("MASSCAN -- Fast Port Discovery")

    for ip in ip_list:
        Name = FileGenarator(ip)
        File = os.path.join(Dir, Name)

        status_msg(f"Scanning {ip}...")
        # os.system gives masscan direct terminal access (required for sudo password prompt)
        os.system(f'sudo masscan --top-ports 1000 {ip} --open --rate=25000 --wait 0 -oJ {File}.json')

        json_path = f'{File}.json'
        if os.path.exists(json_path) and os.path.getsize(json_path) > 2:
            with open(json_path, 'r') as f:
                data = f.read()
                ips[ip] = data
            success_msg(f"{ip} -- ports found")
        else:
            warning_msg(f"{ip} -- no open ports detected")
            if os.path.exists(json_path):
                os.remove(json_path)

    # Cleanup remaining empty JSON files
    os.system(f"find '{Dir}' -name '*.json' -type f -empty -delete 2>/dev/null")

    return {'ip': ips, 'dir': Dir}


def IpHandler(Ip, domain=None, Subdomain_File=None):
    """Orchestrate IP scanning pipeline with robust error handling.

    Supports two modes:
      1. Called from Domain flow: domain & Subdomain_File provided
      2. Called directly with IPs: domain is derived from first IP
    """
    import ReconEnhancer

    # ── Derive domain name if not provided ──
    if not domain:
        domain = Ip[0] if Ip else "unknown_target"

    section_header("IP PIPELINE")

    # ── Step 1: Validate IPs ──
    status_msg("Validating IP addresses...")
    valid_ips = Validate_Ip(Ip)

    if not valid_ips:
        error_msg("No valid IP addresses found. Aborting.")
        return

    success_msg(f"{len(valid_ips)} valid IPs out of {len(Ip)} provided")

    # ── Step 2: Enrich IPs (reverse DNS + alive check) ──
    status_msg("Enriching IPs (reverse DNS + ping)...")
    enriched = enrich_ip_info(valid_ips)

    # Display enrichment results in a table
    rows = []
    alive_ips = []
    for info in enriched:
        alive_str = "[green][+] ALIVE[/green]" if info['alive'] else "[red][x] DOWN[/red]"
        rows.append((info['ip'], info['hostname'], alive_str))
        if info['alive']:
            alive_ips.append(info['ip'])

    make_table(
        "IP Enrichment Results",
        [("IP Address", "cyan"), ("Hostname", "white"), ("Status", "")],
        rows
    )

    # Use alive IPs if any, otherwise fall back to all valid IPs
    scan_ips = alive_ips if alive_ips else valid_ips
    if not alive_ips:
        warning_msg("No hosts responded to ping -- scanning all valid IPs anyway (may be filtered)")

    # ── Step 3: Masscan ──
    IpData = IpMasscan(scan_ips, domain)

    if not IpData['ip']:
        warning_msg("Masscan found no open ports. Proceeding with Nmap for deeper scan...")

    # ── Step 4: Nmap ──
    section_header("NMAP -- Deep Service & OS Discovery")
    try:
        Nmap_Result = IpNmapHandler.main(IpData['ip'], IpData['dir'])
        success_msg(f"Nmap results saved to: {Nmap_Result['File_Location']}")
    except Exception as e:
        error_msg(f"Nmap handler failed: {e}")
        # Create a minimal nmap result so ReconEnhancer can still run
        nmap_dir = os.path.join(IpData['dir'], 'Nmap')
        os.makedirs(nmap_dir, exist_ok=True)
        fallback_json = os.path.join(nmap_dir, 'nmap_report.json')
        with open(fallback_json, 'w') as f:
            json.dump({'serviceDiscovery': {}, 'osDiscovery': {}, 'executionTimes': {}}, f)
        Nmap_Result = {'File_Location': fallback_json}
        warning_msg("Using fallback empty Nmap data")

    # ── Step 5: ReconEnhancer ──
    section_header("RECON ENHANCER -- Deep Analysis")

    # If no subdomain file, create a temporary one
    if not Subdomain_File:
        temp_sub_file = os.path.join(IpData['dir'], 'subdomains_temp.txt')
        with open(temp_sub_file, 'w') as f:
            for info in enriched:
                if info['hostname'] and info['hostname'] != 'N/A':
                    f.write(info['hostname'] + '\n')
        Subdomain_File = temp_sub_file
        info_msg(f"Created temp subdomain file from reverse DNS: {temp_sub_file}")

    try:
        ReconEnhancer.main(domain, Subdomain_File, Nmap_Result['File_Location'], IpData['ip'])
        success_msg("Recon Enhancement complete!")
    except Exception as e:
        error_msg(f"ReconEnhancer failed: {e}")
