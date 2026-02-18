#!/usr/bin/env python3
"""
NullProtocol v2.0 — Automated Reconnaissance Pipeline
Entry point for the application.
"""

from subdomain import GetSubDomain
from IpExtraction import Extraction
from Domain import DomainHandler
from IpHandler import IpHandler
from utility import (
    banner, console, section_header,
    status_msg, error_msg, success_msg, warning_msg, info_msg
)
from rich.prompt import Prompt, IntPrompt, Confirm
import sys
import os
import shutil
import subprocess


def _check_existing_scan(domain):
    """Check if a scan directory already exists for this target.
    Returns the domain name to use (may be renamed) or None to cancel."""
    scan_dir = os.path.join('results', domain)
    if not os.path.isdir(scan_dir):
        return domain  # No conflict, proceed normally

    # Existing scan found — prompt user
    warning_msg(f"Existing scan data found for '{domain}' at {scan_dir}/")
    console.print()
    console.print("  [bold cyan]1[/bold cyan]  -->  [bold]Overwrite[/bold] (delete old results and rescan)")
    console.print("  [bold cyan]2[/bold cyan]  -->  [bold]Rename[/bold] (save as new scan with suffix)")
    console.print("  [bold cyan]3[/bold cyan]  -->  [bold]Cancel[/bold] (abort scan)")
    console.print()

    choice = Prompt.ask("  [bold white]Select option[/bold white]", choices=["1", "2", "3"], default="1")

    if choice == '1':
        # Overwrite — delete existing directory
        try:
            shutil.rmtree(scan_dir)
            success_msg(f"Deleted old scan data for '{domain}'")
        except Exception as e:
            error_msg(f"Could not delete {scan_dir}: {e}")
            return None
        return domain

    elif choice == '2':
        # Find next available suffix
        suffix = 2
        while os.path.isdir(os.path.join('results', f"{domain}_{suffix}")):
            suffix += 1
        new_name = f"{domain}_{suffix}"
        info_msg(f"Scan will be saved as '{new_name}'")
        return new_name

    else:
        info_msg("Scan cancelled.")
        return None


def main():
    banner()

    console.print()
    console.print("  [bold cyan]1[/bold cyan]  -->  I have a [bold]Domain Name[/bold]")
    console.print("  [bold cyan]2[/bold cyan]  -->  I have an [bold]IP Address[/bold]")
    console.print("  [bold cyan]3[/bold cyan]  -->  View Previous Scans (HostRecon)")
    console.print("  [bold cyan]4[/bold cyan]  -->  Launch [bold]Brute Force[/bold] Module")
    console.print()

    choice = Prompt.ask("  [bold white]Select mode[/bold white]", choices=["1", "2", "3", "4"], default="1")

    # ── View Previous Scans ──
    if choice == '3':
        _launch_hostrecon()
        post_recon_interactive()
        return

    # ── Brute Force Module ──
    if choice == '4':
        _launch_brute()
        post_recon_interactive()
        return

    # ── Domain Mode ──
    if choice == '1':
        domain = Prompt.ask("  [bold white]Enter domain name[/bold white]")
        if '://' in domain:
            error_msg("Enter domain only (e.g. example.com), not a full URL.")
            return
        # Check for existing scan
        project_name = _check_existing_scan(domain)
        if not project_name:
            return
        section_header(f"DOMAIN RECON -- {domain}")
        if project_name != domain:
            info_msg(f"Scan results will be saved to: results/{project_name}")
            
        DomainHandler(domain, project_name=project_name)

    # ── IP Mode ──
    elif choice == '2':
        console.print()
        console.print("  [bold cyan]1[/bold cyan]  -->  Single IP address")
        console.print("  [bold cyan]2[/bold cyan]  -->  Multiple IPs (comma-separated)")
        console.print()

        ip_choice = Prompt.ask("  [bold white]Select option[/bold white]", choices=["1", "2"], default="1")

        if ip_choice == '1':
            ip = Prompt.ask("  [bold white]Enter IP address[/bold white]").strip()
            ips = [ip]

        elif ip_choice == '2':
            ip_input = Prompt.ask("  [bold white]Enter IPs (comma-separated)[/bold white]").strip()
            ips = [ip.strip() for ip in ip_input.split(',') if ip.strip()]

        else:
            error_msg("Invalid choice")
            return

        if not ips:
            error_msg("No IPs provided.")
            return

        # Check for existing scan (uses first IP as domain identifier)
        target_name = ips[0] if len(ips) == 1 else ips[0]
        project_name = _check_existing_scan(target_name)
        if not project_name:
            return

        section_header(f"IP RECON -- {len(ips)} target(s)")
        if project_name != target_name:
            info_msg(f"Scan results will be saved to: results/{project_name}")
            
        # For IP Handler, 'domain' param is the target label, 'project_name' is output dir
        IpHandler(ips, domain=target_name, project_name=project_name)

    # ── Chaining Logic ──
    post_recon_interactive()


def _launch_hostrecon():
    """Launch the HostRecon Flask web dashboard."""
    success_msg("Launching HostRecon on http://localhost:5000...")
    info_msg("Press Ctrl+C to stop the web server and return to terminal.")
    try:
        subprocess.run([sys.executable, "hostrecon.py"])
    except KeyboardInterrupt:
        success_msg("Web server stopped.")


def _launch_brute():
    """Launch the Brute Force attack module."""
    success_msg("Transitioning to Brute Force Module...")
    brute_path = os.path.join(os.path.dirname(__file__), '..', 'brute', 'main.py')
    if os.path.exists(brute_path):
        try:
            original_cwd = os.getcwd()
            os.chdir(os.path.join(os.path.dirname(__file__), '..', 'brute'))
            subprocess.run([sys.executable, "main.py"])
            os.chdir(original_cwd)
        except Exception as e:
            error_msg(f"Could not start Brute Force module: {e}")
    else:
        error_msg("Brute Force module not found at ../brute/main.py")


def post_recon_interactive():
    """Prompt the user for next steps after reconnaissance finishes."""
    console.print()
    section_header("POST-RECON ACTIONS")
    console.print("  [bold cyan]1[/bold cyan]  -->  Launch [bold]HostRecon[/bold] Web Dashboard (Current Scan)")
    console.print("  [bold cyan]2[/bold cyan]  -->  Start [bold]Brute Force[/bold] Attack Module")
    console.print("  [bold cyan]3[/bold cyan]  -->  View Previous Scans (HostRecon)")
    console.print("  [bold cyan]4[/bold cyan]  -->  Exit")
    console.print()

    choice = Prompt.ask("  [bold white]Select action[/bold white]", choices=["1", "2", "3", "4"], default="1")

    if choice == '1':
        _launch_hostrecon()
        post_recon_interactive()

    elif choice == '2':
        _launch_brute()
        post_recon_interactive()

    elif choice == '3':
        _launch_hostrecon()
        post_recon_interactive()

    else:
        success_msg("Exiting NullProtocol. Happy Hunting!")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n  [bold red]Scan aborted by user.[/bold red]")
    except Exception as e:
        error_msg(f"Unexpected error: {e}")
