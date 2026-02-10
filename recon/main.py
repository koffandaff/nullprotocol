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
    status_msg, error_msg, success_msg, warning_msg
)
from rich.prompt import Prompt, IntPrompt, Confirm
import sys
import subprocess


def main():
    banner()

    console.print()
    console.print("  [bold cyan]1[/bold cyan]  →  I have a [bold]Domain Name[/bold]")
    console.print("  [bold cyan]2[/bold cyan]  →  I have an [bold]IP Address[/bold]")
    console.print()

    choice = Prompt.ask("  [bold white]Select mode[/bold white]", choices=["1", "2"], default="1")

    # ── Domain Mode ──
    if choice == '1':
        domain = Prompt.ask("  [bold white]Enter domain name[/bold white]")
        if '://' in domain:
            error_msg("Enter domain only (e.g. example.com), not a full URL.")
            return
        section_header(f"DOMAIN RECON — {domain}", "🌐")
        DomainHandler(domain)

    # ── IP Mode ──
    elif choice == '2':
        console.print()
        console.print("  [bold cyan]1[/bold cyan]  →  Single IP address")
        console.print("  [bold cyan]2[/bold cyan]  →  Multiple IPs (comma-separated)")
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

        section_header(f"IP RECON — {len(ips)} target(s)", "🎯")
        IpHandler(ips)

    # ── Chaining Logic ──
    post_recon_interactive()


def post_recon_interactive():
    """Prompt the user for next steps after reconnaissance finishes."""
    console.print()
    section_header("POST-RECON ACTIONS", "🛠️")
    console.print("  [bold cyan]1[/bold cyan]  →  Launch [bold]HostRecon[/bold] Web Dashboard")
    console.print("  [bold cyan]2[/bold cyan]  →  Start [bold]Brute Force[/bold] Attack Module")
    console.print("  [bold cyan]3[/bold cyan]  →  Exit")
    console.print()

    choice = Prompt.ask("  [bold white]Select action[/bold white]", choices=["1", "2", "3"], default="1")

    if choice == '1':
        success_msg("Launching HostRecon on http://localhost:5000...")
        info_msg("Press Ctrl+C to stop the web server and return to terminal.")
        try:
            # Run flask in a way that doesn't block entirely if possible, 
            # but for simplicity we'll just run it. 
            # Or use subprocess.Popen if we want it in background.
            subprocess.run([sys.executable, "hostrecon.py"])
        except KeyboardInterrupt:
            success_msg("Web server stopped.")
            post_recon_interactive()

    elif choice == '2':
        success_msg("Transitioning to Brute Force Module...")
        # Check if brute/main.py exists
        brute_path = os.path.join(os.path.dirname(__file__), '..', 'brute', 'main.py')
        if os.path.exists(brute_path):
            try:
                # We need to change directory to brute to ensure relative imports work there
                original_cwd = os.getcwd()
                os.chdir(os.path.join(os.path.dirname(__file__), '..', 'brute'))
                subprocess.run([sys.executable, "main.py"])
                os.chdir(original_cwd)
            except Exception as e:
                error_msg(f"Could not start Brute Force module: {e}")
        else:
            error_msg("Brute Force module not found at ../brute/main.py")
        
        post_recon_interactive()

    else:
        success_msg("Exiting NullProtocol. Happy Hunting!")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n  [bold red]⏹  Scan aborted by user.[/bold red]")
    except Exception as e:
        error_msg(f"Unexpected error: {e}")
