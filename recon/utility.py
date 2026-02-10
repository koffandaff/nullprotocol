import sys
import os
import json
import mimetypes
import magic
import datetime
import re
import socket
import subprocess

# ──────────────────────────────────────────────────────────────
# RICH CONSOLE OUTPUT
# ──────────────────────────────────────────────────────────────
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.progress import (
    Progress, BarColumn, TextColumn,
    TimeRemainingColumn, TimeElapsedColumn,
    SpinnerColumn, TaskProgressColumn
)

console = Console()

def banner():
    """Display the NullProtocol ASCII banner with attribution."""
    console.print(f"\n[bold cyan]{'='*60}[/bold cyan]")
    console.print("[bold white]   ███╗   ██╗██╗   ██╗██╗     ██╗      [/bold white]")
    console.print("[bold white]   ████╗  ██║██║   ██║██║     ██║      [/bold white]")
    console.print("[bold white]   ██╔██╗ ██║██║   ██║██║     ██║      [/bold white]")
    console.print("[bold white]   ██║╚██╗██║██║   ██║██║     ██║      [/bold white]")
    console.print("[bold white]   ██║ ╚████║╚██████╔╝███████╗███████╗ [/bold white]")
    console.print("[bold white]   ╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚══════╝ [/bold white]")
    console.print("[bold cyan]            P R O T O C O L  v 2 . 0           [/bold cyan]")
    console.print("[bold white]       Dhruvil | github.com/koffandaff       [/bold white]")
    console.print(f"[bold cyan]{'='*60}[/bold cyan]\n")

def section_header(title, icon=""):
    """Print a styled section header."""
    console.print()
    label = f"  {icon}  {title}" if icon else f"  {title}"
    console.print(Panel(
        label,
        border_style="bright_cyan",
        style="bold white"
    ))

def status_msg(msg, style="green"):
    """Print a status message."""
    console.print(f"  [bold {style}]>[/bold {style}] {msg}")

def error_msg(msg):
    """Print an error message."""
    console.print(f"  [bold red][x][/bold red] {msg}")

def success_msg(msg):
    """Print a success message."""
    console.print(f"  [bold green][+][/bold green] {msg}")

def warning_msg(msg):
    """Print a warning message."""
    console.print(f"  [bold yellow][!][/bold yellow] {msg}")

def info_msg(msg):
    """Print an info message."""
    console.print(f"  [dim][i] {msg}[/dim]")

def get_progress_bar():
    """Return a pre-configured rich progress bar."""
    return Progress(
        SpinnerColumn("dots", style="cyan"),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(bar_width=30, style="cyan", complete_style="green"),
        TaskProgressColumn(),
        TextColumn("•", style="dim"),
        TimeRemainingColumn(),
        TextColumn("•", style="dim"),
        TimeElapsedColumn(),
        console=console,
    )

def make_table(title, columns, rows):
    """Build and print a rich table."""
    table = Table(title=title, border_style="cyan", show_lines=True)
    for col_name, col_style in columns:
        table.add_column(col_name, style=col_style)
    for row in rows:
        table.add_row(*[str(cell) for cell in row])
    console.print(table)

# ──────────────────────────────────────────────────────────────
# FILE UTILITIES
# ──────────────────────────────────────────────────────────────

def FileType(FileName):
    extension = os.path.splitext(FileName)[1].lower()

    if extension == ".json":
        try:
            with open(FileName, "r") as f:
                json.load(f)
            return "json"
        except Exception:
            pass

    elif extension == ".txt":
        return "txt"

    mime_type, _ = mimetypes.guess_type(FileName)
    if mime_type:
        return mime_type

    try:
        type_detector = magic.Magic(mime=True)
        return type_detector.from_file(FileName)
    except Exception:
        return "unknown"


def FileGenarator(domain):
    time = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    return domain + "_" + time


def Create_Domain_Directory(domain, subfolder=''):
    if subfolder:
        dir_path = os.path.join('results', domain, subfolder)
    else:
        dir_path = os.path.join('results', domain)

    os.makedirs(dir_path, exist_ok=True)
    return dir_path


# ──────────────────────────────────────────────────────────────
# IP VALIDATION & NETWORK HELPERS
# ──────────────────────────────────────────────────────────────

def Validate_Ip(ip_list):
    """Validate a list of IPs and return only valid ones."""
    valid_ips = []

    for ip in ip_list:
        ip = str(ip).strip()
        ip = ip.split('#')[0].split(':')[0]

        if '.' in ip:
            parts = ip.split('.')
            if len(parts) == 4:
                valid = True
                for part in parts:
                    if not part.isdigit() or not 0 <= int(part) <= 255:
                        valid = False
                        break
                if valid:
                    valid_ips.append(ip)
                    continue

        elif ':' in ip:
            parts = ip.split(':')
            if 2 <= len(parts) <= 8:
                valid = True
                for part in parts:
                    if part:
                        try:
                            int(part, 16)
                        except ValueError:
                            valid = False
                            break
                if valid:
                    valid_ips.append(ip)
                    continue

    return valid_ips


def reverse_dns(ip):
    """Perform reverse DNS lookup for an IP address."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return None


def is_host_alive(ip, timeout=2):
    """Check if a host is alive using ping."""
    try:
        result = subprocess.run(
            ['ping', '-c', '1', '-W', str(timeout), ip],
            capture_output=True, text=True, timeout=timeout + 2
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        return False


def enrich_ip_info(ip_list):
    """Enrich a list of IPs with reverse DNS and liveness check.
    Returns a list of dicts: {ip, hostname, alive}
    """
    enriched = []
    with get_progress_bar() as progress:
        task = progress.add_task("Enriching IPs", total=len(ip_list))
        for ip in ip_list:
            hostname = reverse_dns(ip) or "N/A"
            alive = is_host_alive(ip)
            enriched.append({
                'ip': ip,
                'hostname': hostname,
                'alive': alive
            })
            progress.update(task, advance=1)
    return enriched


if __name__ == "__main__":
    if len(sys.argv) > 1:
        filename = sys.argv[1]
        print(FileType(filename))
