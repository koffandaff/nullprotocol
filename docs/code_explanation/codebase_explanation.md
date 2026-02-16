# Codebase Explanation

This document provides a detailed, line-by-line style explanation of the core modules in the NullProtocol codebase.

## 1. Core Orchestration (`recon/`)

### `recon/main.py`
**Purpose**: The entry point for the application.
- **Imports**: Imports handlers for Domain, IP, and Subdomain logic.
- **`main()`**: Displays the banner and interactive menu using `rich.prompt`.
- **Modes**:
    - **1. Domain Mode**: Accepts a domain, validates it (rejects `http://`), and calls `DomainHandler`.
    - **2. IP Mode**: Accepts single or comma-separated IPs, validates them, and calls `IpHandler`.
    - **3. View Previous Scans**: Launches `hostrecon.py` (Flask app) as a subprocess.
    - **4. Brute Force**: Transitions to `brute/main.py`.

### `recon/Domain.py`
**Purpose**: Orchestrates the workflow for Domain targets.
- **Flow**:
    1.  Calls `GetSubDomain` to enumerate subdomains.
    2.  Resolves IPs for all found subdomains using `IpConvertor` (system nslookup) and `IpConvertorSocket` (Python socket).
    3.  Creates a directory structure for the domain.
    4.  Saves `SubDomainReport` and `IPsReport`.
    5.  Passes the unique, resolved IPs to `IpHandler` for port scanning.

### `recon/IpHandler.py`
**Purpose**: Manages the scanning pipeline for IP addresses.
- **`IpHandler` Function**:
    1.  **Validation**: Filters invalid IPs using `Validate_Ip`.
    2.  **Enrichment**: Performs Reverse DNS and Ping (Alive check).
    3.  **Masscan**: Calls `IpMasscan` to scan top 1000 ports at high speed (25k pps).
    4.  **Nmap**: If Masscan finds ports, `IpNmapHandler` scans those specific ports for services/versions.
    5.  **Enhancement**: Passes results to `ReconEnhancer` for web analysis and exploit mapping.

### `recon/subdomain.py`
**Purpose**: Wrapper for external subdomain enumeration tools.
- **`SubDomain` Class**:
    - **`Dnsrecon`**: Runs `dnsrecon -d domain` and extracts results.
    - **`FindDomain`**: Runs `findomain -t domain` (very fast Rust tool).
- **Extraction**: Uses helper classes to parse the tool output into a clean list.

---

## 2. Advanced Analysis (`recon/ReconEnhancerTools/`)

### `exploit_searcher.py`
**Purpose**: Maps discovered services to potential vulnerabilities.
- **`attack_patterns`**: Dictionary of Regex patterns to classify vulnerability titles (e.g., "RCE", "SQL Injection").
- **`service_exploit_map`**: Maps service names (Apache, MySQL) to search keywords.
- **`search_exploits(service_name, version)`**: Uses `searchsploit` (Exploit-DB) via subprocess to find CVEs matching the service name and version.
- **Scoring**: Assigns a risk score (Crit/High/Med/Low) based on keywords in the exploit title.

### `web_scanner.py`
**Purpose**: specialized scanner for HTTP services.
- **Wordlists**: Smart detection of Kali wordlists (Dirb, Seclists).
- **`run_gobuster`**: Directory brute-forcing.
- **`run_whatweb`**: identifies technologies (CMS, Frameworks).
- **`check_sensitive_files`**: Checks for `robots.txt`, `.git`, `.env` etc.
- **`check_api_endpoints`**: Probes for common API paths like `/api/v1`, `/graphql`.

### `crawler.py`
**Purpose**: Custom Python-based crawler for SQL Injection targeting.
- **`crawl()`**: BFS crawler that visits pages up to a limit.
- **Extraction**:
    - Finds URLs with query parameters (`id=1`).
    - Finds HTML Forms (`<form>`).
- **`_identify_sqli_targets`**: Heuristics to identify parameters likely vulnerable to SQLi (e.g., `id`, `search`, `uid`).

---

## 3. Attack Automation (`brute/`)

### `brute/main.py`
**Purpose**: The "Active Attack" menu.
- **`load_recon_data`**: Reads `enhanced.json` from previous scans.
- **`identify_attack_opportunities`**: Parses the JSON to find actionable targets:
    - **SSH/FTP/MySQL**: Suggests Hydra.
    - **HTTP Params**: Suggests SQLMap.
    - **CVEs**: Suggests Metasploit.
- **Menu**: Allows user to select specific attacks to run.

### `brute/attack_chain.py`
**Purpose**: Wrappers for attack tools.
- Contains functions like `hydra_ssh`, `sqlmap_url`, `hping3_dos`.
- **`run_tool_live`**: crucial helper that runs a command and streams STDOUT in real-time to the console, so the user sees progress.
