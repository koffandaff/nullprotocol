# Reliability & Edge Cases

NullProtocol is designed to handle the unpredictable nature of network scanning. This document outlines how we handle common failures and edge cases.

## Network & Connectivity

### 1. Host Unreachable (Offline)
- **Detection**: `IpHandler.py` performs an initial Ping.
- **Handling**: 
    - If ping fails, the host is marked as "DOWN".
    - **Edge Case**: Some firewalls block ICMP (Ping) but allow TCP.
    - **Fallback**: We warn the user ("No hosts responded to ping") but **proceed with scanning anyway** in case of firewall blocking (`-Pn` equivalent).

### 2. DNS Resolution Failures
- **Scenario**: `subdomain.py` finds a subdomain (e.g., `dev.example.com`) but it doesn't resolve to an IP.
- **Handling**: `DnsResolver.py` catches `socket.gaierror` and `subprocess.TimeoutExpired`. It prints an error but **does not crash**. The subdomain is simply skipped in the final IP list.

### 3. Tool Timeouts
- **Scenario**: A tool like `gobuster` hangs indefinitely due to a tarpit or slow server.
- **Handling**:
    - `run_tool_live` (in `utility.py` / `attack_chain.py`) reads output line-by-line.
    - We currently trust the tool's internal timeouts (e.g., `masscan --wait 0`, `nmap -T4`).
    - **Improvement Needed**: We should implement a strict Python-side timeout `subprocess.run(..., timeout=300)` to kill hung processes.

## Input Validation

### 1. Invalid Domains/IPs
- **Scenario**: User enters `http://example.com` instead of `example.com`.
- **Handling**: `main.py` checks for `://` and rejects the input immediately with an error message, preventing tools from breaking later.
- **Scenario**: User enters partial IP `192.168.1`.
- **Handling**: `IpExtraction.py` uses Regex to validate IP format. Invalid IPs are discarded before scanning starts.

## System Resources

### 1. Disk Space
- **Scenario**: Masscan produces a 10GB JSON file for a massive subnet.
- **Handling**: 
    - We interpret the JSON stream.
    - **Risk**: Python's `json.load` loads the whole file into RAM. This is a known limitation.
    - **Mitigation**: We only scan top 1000 ports to keep file sizes manageable.

### 2. Missing Tools
- **Scenario**: User runs the script but `sqlmap` is not installed.
- **Handling**:
    - `shutil.which('tool_name')` checks (in some modules, not all yet).
    - If a critical tool (Nmap) is missing, the script will error out or defined behavior in `install.sh` ensures they are present.
    - **Edge Case**: Verify your path. The script assumes tools are in `$PATH`.
