# Success Metrics & Failure Criteria

This document defines how "Success" and "Failure" are determined for each attack module in NullProtocol. It explains the specific conditions that trigger a clean return versus an error state.

## 1. Web Vulnerability Scanning

### SQLMap (SQL Injection)
- **Success Criteria:** The tool identifies a specific injection point (parameter) and a backend DBMS type.
- **Return Value:** `True` (Injectable) if output contains:
  - "is vulnerable"
  - "sqlmap identified the following injection point"
  - "available databases"
- **Failure:** Tool completes but finds no injection points.
- **Note:** A "Success" here means the target is **confirmed vulnerable** to SQLi.

### Gobuster (Directory Brute Force)
- **Success Criteria:** At least one valid directory or file (Status 200/301/403) is discovered from the wordlist.
- **Return Value:** Count of `dirs_found`.
- **Failure:** No paths found, or connection timeout/refusal.
- **Metric:** "Success" means **hidden surface area was exposed**.

## 2. Infrastructure Brute Force (Hydra)

### SSH, FTP, RDP, MySQL, etc.
- **Success Criteria:** Valid credentials (username/password pair) are found.
- **Return Value:** `credentials_found` list is not empty.
- **Failure:** Wordlist exhausted without finding a match, or target locked out/connection refused.
- **Metric:** "Success" means **unauthorized access is possible**.

## 3. Vulnerability Scanning

### Nmap Vuln Scan
- **Success Criteria:** At least one CVE ID or "VULNERABLE" string is parsed from the script output.
- **Return Value:** `cves_found` list length > 0.
- **Failure:** Scan completes but reports no known vulnerabilities.
- **Metric:** "Success" indicates a **known CVE is present**.

## 4. Denial of Service (DoS)

### hping3 (Packet Flood)
- **Success Criteria:** The command executed successfully for the full duration (e.g., 60s) without being blocked by the local OS or failing to resolve the host.
- **Return Value:** "DoS Stress Test Completed".
- **Critical Note:**
  - **Success** here means the **Attack was Launched Successfully**.
  - It does **NOT** automatically mean the target went offline.
  - **Why?** Measuring target downtime requires an external monitor (like a separate ping check) which might be blocked by the same firewall handling the DoS.
  - **Effectiveness Metric:** You must manually check if the target's latency increases or if the service becomes unresponsive during the test.
  - **Failure:** `hping3` command fails (e.g., "Permission denied" if not root, or "Host not found").

### Nmap DoS Script
- **Success Criteria:** The script identifies a vulnerability (e.g., "VULNERABLE: Slowloris").
- **Return Value:** Vulnerability description found in output.
- **Failure:** Target is patched or resilient.

---

## Summary Table

| Tool | Success Condition | Failure Condition |
|------|-------------------|-------------------|
| **SQLMap** | Injection found | No injection |
| **Hydra** | Password cracked | List exhausted |
| **Gobuster** | Paths discovered | 0 paths / Error |
| **hping3** | **Packets SENT** | Command error |
| **Nmap** | CVEs found | System secure |

> **Note on DoS:** Unlike other tools where "Success" = "Vulnerability Found", for DoS tools "Success" typically implies "Test Completed". True impact verification is manual.
