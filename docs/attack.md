# Attack Commands & Methodologies

This document outlines the specific attack commands used by NullProtocol and the reasoning behind them. It includes manual commands, automated tool configurations, and relevant Metasploit modules for further exploitation.

## 1. Web Vulnerability Scanning & Exploitation

### SQL Injection (SQLMap)
**Command:**
```bash
sqlmap -u "TARGET_URL" --batch --level=2 --risk=1 --threads=10 --random-agent --tamper=between
```
**Why:**
- `--level=2`: Checks cookie-based injections.
- `--risk=1`: Avoids heavy queries that might break the application.
- `--tamper=between`: Obfuscates SQL keywords to bypass WAFs.
- `threads=10`: Accelerates the improved scan speed.

### Directory Brute Force (Gobuster)
**Command:**
```bash
gobuster dir -u TARGET_URL -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 50 --no-error -k
```
**Why:**
- Finding hidden admin panels, backups, and config files is critical for initial access.
- `-t 50`: High concurrency for speed.
- `-k`: Skips SSL verification (useful for internal/self-signed certs).

### Metasploit Modules (Web)
| Service | Module | Purpose |
|---------|--------|---------|
| **HTTP** | `auxiliary/scanner/http/http_version` | Identify server version |
| **HTTP** | `auxiliary/scanner/http/dir_scanner` | Directory enumeration |
| **HTTP** | `auxiliary/scanner/http/robots_txt` | Check robots.txt |
| **HTTP** | `exploit/multi/http/tomcat_mgr_upload` | Tomcat RCE via manager |
| **HTTP** | `auxiliary/scanner/http/wordpress_login_enum` | WP User Enum |
| **SSL** | `auxiliary/scanner/http/ssl` | SSL Certificate Info |

---

## 2. Infrastructure Brute Force (Hydra)

**Command Structure:**
```bash
hydra -L users.txt -P pass.txt -s PORT -t 16 -f -vV IP SERVICE
```
**Why:**
- `-t 16`: Parallel tasks for speed.
- `-f`: Stop on first found credential.
- `-s PORT`: Target specific non-standard ports.

### Metasploit Modules (Services)
| Service | Module | Purpose |
|---------|--------|---------|
| **SSH** | `auxiliary/scanner/ssh/ssh_login` | SSH Brute Force |
| **SSH** | `auxiliary/scanner/ssh/ssh_version` | SSH Version Info |
| **FTP** | `auxiliary/scanner/ftp/ftp_login` | FTP Brute Force |
| **FTP** | `auxiliary/scanner/ftp/anonymous` | Check Anonymous FTP |
| **SMB** | `auxiliary/scanner/smb/smb_login` | SMB Brute Force |
| **SMB** | `exploit/windows/smb/ms17_010_eternalblue` | EternalBlue Exploit |
| **MySQL** | `auxiliary/scanner/mysql/mysql_login` | MySQL Brute Force |
| **RDP** | `auxiliary/scanner/rdp/rdp_scanner` | Check RDP Encryption |
| **Telnet**| `auxiliary/scanner/telnet/telnet_login` | Telnet Brute Force |

---

## 3. Denial of Service (DoS)

### Packet Flood (hping3)
**Command:**
```bash
sudo timeout 60s hping3 -p PORT --flood -d 120 IP
```
**Why:**
- `--flood`: Sends packets as fast as possible, ignoring replies.
- `-d 120`: Payload size of 120 bytes (heavier than standard 0-byte SYN).
- `timeout 60s`: Sustained stress test to trigger rate limits or resource exhaustion.

### Synalize (Nmap)
**Command:**
```bash
nmap -Pn --script=dos IP
```
**Why:**
- Checks if the target is vulnerable to specific DoS conditions (like slowloris) without fully crashing it.

---

## 4. Manual Verification Steps

If automated tools find an issue, verify manually:

**SQL Injection:**
- Try adding `'` or `"` to parameters.
- Look for database errors in response.

**XSS:**
- Inject `<script>alert(1)</script>` into search bars/inputs.

**Open Ports:**
- Connect using Netcat: `nc -nv IP PORT` to see banners.
