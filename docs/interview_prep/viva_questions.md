# Comprehensive Viva Questions (100+)

This document contains over 100 potential questions you might be asked during a project defense, interview, or viva, categorized by topic.

## 1. General Project Overview (1-10)

1.  **What is NullProtocol?**
    - A modular, automated reconnaissance and vulnerability scanning framework written in Python.
2.  **What problem does this project solve?**
    - It automates the tedious process of manual reconnaissance, port scanning, and vulnerability identification, saving time for security professionals.
3.  **Why did you choose Python?**
    - Python has extensive library support (`requests`, `socket`), is easy to read/modify, and integrates well with system tools via `subprocess`.
4.  **What is the difference between Passive and Active Reconnaissance?**
    - Passive: Gathering info without interacting directly (Whois, Shodan). Active: Touching the target (Port Scanning, DNS enumeration). NullProtocol does mostly Active recon.
5.  **Explain the modular architecture.**
    - We have `recon` (Info gathering), `brute` (Attacks), and `HostRecon` (Reporting). They are decoupled and communicate via JSON artifacts.
6.  **What is the role of `enhanced.json`?**
    - It acts as the central database/state file, storing all findings (IPs, ports, vulns) to be used by other modules.
7.  **Why not just use Nmap?**
    - Nmap is great but slow for large networks. We use Masscan for speed and chain it with Nmap for precision, plus we add web enumeration and exploit mapping.
8.  **What is the "Enhancer" module?**
    - It takes raw port data and adds context: identifying web technologies, finding CVEs (using Exploit-DB), and flagging high-value targets.
9.  **How do you handle error reporting?**
    - We use python's `try-except` blocks and print colored error messages to the console using the `rich` library.
10. **What is the difference between a Vulnerability Assessment and Penetration Testing?**
    - VA is finding flaws (what our tool mostly does). PT is exploiting them to prove impact (what our Brute Force module allows).

## 2. Networking Fundamentals (11-25)

11. **What is an IP address?**
    - A unique numerical label assigned to each device connected to a computer network (e.g., 192.168.1.1).
12. **What is a Subnet Mask?**
    - It divides the IP address into network and host portions. `/24` means 255.255.255.0.
13. **Explain the 3-Way Handshake.**
    - SYN (Client) -> SYN-ACK (Server) -> ACK (Client). It establishes a reliable TCP connection.
14. **What is the difference between TCP and UDP?**
    - TCP is connection-oriented and reliable (HTTP, SSH). UDP is connectionless and faster but unreliable (DNS, Streaming).
15. **What is a Port?**
    - A communication endpoint. There are 65,535 ports. 0-1023 are well-known ports.
16. **What runs on Port 80, 443, 22, 21, 53?**
    - 80: HTTP, 443: HTTPS, 22: SSH, 21: FTP, 53: DNS.
17. **What is DNS?**
    - Domain Name System. It translates human-readable domain names (google.com) into IP addresses (142.250.x.x).
18. **What is a "Socket" in programming?**
    - An endpoint for sending/receiving data across a network. In Python, `socket` library creates these interfaces.
19. **What is "localhost"?**
    - The computer you are currently working on. Usually IP `127.0.0.1`.
20. **What is ARP?**
    - Address Resolution Protocol. Maps IP addresses to MAC addresses on a local network.
21. **What is ICMP?**
    - Internet Control Message Protocol. Used for diagnostics like `ping`.
22. **Why do some scans fail even if the host is up?**
    - Firewalls often block ICMP (Ping) or drop packets to specific ports (Filtered status).
23. **What is a "Reverse DNS" lookup?**
    - Finding the domain name associated with an IP address (PTR record).
24. **Difference between IPv4 and IPv6?**
    - IPv4 is 32-bit (4.3 billion addresses). IPv6 is 128-bit (practically infinite).
25. **What is a Proxy?**
    - An intermediary server separating the client from the destination server.

## 3. Python & Codebase Logic (26-45)

26. **What does `if __name__ == "__main__":` do?**
    - It ensures the code block only runs if the script is executed directly, not imported as a module.
27. **Explain `subprocess.run` vs `os.system`.**
    - `subprocess.run` is newer, more secure, and allows capturing output (stdout/stderr). `os.system` just runs a command in the shell.
28. **What relies on `requests` library in your code?**
    - The Crawler, Web Scanner, and Ollama module use it to make HTTP GET/POST requests.
29. **What is a Virtual Environment (`venv`)?**
    - An isolated environment to manage dependencies for a specific project without conflicting with system-wide packages.
30. **How do you handle multithreading in Python?**
    - We use `threading` or rely on the tools (Masscan/Hydra) to handle their own threads.
31. **What is the Global Interpreter Lock (GIL)?**
    - A mutex that allows only one thread to hold the control of the Python interpreter, limiting true parallelism in CPU-bound tasks.
32. **How does your Crawler avoid infinite loops?**
    - It uses a `set()` called `visited` to track URLs it has already seen.
33. **Why use `BeautifulSoup`?**
    - To parse HTML and extract specific tags like `<a>` (links) and `<form>` (inputs) easily.
34. **What is JSON?**
    - JavaScript Object Notation. A lightweight data-interchange format we use for storing scan results.
35. **What regex is used to find an IP address?**
    - Typically `\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`.
36. **What is the purpose of `requirements.txt`?**
    - Lists all Python dependencies so they can be installed via `pip install -r requirements.txt`.
37. **How does the `argparse` library work? (if utilized)**
    - It parses command-line arguments sent to the script (e.g., `--target 1.1.1.1`). (Note: We use `rich.prompt` interactive menus mostly).
38. **What is a Shebang (`#!/usr/bin/env python3`)?**
    - The first line in a script that tells the OS which interpreter to use to run the file.
39. **Explain the functionality of `xmltodict`.**
    - It converts XML (from Nmap output) into a Python Dictionary for easy key-value access.
40. **How do you validate a domain name input?**
    - We check if it contains `http://` (invalid for our tool) and potentially use regex to ensure it looks like `domain.tld`.
41. **What happens if a tool like Nmap is missing?**
    - The script might crash or throw a `FileNotFoundError` unless we check with `shutil.which()` first.
42. **Why use Classes vs Functions?**
    - Classes (OOP) help manage state (like `self.visited` in Crawler) better than passing variables between many functions.
43. **What is `sys.path.insert` used for?**
    - To add a directory to the Python path so we can import modules from sibling directories (e.g., importing `utility` from `recon` into `brute`).
44. **What is the `rich` library?**
    - A library for writing rich text (color, bold, tables, progress bars) to the terminal.
45. **How do you handle timeouts in Requests?**
    - We pass `timeout=5` to `requests.get()` so the script doesn't hang forever on a slow server.

## 4. Reconnaissance & Enumeration (46-65)

46. **What is Subdomain Enumeration?**
    - Finding valid subdomains (e.g., `admin.example.com`) for a main domain.
47. **How does `dnsrecon` work?**
    - It queries DNS servers for A, AAAA, CNAME, MX, and TXT records, and can also brute-force subdomains using a wordlist.
48. **What is `Findomain`?**
    - A very fast tool written in Rust that uses Certificate Transparency logs to find subdomains.
49. **Why do we resolve Subdomains to IPs?**
    - Because we can't port scan a "name"; we need the IP address where that name is hosted.
50. **What is scanning "Top 1000 ports"?**
    - Scanning the most statistically common open ports (80, 443, 22, etc.) rather than all 65,535.
51. **Why use Masscan instead of Nmap for the first pass?**
    - Masscan scans the entire internet in minutes (asyn-syn). Nmap is much slower. We use Masscan to find "alive" ports, then Nmap to interrogate them.
52. **What does Nmap `-sV` do?**
    - Service Version detection. Sends probes to open ports to determine what software (and version) is running.
53. **What does Nmap `-O` do?**
    - OS Detection. It analyzes IP packet fingerprints (TTL, Window Size) to guess the operating system.
54. **What does Nmap `-Pn` do?**
    - "Treat all hosts as online". Skips the initial Ping check. Useful if firewalls block Ping.
55. **What is "Banner Grabbing"?**
    - Connecting to a port and reading the initial text it sends (e.g., "SSH-2.0-OpenSSH_8.2").
56. **What is a "False Positive"?**
    - Reporting a vulnerability or open port that isn't actually there.
57. **What is a "tcpwrapped" service?**
    - When a TCP connection is established but immediately closed by the server (often a distinct firewall or TCP wrapper behavior).
58. **How do you identify a Web Server?**
    - Look for ports 80/443, or use tools like `whatweb` to identify headers/technologies.
59. **What is `robots.txt`?**
    - A file webmasters use to tell crawlers which parts of the site NOT to visit. It often reveals sensitive directories (`/admin`).
60. **What is Directory Brute Forcing?**
    - Guessing folder names (`/test`, `/backup`) by trying thousands of words from a list.
61. **What is a Wordlist?**
    - A text file containing common passwords, usernames, or directory names used for brute forcing.
62. **What is `rockyou.txt`?**
    - A famous wordlist containing millions of real leaked passwords.
63. **What is "Zone Transfer"?**
    - A DNS misconfiguration where a server gives you a copy of the entire domain's DNS records (AXFR).
64. **What is User-Agent spoofing?**
    - Changing the identity string browser sends to look like a legitimate user (e.g., pretending to be iPhone Safari).
65. **Why check for `.git` folders?**
    - If exposed, you can download the entire source code and history of the website.

## 5. Security & Exploitation (66-85)

66. **What is Vulnerability Assessment?**
    - The process of identifying, quantifying, and prioritizing vulnerabilities in a system.
67. **What is a CVE?**
    - Common Vulnerabilities and Exposures. A unique ID (CVE-2021-44228) for a known security flaw.
68. **What is Exploit-DB?**
    - A public archive of exploits and vulnerable software. `searchsploit` queries this offline.
69. **What is Brute Force Attack?**
    - Trying every possible password combination until the correct one is found.
70. **What is Hydra?**
    - A fast, parallelized login cracker supporting many protocols (SSH, FTP, HTTP, etc.).
71. **What is SQL Injection (SQLi)?**
    - Code injection that destroys/modifies your database. E.g., `SELECT * FROM users WHERE name = '' OR '1'='1'`.
72. **What is SQLMap?**
    - An automated tool that detects and exploits SQL injection flaws.
73. **What is Cross-Site Scripting (XSS)?**
    - Injecting malicious scripts into trusted websites. Stored, Reflected, and DOM-based.
74. **What is Denial of Service (DoS)?**
    - Flooding a service to make it unavailable to legitimate users.
75. **What is a SYN Flood?**
    - Sending thousands of SYN packets but never completing the handshake (never sending ACK), exhausting server resources.
76. **How does `hping3` perform DoS?**
    - It can send custom TCP/IP packets at a very high rate.
77. **What is Metasploit?**
    - A penetration testing framework for developing and executing exploit code against a remote target machine.
78. **What is a Payload?**
    - The part of the exploit code that performs the malicious action (e.g., creating a reverse shell).
79. **What is a Reverse Shell?**
    - When the victim machine initiates a connection back to the attacker's machine (bypassing inbound firewall rules).
80. **What is Privilige Escalation?**
    - Going from a low-level user account to root/admin.
81. **What is RCE?**
    - Remote Code Execution. The highest severity vulnerability—allows running commands on the server.
82. **What is "Dictionary Attack"?**
    - A type of brute force using a list of likely passwords instead of random characters.
83. **What are "Default Credentials"?**
    - Username/passwords that come with devices (admin/admin) that users forget to change.
84. **What is SSL/TLS?**
    - Encryption protocols for secure communication over a network (HTTPS).
85. **What is a "Hash"?**
    - A one-way mathematical function (MD5, SHA256) used to store passwords securely.

## 6. System & DevOps (86-95)

86. **How do you install dependencies in Python?**
    - `pip install package_name` or `pip install -r requirements.txt`.
87. **What is Linux?**
    - An open-source kernel/OS. Using Kali Linux is standard for penetration testing due to pre-installed tools.
88. **What is `chmod +x`?**
    - A command to make a file executable. Important for our `.sh` or `.py` scripts.
89. **What is Git?**
    - A version control system to track changes in code.
90. **What is the difference between `main` and a `branch`?**
    - `main` is production code. `branch` is for working on new features without breaking main.
91. **What is Docker?**
    - A platform for developing, shipping, and running applications in containers.
92. **Why might we Dockerize this tool?**
    - To ensure all dependencies (Nmap, Masscan, Python libs) work on any machine without complex installation.
93. **What is `sudo`?**
    - SuperUser DO. Runs commands with root privileges. Required for Masscan and hping3 (raw socket access).
94. **What are File Descriptors?**
    - Identifiers for open files/sockets. High-speed scanning can run out of these (ulimit).
95. **What is CI/CD?**
    - Continuous Integration/Deployment. Automating testing and deployment pipelines.

## 7. Ethics & Compliance (96-100+)

96. **Is it legal to scan any website?**
    - NO. You must have explicit written permission. Scanning without permission is illegal (CFAA in US, IT Act in India).
97. **What is Responsible Disclosure?**
    - Reporting a vulnerability to the vendor privately and giving them time to fix it before making it public.
98. **What is a Bug Bounty Program?**
    - Companies pay ethical hackers to find and report bugs (e.g., HackerOne).
99. **What is the difference between White Hat and Black Hat?**
    - White Hat: Ethical, legal. Black Hat: Malicious, illegal. Grey Hat: Borderline.
100. **Why is reporting important?**
    - Finding bugs is useless if you can't communicate the risk and fix to the stakeholders.
101. **What is GDPR?**
    - General Data Protection Regulation. Privacy law in EU. Relevant if we handle PII (Personally Identifiable Information).
102. **How can you mitigate the vulnerabilities found by your tool?**
    - Patch software (for CVEs), sanitize inputs (for SQLi/XSS), use strong passwords/MFA (for Brute Force), close unused ports.
