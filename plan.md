# Refactoring & Feature Expansion Plan

This document outlines the roadmap for refactoring the "Fsociety Recon Pipeline" and adding advanced features like Ollama integration, web reporting, and automated brute-forcing.

## 📋 Checklist & Tasks

### 1. Refactor IP Pipeline
**Goal**: Fix issues with IP-based scans (missing hostnames, error risks) and improve robustness.
- [ ] **Reverse DNS Lookup**: Implement `socket.gethostbyaddr()` to find hostnames for IPs.
- [ ] **Error Handling**: Add try-catch blocks for "Masscan" and "Nmap" execution failures.
- [ ] **Validation**: Ensure IPs are live before heavy scanning (ICMP ping check).
- [ ] **Files Affected**: `recon/IpHandler.py`, `recon/utility.py`, `recon/IpExtraction.py`.
- [ ] **Flow**: Input IPs -> Validation -> Reverse DNS -> Masscan -> Nmap -> ReconEnhancer.

### 2. Refactor ReconEnhancer (API & Clean-up)
**Goal**: Remove "garbage data", improve API testing, and fix result display.
- [ ] **Filter Noise**: Ignore 404s and non-informative HTTP responses in `WebScanner`.
- [ ] **Better API Discovery**: Use a curated wordlist and `ffuf` (if installed) or optimized Python `requests` for API endpoints.
- [ ] **Structured Output**: Ensure JSON output is strictly typed to avoid "garbage" strings.
- [ ] **Files Affected**: `recon/ReconEnhancer.py`, `recon/ReconEnhancerTools/web_scanner.py`.

### 3. & 4. Ollama Integration (Analysis & Exploit)
**Goal**: Use local LLM (Ollama) to analyze findings and suggest exploits.
- [ ] **Ollama Check**: Function to check if Ollama is running on default port.
- [ ] **Prompt Engineering**: Create prompts to feed scan results (open ports, services, versions) to Ollama.
- [ ] **Exploit Suggestion**: Ask Ollama to map found versions to CVEs or attack vectors.
- [ ] **User Prompt**: "Do you have Ollama installed? (y/n)"
- [ ] **Files Affected**: `recon/ReconEnhancer.py`, `recon/ReconEnhancerTools/ollama_handler.py` (NEW).

### 5. New Tool: Crawler for SQLMap
**Goal**: Crawl the site to find parameters susceptible to SQL injection.
- [ ] **Crawler Logic**: Use `BeautifulSoup` to find links with parameters (e.g., `?id=1`).
- [ ] **Forms Extraction**: Identify `<form>` inputs.
- [ ] **Integration**: Save potential SQLi targets to a file for the brute module or SQLMap.
- [ ] **Files Affected**: `recon/ReconEnhancerTools/crawler.py` (NEW), `recon/ReconEnhancer.py`.

### 6. HostRecon (Web Reporting)
**Goal**: Host a professional HTML Report on port 5000 with PDF export.
- [ ] **Flask App**: distinct `hostrecon.py` server.
- [ ] **Dynamic Templates**: Use `Jinja2` to render the JSON report into a Bootstrap dashboard.
- [ ] **Ollama Option**: If selected, use Ollama to generate an executive summary or code snippets for the report.
- [ ] **PDF Export**: Button to print the page to PDF (frontend JS or backend `weasyprint`).
- [ ] **Files Affected**: `recon/hostrecon.py` (NEW), `recon/templates/` (NEW), `recon/static/` (NEW).

### 7. Brute Force Module
**Goal**: Automated brute force attacks based on recon findings.
- [ ] **Chain of Attack**: Read `enhanced.json` -> Identify services (SSH, FTP, MySQL, HTTP forms).
- [ ] **User Permission**: "Found SSH on port 22. Launch Hydra? (y/n)".
- [ ] **Subprocess Execution**: Launch `hydra` or `sqlmap` with safe defaults.
- [ ] **Folder Structure**: `brute/` folder alongside `recon/`.
- [ ] **Files Affected**: `brute/main.py` (NEW), `brute/attack_chain.py` (NEW).

---

## 🏗️ New Flow
1.  **Recon Phase**:
    *   User inputs target.
    *   (Refactored) IP/Domain pipeline runs.
    *   (New) Crawler finds injection points.
    *   (Refactored) ReconEnhancer compiles data.
    *   (New) Ollama analyzes results (if enabled).
    *   Results saved to `results/<target>/FinalReport/enhanced.json`.
2.  **Reporting Phase**:
    *   `HostRecon` starts on port 5000.
    *   User views/exports Professional Report.
3.  **Attack Phase** (Optional):
    *   `Brute` module reads `enhanced.json`.
    *   Suggests attacks (SQLMap for crawled URLs, Hydra for open services).
    *   Executes attacks approved by user.

---

## 📦 Requirements Updates

### `requirements.txt`
```text
requests>=2.31.0
xmltodict>=0.13.0
python-magic>=0.4.27
rich>=13.7.0
flask>=3.0.0              # For HostRecon
beautifulsoup4>=4.12.0    # For Crawler
ollama>=0.1.0             # Python client for Ollama
weasyprint>=60.0          # For PDF Export (optional)
```

### `install.sh`
Added tools:
```bash
sudo apt install -y \
    hydra \
    sqlmap \
    ffuf \
    wkhtmltopdf # For PDF generation support if needed
```
