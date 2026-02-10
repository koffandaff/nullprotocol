#!/bin/bash
# ═══════════════════════════════════════════════════════
#  NullProtocol v2.0 — Full Installation Script
#  Automated Reconnaissance & Attack Pipeline
# ═══════════════════════════════════════════════════════

set -e

echo ""
echo "  ███╗   ██╗██╗   ██╗██╗     ██╗     "
echo "  ████╗  ██║██║   ██║██║     ██║     "
echo "  ██╔██╗ ██║██║   ██║██║     ██║     "
echo "  ██║╚██╗██║██║   ██║██║     ██║     "
echo "  ██║ ╚████║╚██████╔╝███████╗███████╗"
echo "  ╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚══════╝"
echo "       P R O T O C O L  v2.0"
echo "  Dhruvil | github.com/koffandaff"
echo "  Installer — Automated Recon Pipeline"
echo ""

# ─── System Update ────────────────────────────────────
echo "[1/7] Updating system packages..."
sudo apt update && sudo apt upgrade -y

# ─── Core Dependencies ────────────────────────────────
echo "[2/7] Installing core dependencies..."
sudo apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    git \
    wget \
    curl \
    unzip \
    libmagic-dev \
    jq

# ─── Security / Recon Tools ───────────────────────────
echo "[3/7] Installing security tools..."
sudo apt install -y \
    nmap \
    masscan \
    dnsrecon \
    gobuster \
    whatweb \
    nikto \
    exploitdb \
    seclists

# ─── New Tools (Brute Force + Fuzzing) ────────────────
echo "[4/7] Installing attack & fuzzing tools..."
sudo apt install -y \
    hydra \
    sqlmap \
    wkhtmltopdf

# Install ffuf (Go-based fuzzer)
if ! command -v ffuf &> /dev/null; then
    echo "  → Installing ffuf..."
    wget -q https://github.com/ffuf/ffuf/releases/latest/download/ffuf_2.1.0_linux_amd64.tar.gz -O /tmp/ffuf.tar.gz
    tar -xzf /tmp/ffuf.tar.gz -C /tmp/ ffuf
    sudo mv /tmp/ffuf /usr/local/bin/
    rm /tmp/ffuf.tar.gz
    echo "  → ffuf installed"
else
    echo "  → ffuf already installed"
fi

# ─── Findomain ────────────────────────────────────────
echo "[5/7] Installing Findomain..."
if ! command -v findomain &> /dev/null; then
    wget -q https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux.zip -O /tmp/findomain.zip
    unzip -qo /tmp/findomain.zip -d /tmp/
    chmod +x /tmp/findomain
    sudo mv /tmp/findomain /usr/local/bin/
    rm /tmp/findomain.zip
    echo "  → Findomain installed"
else
    echo "  → Findomain already installed"
fi

# ─── Python Libraries ─────────────────────────────────
echo "[6/7] Installing Python libraries..."
pip3 install --upgrade pip
pip3 install -r requirements.txt

# ─── Wordlists ────────────────────────────────────────
echo "[7/7] Downloading wordlists..."
mkdir -p wordlists

if [ ! -f "wordlists/common.txt" ]; then
    wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt -O wordlists/common.txt
    echo "  → common.txt downloaded"
fi

if [ ! -f "wordlists/subdomains.txt" ]; then
    wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt -O wordlists/subdomains.txt
    echo "  → subdomains.txt downloaded"
fi

if [ ! -f "wordlists/api-endpoints.txt" ]; then
    wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt -O wordlists/api-endpoints.txt 2>/dev/null || true
    echo "  → api-endpoints.txt downloaded"
fi

# ─── Permissions ──────────────────────────────────────
chmod +x recon/*.py 2>/dev/null || true
chmod +x brute/*.py 2>/dev/null || true

# ─── Ollama Notice ────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════"
echo "  ✓ Installation complete!"
echo ""
echo "  To use NullProtocol:"
echo "    cd recon && python3 main.py"
echo ""
echo "  To launch web reports:"
echo "    python3 recon/hostrecon.py"
echo ""
echo "  To run brute force module:"
echo "    python3 brute/main.py"
echo ""
echo "  ⚡ Optional: Install Ollama for AI analysis"
echo "    curl -fsSL https://ollama.com/install.sh | sh"
echo "    ollama pull llama3"
echo "═══════════════════════════════════════════════════"
