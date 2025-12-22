#!/bin/bash
# Fsociety Pentest Automation - Installer

echo "====================================================="
echo "   Fsociety Pentest Automation Installer By: KOFFAN  "
echo "====================================================="

echo "[*] Updating system packages..."
sudo apt update && sudo apt upgrade -y

echo "[*] Installing core dependencies..."
sudo apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    git \
    wget \
    curl \
    unzip \
    libmagic-dev

echo "[*] Installing security tools..."
sudo apt install -y \
    nmap \
    masscan \
    dnsrecon \
    gobuster \
    whatweb \
    exploitdb \
    seclists

echo "[*] Installing Findomain..."
wget -q https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux.zip
unzip -q findomain-linux.zip
chmod +x findomain
sudo mv findomain /usr/local/bin/
rm findomain-linux.zip

echo "[*] Installing Python libraries..."
pip3 install --upgrade pip
pip3 install requests xmltodict python-magic rich

echo "[*] Setting up directory structure..."
mkdir -p recon/results/{scans,reports,data}
mkdir -p wordlists

echo "[*] Downloading additional wordlists..."
if [ ! -f "wordlists/common.txt" ]; then
    wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt -O wordlists/common.txt
fi
if [ ! -f "wordlists/subdomains.txt" ]; then
    wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt -O wordlists/subdomains.txt
fi

echo "[*] Setting permissions..."
chmod +x recon/*.py
find recon/ -name "*.py" -exec chmod +x {} \;

echo "==========================================="
echo "[+] Installation complete!"
echo ""
echo "To start using Fsociety Pentest Automation:"
echo "1. cd recon"
echo "2. python3 main.py"
echo ""
echo "Available wordlists in 'wordlists/' directory:"
echo "- common.txt (for directory brute forcing)"
echo "- subdomains.txt (for subdomain discovery)"
echo "==========================================="
