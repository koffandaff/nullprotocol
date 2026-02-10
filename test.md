# Ollama WSL Connectivity Test

Save the Python code below as `test_ollama.py` in your WSL recon directory, then run it.

## Quick Test Script

```bash
# From your WSL terminal:
cd ~/projects/fsociety/recon
python3 test_ollama.py
```

## test_ollama.py

```python
#!/usr/bin/env python3
"""
Ollama WSL Connectivity Tester
Tests all possible routes from WSL to Ollama on your Windows host.
"""

import requests
import subprocess
import sys

HOSTS = [
    ("localhost",            "http://localhost:11434"),
    ("127.0.0.1",            "http://127.0.0.1:11434"),
    ("host.docker.internal", "http://host.docker.internal:11434"),
    ("10.0.2.2 (WSL1 NAT)", "http://10.0.2.2:11434"),
]

# Try to auto-detect WSL2 default gateway
try:
    gw = subprocess.check_output(
        "ip route show default | awk '{print $3}'",
        shell=True, text=True
    ).strip()
    if gw:
        HOSTS.insert(2, (f"WSL2 gateway ({gw})", f"http://{gw}:11434"))
except Exception:
    pass

print("=" * 60)
print("  OLLAMA CONNECTIVITY TEST")
print("=" * 60)
print()

# Check if Ollama is running on Windows first
print("[i] Make sure Ollama is running on Windows!")
print("    Open a Windows terminal and run: ollama serve")
print("    Or check system tray for the Ollama icon.")
print()

found = False
for name, url in HOSTS:
    try:
        r = requests.get(f"{url}/api/tags", timeout=3)
        if r.status_code == 200:
            models = [m['name'] for m in r.json().get('models', [])]
            print(f"[+] {name:25s} --> CONNECTED!")
            print(f"    URL: {url}")
            print(f"    Models: {', '.join(models) if models else 'None (run: ollama pull llama3)'}")
            found = True
        else:
            print(f"[-] {name:25s} --> HTTP {r.status_code}")
    except requests.exceptions.ConnectionError:
        print(f"[-] {name:25s} --> Connection refused")
    except requests.exceptions.Timeout:
        print(f"[-] {name:25s} --> Timeout")
    except Exception as e:
        print(f"[-] {name:25s} --> Error: {e}")

print()
if found:
    print("[+] SUCCESS! Ollama is reachable.")
    print("    NullProtocol will auto-detect this during scans.")
else:
    print("[!] FAILED! Ollama is NOT reachable from WSL.")
    print()
    print("    Troubleshooting steps:")
    print("    1. Start Ollama on Windows: ollama serve")
    print("    2. Check Windows Firewall allows port 11434")
    print("    3. Set Ollama to listen on all interfaces:")
    print("       set OLLAMA_HOST=0.0.0.0  (in Windows env vars)")
    print("       Then restart Ollama")
    print("    4. Pull a model: ollama pull llama3")
    print()

    # Quick network debug
    print("  --- Network Debug Info ---")
    try:
        gw = subprocess.check_output(
            "ip route show default | awk '{print $3}'",
            shell=True, text=True
        ).strip()
        print(f"    WSL Gateway: {gw}")
    except Exception:
        print("    WSL Gateway: Could not detect")

    try:
        ip = subprocess.check_output(
            "hostname -I | awk '{print $1}'",
            shell=True, text=True
        ).strip()
        print(f"    WSL IP:      {ip}")
    except Exception:
        print("    WSL IP:      Could not detect")
```

## What to do based on results

| Result | Action |
|--------|--------|
| `CONNECTED` on any host | NullProtocol will auto-detect it. No action needed. |
| All `Connection refused` | Ollama isn't running. Start it: `ollama serve` on Windows |
| All `Timeout` | Firewall blocking port 11434. Add exception or set `OLLAMA_HOST=0.0.0.0` |
| No models found | Run `ollama pull llama3` on Windows |

## Important Note

**NullProtocol works fine WITHOUT Ollama!** Ollama only enhances the report with AI analysis.
Without it, you still get:
- Full port scanning (masscan + nmap)
- Web vulnerability scanning
- Exploit searching
- SQL injection crawling
- Complete HTML dashboard via HostRecon
