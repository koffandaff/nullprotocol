#!/usr/bin/env python3
"""
Ollama Integration — Local LLM for exploit analysis and report generation.
Communicates with Ollama running on WSL via its default REST API (port 11434).
"""

import requests
import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from utility import console, status_msg, success_msg, error_msg, warning_msg, info_msg

OLLAMA_HOSTS = [
    "http://10.0.2.2:11434",   # WSL default gateway (Windows host)
    "http://localhost:11434",   # Native / same-machine fallback
]

OLLAMA_BASE = None  # Will be set by is_ollama_available()


def is_ollama_available():
    """Check if Ollama is reachable. Tries WSL-to-Windows host IP first, then localhost."""
    global OLLAMA_BASE
    for host in OLLAMA_HOSTS:
        try:
            resp = requests.get(f"{host}/api/tags", timeout=3)
            if resp.status_code == 200:
                OLLAMA_BASE = host
                info_msg(f"Ollama detected at {host}")
                return True
        except Exception:
            continue
    return False


def get_available_models():
    """Return a list of available Ollama model names."""
    try:
        resp = requests.get(f"{OLLAMA_BASE}/api/tags", timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            return [m['name'] for m in data.get('models', [])]
    except Exception:
        pass
    return []


def ask_ollama(prompt, model=None, system_prompt=None, max_tokens=2048):
    """Send a prompt to Ollama and return the full response text.
    Uses the /api/generate endpoint (non-streaming for simplicity).
    """
    if not model:
        models = get_available_models()
        if not models:
            error_msg("No Ollama models available.")
            return None
        model = models[0]
        info_msg(f"Using model: {model}")

    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "num_predict": max_tokens,
            "temperature": 0.3,  # Lower temp for factual analysis
        }
    }

    if system_prompt:
        payload["system"] = system_prompt

    try:
        resp = requests.post(
            f"{OLLAMA_BASE}/api/generate",
            json=payload,
            timeout=120
        )
        if resp.status_code == 200:
            data = resp.json()
            return data.get('response', '')
        else:
            error_msg(f"Ollama returned status {resp.status_code}")
            return None
    except requests.exceptions.Timeout:
        error_msg("Ollama request timed out (120s)")
        return None
    except Exception as e:
        error_msg(f"Ollama error: {e}")
        return None


def analyze_findings_with_ollama(findings_json, model=None):
    """Send recon findings to Ollama for expert vulnerability analysis.
    Returns the LLM's analysis as a string.
    """
    system_prompt = """You are an expert penetration tester and cybersecurity analyst. 
You are analyzing reconnaissance findings from automated scanning tools.
Provide a structured, actionable analysis including:
1. CRITICAL FINDINGS - highest priority vulnerabilities
2. ATTACK SURFACE SUMMARY - what's exposed
3. RECOMMENDED EXPLOITS - specific tools and commands to use
4. REMEDIATION ADVICE - how to fix discovered issues
Be concise but thorough. Use technical language appropriate for a security professional."""

    # Truncate findings to avoid exceeding context limits
    findings_str = json.dumps(findings_json, indent=1)
    if len(findings_str) > 8000:
        findings_str = findings_str[:8000] + "\n... [truncated]"

    prompt = f"""Analyze these reconnaissance findings and provide a security assessment:

```json
{findings_str}
```

Provide your analysis with specific CVEs, exploit paths, and attack vectors where applicable."""

    return ask_ollama(prompt, model=model, system_prompt=system_prompt, max_tokens=4096)


def suggest_exploits_with_ollama(service_name, version, open_ports, model=None):
    """Ask Ollama to suggest specific exploits for a given service/version."""
    system_prompt = """You are an expert penetration tester. Given service information, 
suggest specific exploits, CVEs, and attack commands. Be precise and actionable.
Format your response as a numbered list with:
- CVE ID (if applicable)
- Exploit description
- Specific command to execute
- Severity rating (Critical/High/Medium/Low)"""

    prompt = f"""Service: {service_name}
Version: {version}
Open Ports: {', '.join([str(p) for p in open_ports]) if open_ports else 'N/A'}

List the top 5 most relevant and impactful exploits/vulnerabilities for this specific service and version.
Include specific commands using tools like metasploit, nmap scripts, hydra, or sqlmap where applicable."""

    return ask_ollama(prompt, model=model, system_prompt=system_prompt, max_tokens=2048)


def generate_report_html_with_ollama(findings_json, model=None):
    """Ask Ollama to generate professional HTML report code from findings.
    Returns HTML string.
    """
    system_prompt = """You are a web developer creating professional cybersecurity reports.
Generate clean, modern HTML with Bootstrap 5 styling. 
Include:
- Executive Summary section
- Findings table with severity colors
- Risk assessment chart description
- Recommendations section
Return ONLY the HTML code, no explanations."""

    findings_str = json.dumps(findings_json, indent=1)
    if len(findings_str) > 6000:
        findings_str = findings_str[:6000] + "\n... [truncated]"

    prompt = f"""Generate a professional HTML security assessment report from these findings:

```json
{findings_str}
```

Use Bootstrap 5, dark theme, professional styling. Make it look like an industry-grade penetration test report."""

    return ask_ollama(prompt, model=model, system_prompt=system_prompt, max_tokens=8192)


def interactive_ollama_check():
    """Interactively check Ollama availability and let user select a model.
    Returns (is_available, selected_model) tuple.
    """
    if is_ollama_available():
        models = get_available_models()
        if models:
            success_msg(f"Ollama detected with {len(models)} model(s): {', '.join(models[:5])}")
            
            from rich.prompt import Prompt
            use_ollama = Prompt.ask(
                "  [bold white]Use Ollama for AI-powered analysis?[/bold white]",
                choices=["y", "n"], default="y"
            )
            
            if use_ollama == 'y':
                if len(models) == 1:
                    return True, models[0]
                
                console.print()
                for i, m in enumerate(models, 1):
                    console.print(f"    [cyan]{i}[/cyan] -- {m}")
                console.print()
                
                choice = Prompt.ask(
                    "  [bold white]Select model number[/bold white]",
                    default="1"
                )
                try:
                    idx = int(choice) - 1
                    if 0 <= idx < len(models):
                        return True, models[idx]
                except ValueError:
                    pass
                return True, models[0]
        else:
            warning_msg("Ollama is running but no models found. Run: ollama pull llama3")
    else:
        info_msg("Ollama not detected on localhost:11434. Skipping AI analysis.")
    
    return False, None
