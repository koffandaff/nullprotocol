#!/usr/bin/env python3
"""
HostRecon — Professional Web Reporting Dashboard
Serves scan results on port 5000 with a Bootstrap 5 dark-themed UI.
Supports PDF export via browser print or wkhtmltopdf.
"""

import os
import sys
import json
import glob
from datetime import datetime
from flask import Flask, render_template, jsonify, send_file, request, abort
import subprocess

app = Flask(__name__,
            template_folder=os.path.join(os.path.dirname(__file__), 'templates'),
            static_folder=os.path.join(os.path.dirname(__file__), 'static'))

RESULTS_DIR = os.path.join(os.path.dirname(__file__), '..', 'results')


def get_all_scans():
    """Discover all scan result directories and their enhanced.json files."""
    scans = []
    if not os.path.exists(RESULTS_DIR):
        return scans

    for domain_dir in sorted(os.listdir(RESULTS_DIR), reverse=True):
        report_dir = os.path.join(RESULTS_DIR, domain_dir, 'FinalReport')
        json_path = os.path.join(report_dir, 'enhanced.json')
        report_path = os.path.join(report_dir, 'report.txt')

        if os.path.exists(json_path):
            try:
                with open(json_path, 'r') as f:
                    data = json.load(f)
                scans.append({
                    'domain': data.get('domain', domain_dir),
                    'dir_name': domain_dir,
                    'timestamp': data.get('timestamp', ''),
                    'web_count': data.get('web_targets_count', 0),
                    'service_count': data.get('service_targets_count', 0),
                    'ips_count': data.get('ips_count', 0),
                    'has_report': os.path.exists(report_path),
                    'has_ollama': bool(data.get('ollama_analysis')),
                })
            except Exception:
                continue

    return scans


def load_scan_data(domain_dir):
    """Load full enhanced.json for a scan."""
    json_path = os.path.join(RESULTS_DIR, domain_dir, 'FinalReport', 'enhanced.json')
    if not os.path.exists(json_path):
        return None
    with open(json_path, 'r') as f:
        return json.load(f)


def load_report_txt(domain_dir):
    """Load the plain-text report."""
    report_path = os.path.join(RESULTS_DIR, domain_dir, 'FinalReport', 'report.txt')
    if os.path.exists(report_path):
        with open(report_path, 'r') as f:
            return f.read()
    return None


# ─── ROUTES ────────────────────────────────────────────────

@app.route('/')
def index():
    """Dashboard — list all scans."""
    scans = get_all_scans()
    return render_template('index.html', scans=scans)


@app.route('/scan/<domain_dir>')
def scan_detail(domain_dir):
    """Detailed view for a single scan."""
    data = load_scan_data(domain_dir)
    if not data:
        abort(404)

    report_txt = load_report_txt(domain_dir)

    # Compute severity stats
    vuln_stats = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for wt in data.get('web_targets', []):
        for v in wt.get('vulnerabilities', []):
            sev = v.get('severity', 'low').lower()
            if sev in vuln_stats:
                vuln_stats[sev] += 1

    exploit_count = 0
    for src in ['web_targets', 'service_targets']:
        for item in data.get(src, []):
            exploit_count += len(item.get('exploits', []))

    # Crawler stats
    crawler_data = data.get('crawler', {})
    sqli_count = sum(len(c.get('potential_sqli', [])) for c in crawler_data.values()) if isinstance(crawler_data, dict) else 0

    return render_template('scan_detail.html',
                           data=data,
                           domain_dir=domain_dir,
                           report_txt=report_txt,
                           vuln_stats=vuln_stats,
                           exploit_count=exploit_count,
                           sqli_count=sqli_count)


@app.route('/api/scan/<domain_dir>')
def api_scan_data(domain_dir):
    """JSON API endpoint for scan data."""
    data = load_scan_data(domain_dir)
    if not data:
        return jsonify({'error': 'Scan not found'}), 404
    return jsonify(data)


@app.route('/export/pdf/<domain_dir>')
def export_pdf(domain_dir):
    """Export scan report to PDF using wkhtmltopdf or weasyprint."""
    data = load_scan_data(domain_dir)
    if not data:
        abort(404)

    report_txt = load_report_txt(domain_dir)
    vuln_stats = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for wt in data.get('web_targets', []):
        for v in wt.get('vulnerabilities', []):
            sev = v.get('severity', 'low').lower()
            if sev in vuln_stats:
                vuln_stats[sev] += 1

    exploit_count = sum(
        len(item.get('exploits', []))
        for src in ['web_targets', 'service_targets']
        for item in data.get(src, [])
    )

    crawler_data = data.get('crawler', {})
    sqli_count = sum(len(c.get('potential_sqli', [])) for c in crawler_data.values()) if isinstance(crawler_data, dict) else 0

    # Render the printable template
    html_content = render_template('report_print.html',
                                   data=data,
                                   report_txt=report_txt,
                                   vuln_stats=vuln_stats,
                                   exploit_count=exploit_count,
                                   sqli_count=sqli_count)

    # Try wkhtmltopdf, else return HTML for browser print
    pdf_path = os.path.join(RESULTS_DIR, domain_dir, 'FinalReport', 'report.pdf')
    html_path = os.path.join(RESULTS_DIR, domain_dir, 'FinalReport', 'report_export.html')

    with open(html_path, 'w') as f:
        f.write(html_content)

    try:
        subprocess.run(
            ['wkhtmltopdf', '--enable-local-file-access', html_path, pdf_path],
            capture_output=True, timeout=30
        )
        if os.path.exists(pdf_path):
            return send_file(pdf_path, as_attachment=True,
                           download_name=f"report_{data.get('domain', 'scan')}.pdf")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Fallback: return HTML (user can print to PDF from browser)
    return html_content


@app.route('/raw/<domain_dir>')
def raw_report(domain_dir):
    """Serve the raw text report."""
    report = load_report_txt(domain_dir)
    if not report:
        abort(404)
    return f'<pre style="background:#0d1117;color:#c9d1d9;padding:20px;font-family:monospace;white-space:pre-wrap;">{report}</pre>'


def start_hostrecon(port=5000):
    """Launch the HostRecon dashboard."""
    print(f"\n  🌐 HostRecon Dashboard starting on http://localhost:{port}")
    print(f"  📁 Serving results from: {os.path.abspath(RESULTS_DIR)}")
    print(f"  🔒 Press Ctrl+C to stop\n")
    app.run(host='0.0.0.0', port=port, debug=False)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='HostRecon — Web Reporting Dashboard')
    parser.add_argument('-p', '--port', type=int, default=5000, help='Port to serve on')
    args = parser.parse_args()
    start_hostrecon(args.port)
