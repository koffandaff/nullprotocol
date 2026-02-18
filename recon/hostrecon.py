#!/usr/bin/env python3
"""
HostRecon -- Professional Web Reporting Dashboard
Serves scan results on port 5000 with a Bootstrap 5 dark-themed UI.
Supports PDF export via browser print or wkhtmltopdf.
"""

import os
import sys
import json
import glob
import shutil
from datetime import datetime
from flask import Flask, render_template, jsonify, send_file, request, abort, redirect, url_for
import subprocess

# SQLite database support
try:
    from db_handler import DatabaseHandler, find_db_files
    DB_AVAILABLE = True
except ImportError:
    DB_AVAILABLE = False

app = Flask(__name__,
            template_folder=os.path.join(os.path.dirname(__file__), 'templates'),
            static_folder=os.path.join(os.path.dirname(__file__), 'static'))

# Scan results are saved relative to CWD (e.g. recon/results/<domain>/FinalReport/)
# Try CWD-relative first, then fallback to script-relative paths
_cwd_results = os.path.join(os.getcwd(), 'results')
_script_results = os.path.join(os.path.dirname(__file__), 'results')
_parent_results = os.path.join(os.path.dirname(__file__), '..', 'results')

# Pick whichever path actually exists
if os.path.isdir(_cwd_results):
    RESULTS_DIR = _cwd_results
elif os.path.isdir(_script_results):
    RESULTS_DIR = _script_results
else:
    RESULTS_DIR = _parent_results


def get_all_scans():
    """Discover all scan results. Tries SQLite first, falls back to JSON."""
    scans = []
    if not os.path.exists(RESULTS_DIR):
        return scans

    # Track which domain_dirs we've already loaded from DB
    loaded_dirs = set()

    # ── Try SQLite databases first ──
    if DB_AVAILABLE:
        for domain_dir in sorted(os.listdir(RESULTS_DIR), reverse=True):
            db_path = os.path.join(RESULTS_DIR, domain_dir, 'FinalReport', 'nullprotocol.db')
            if os.path.exists(db_path):
                try:
                    db = DatabaseHandler(db_path)
                    db_scans = db.get_all_scans()
                    for s in db_scans:
                        report_path = os.path.join(RESULTS_DIR, domain_dir, 'FinalReport', 'report.txt')
                        s['dir_name'] = domain_dir
                        s['has_report'] = os.path.exists(report_path)
                        scans.append(s)
                    loaded_dirs.add(domain_dir)
                    db.close()
                except Exception:
                    pass

    # ── JSON fallback for dirs without a DB ──
    for domain_dir in sorted(os.listdir(RESULTS_DIR), reverse=True):
        if domain_dir in loaded_dirs:
            continue
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
    """Load full scan data. Tries SQLite first, falls back to JSON."""
    report_dir = os.path.join(RESULTS_DIR, domain_dir, 'FinalReport')

    # ── Try SQLite first ──
    if DB_AVAILABLE:
        db_path = os.path.join(report_dir, 'nullprotocol.db')
        if os.path.exists(db_path):
            try:
                db = DatabaseHandler(db_path)
                # Get the most recent scan in this DB
                db_scans = db.get_all_scans()
                if db_scans:
                    data = db.get_full_scan_as_dict(db_scans[0]['id'])
                    db.close()
                    if data:
                        return data
                db.close()
            except Exception:
                pass

    # ── JSON fallback ──
    json_path = os.path.join(report_dir, 'enhanced.json')
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


def load_brute_results(domain_dir):
    """Load brute force results if they exist."""
    brute_path = os.path.join(RESULTS_DIR, domain_dir, 'BruteForce', 'brute_results.json')
    if os.path.exists(brute_path):
        try:
            with open(brute_path, 'r') as f:
                return json.load(f)
        except Exception:
            return None
    return None


# ─── ROUTES ────────────────────────────────────────────────

@app.route('/scan/<domain_dir>/delete', methods=['POST'])
def delete_scan(domain_dir):
    """Permanently delete a scan's result directory."""
    # Security: validate domain_dir has no path traversal
    if '..' in domain_dir or '/' in domain_dir or '\\' in domain_dir:
        abort(400)

    scan_path = os.path.join(RESULTS_DIR, domain_dir)
    if not os.path.isdir(scan_path):
        abort(404)

    try:
        shutil.rmtree(scan_path)
        return redirect(url_for('index'))
    except Exception as e:
        return jsonify({'error': f'Failed to delete: {e}'}), 500


@app.route('/')
def index():
    """Dashboard -- list all scans."""
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

    # Brute force results
    brute_results = load_brute_results(domain_dir)
    brute_success_count = 0
    if brute_results:
        brute_success_count = sum(1 for r in brute_results if r.get('result', {}).get('success'))

    return render_template('scan_detail.html',
                           data=data,
                           domain_dir=domain_dir,
                           report_txt=report_txt,
                           vuln_stats=vuln_stats,
                           exploit_count=exploit_count,
                           sqli_count=sqli_count,
                           brute_results=brute_results,
                           brute_success_count=brute_success_count)


@app.route('/api/scan/<domain_dir>')
def api_scan_data(domain_dir):
    """JSON API endpoint for scan data."""
    data = load_scan_data(domain_dir)
    if not data:
        return jsonify({'error': 'Scan not found'}), 404
    return jsonify(data)


@app.route('/api/search')
def api_search():
    """Search scans via SQLite database.
    Query params: domain, severity, date_from, date_to
    """
    if not DB_AVAILABLE:
        return jsonify({'error': 'Database support not available'}), 501

    domain = request.args.get('domain')
    severity = request.args.get('severity')
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')

    all_results = []
    if os.path.exists(RESULTS_DIR):
        for domain_dir in os.listdir(RESULTS_DIR):
            db_path = os.path.join(RESULTS_DIR, domain_dir, 'FinalReport', 'nullprotocol.db')
            if os.path.exists(db_path):
                try:
                    db = DatabaseHandler(db_path)
                    results = db.search_scans(
                        domain=domain,
                        severity=severity,
                        date_from=date_from,
                        date_to=date_to
                    )
                    for r in results:
                        r['dir_name'] = domain_dir
                    all_results.extend(results)
                    db.close()
                except Exception:
                    continue

    return jsonify(all_results)


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

    # Brute force results for PDF
    brute_results = load_brute_results(domain_dir)
    brute_success_count = sum(1 for r in brute_results if r.get('result', {}).get('success')) if brute_results else 0

    # Render the printable template
    html_content = render_template('report_print.html',
                                   data=data,
                                   report_txt=report_txt,
                                   vuln_stats=vuln_stats,
                                   exploit_count=exploit_count,
                                   sqli_count=sqli_count,
                                   brute_results=brute_results,
                                   brute_success_count=brute_success_count)

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
    print(f"\n  HostRecon Dashboard starting on http://localhost:{port}")
    print(f"  Serving results from: {os.path.abspath(RESULTS_DIR)}")
    print(f"  Press Ctrl+C to stop\n")
    app.run(host='0.0.0.0', port=port, debug=False)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='HostRecon -- Web Reporting Dashboard')
    parser.add_argument('-p', '--port', type=int, default=5000, help='Port to serve on')
    args = parser.parse_args()
    start_hostrecon(args.port)
