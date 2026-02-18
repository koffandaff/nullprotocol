"""
DatabaseHandler — SQLite persistence layer for NullProtocol.

Provides ACID-compliant storage alongside the existing JSON output.
Uses Python's built-in sqlite3 module (no extra dependencies).
DB file: results/<domain>/FinalReport/nullprotocol.db
"""

import os
import json
import sqlite3
from datetime import datetime

try:
    from utility import success_msg, error_msg, info_msg, warning_msg
except (ImportError, ModuleNotFoundError):
    # Fallback: allow standalone usage (e.g. in tests where python-magic isn't installed)
    def success_msg(msg): print(f"[+] {msg}")
    def error_msg(msg):   print(f"[-] {msg}")
    def info_msg(msg):    print(f"[*] {msg}")
    def warning_msg(msg): print(f"[!] {msg}")


class DatabaseHandler:
    """Manages all SQLite database operations for NullProtocol scans."""

    # ──────────────────────────────────────────────────────────
    # SCHEMA
    # ──────────────────────────────────────────────────────────

    SCHEMA_SQL = """
    CREATE TABLE IF NOT EXISTS scans (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        domain          TEXT    NOT NULL,
        timestamp       TEXT    NOT NULL,
        status          TEXT    DEFAULT 'complete',
        subdomains_count INTEGER DEFAULT 0,
        ips_count       INTEGER DEFAULT 0,
        web_targets_count   INTEGER DEFAULT 0,
        service_targets_count INTEGER DEFAULT 0,
        scan_duration   REAL,
        ollama_analysis TEXT,
        created_at      TEXT    DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS hosts (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id     INTEGER NOT NULL,
        ip          TEXT    NOT NULL,
        hostname    TEXT,
        is_alive    INTEGER DEFAULT 1,
        os_guess    TEXT,
        FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS services (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        host_id         INTEGER NOT NULL,
        port            INTEGER,
        protocol        TEXT    DEFAULT 'tcp',
        service_name    TEXT,
        version         TEXT,
        banner          TEXT,
        raw_service     TEXT,
        FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS vulnerabilities (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        service_id  INTEGER,
        host_id     INTEGER,
        scan_id     INTEGER NOT NULL,
        source_type TEXT    DEFAULT 'web',
        vuln_type   TEXT,
        severity    TEXT,
        title       TEXT,
        description TEXT,
        cve_id      TEXT,
        FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE,
        FOREIGN KEY (host_id)    REFERENCES hosts(id)    ON DELETE CASCADE,
        FOREIGN KEY (scan_id)    REFERENCES scans(id)    ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS web_findings (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id         INTEGER NOT NULL,
        host_id         INTEGER,
        url             TEXT,
        ip              TEXT,
        port            TEXT,
        service         TEXT,
        technologies    TEXT,
        directories     TEXT,
        api_endpoints   TEXT,
        exploits        TEXT,
        FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
        FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS ip_analyses (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id         INTEGER NOT NULL,
        ip              TEXT,
        geolocation     TEXT,
        asn_info        TEXT,
        threat_intel    TEXT,
        port_analysis   TEXT,
        open_ports_count INTEGER DEFAULT 0,
        services_found  TEXT,
        FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS crawler_results (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id         INTEGER NOT NULL,
        url             TEXT,
        pages_crawled   INTEGER DEFAULT 0,
        forms_found     INTEGER DEFAULT 0,
        potential_sqli  TEXT,
        FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
    );

    -- Indexes for common queries
    CREATE INDEX IF NOT EXISTS idx_scans_domain    ON scans(domain);
    CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp);
    CREATE INDEX IF NOT EXISTS idx_hosts_scan_id   ON hosts(scan_id);
    CREATE INDEX IF NOT EXISTS idx_hosts_ip        ON hosts(ip);
    CREATE INDEX IF NOT EXISTS idx_services_host   ON services(host_id);
    CREATE INDEX IF NOT EXISTS idx_vulns_scan      ON vulnerabilities(scan_id);
    CREATE INDEX IF NOT EXISTS idx_vulns_severity  ON vulnerabilities(severity);
    CREATE INDEX IF NOT EXISTS idx_web_scan        ON web_findings(scan_id);
    CREATE INDEX IF NOT EXISTS idx_ip_scan         ON ip_analyses(scan_id);
    CREATE INDEX IF NOT EXISTS idx_crawler_scan    ON crawler_results(scan_id);
    """

    def __init__(self, db_path):
        """Initialize handler and create schema.

        Args:
            db_path: Full path to the .db file, e.g. results/example.com/FinalReport/nullprotocol.db
        """
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)

        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")

        self._create_schema()

    def _create_schema(self):
        """Create all tables and indexes if they don't exist."""
        self.conn.executescript(self.SCHEMA_SQL)
        self.conn.commit()

    def close(self):
        """Close the database connection."""
        if self.conn:
            self.conn.close()
            self.conn = None

    def __del__(self):
        self.close()

    # ──────────────────────────────────────────────────────────
    # HELPER
    # ──────────────────────────────────────────────────────────

    @staticmethod
    def _json_dump(obj):
        """Safely serialize an object to a JSON string."""
        if obj is None:
            return None
        try:
            return json.dumps(obj, default=str)
        except (TypeError, ValueError):
            return str(obj)

    @staticmethod
    def _json_load(text):
        """Safely deserialize a JSON string back to an object."""
        if text is None:
            return None
        try:
            return json.loads(text)
        except (json.JSONDecodeError, TypeError):
            return text

    @staticmethod
    def _parse_port(port_val):
        """ robustly extract an integer port from a value which might be int, str, or dirty str like '80/tcp'."""
        if port_val is None:
            return 0
        if isinstance(port_val, int):
            return port_val
        
        s = str(port_val).strip()
        if not s:
            return 0
        
        # Extract digits only
        digits = ''.join(filter(str.isdigit, s))
        if digits:
            try:
                return int(digits)
            except ValueError:
                return 0
        return 0

    # ──────────────────────────────────────────────────────────
    # WRITE — Individual Inserts
    # ──────────────────────────────────────────────────────────

    def insert_scan(self, domain, timestamp, status='complete',
                    subdomains_count=0, ips_count=0,
                    web_targets_count=0, service_targets_count=0,
                    scan_duration=None, ollama_analysis=None):
        """Insert a scan record and return its ID."""
        cur = self.conn.execute("""
            INSERT INTO scans (domain, timestamp, status,
                               subdomains_count, ips_count,
                               web_targets_count, service_targets_count,
                               scan_duration, ollama_analysis)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (domain, timestamp, status,
              subdomains_count, ips_count,
              web_targets_count, service_targets_count,
              scan_duration, ollama_analysis))
        self.conn.commit()
        return cur.lastrowid

    def insert_host(self, scan_id, ip, hostname=None, is_alive=True, os_guess=None):
        """Insert a host and return its ID."""
        cur = self.conn.execute("""
            INSERT INTO hosts (scan_id, ip, hostname, is_alive, os_guess)
            VALUES (?, ?, ?, ?, ?)
        """, (scan_id, ip, hostname, int(is_alive), os_guess))
        self.conn.commit()
        return cur.lastrowid

    def insert_service(self, host_id, port, protocol='tcp',
                       service_name=None, version=None,
                       banner=None, raw_service=None):
        """Insert a service/port and return its ID."""
        # Ensure port is clean int
        clean_port = self._parse_port(port)
        
        cur = self.conn.execute("""
            INSERT INTO services (host_id, port, protocol,
                                  service_name, version, banner, raw_service)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (host_id, clean_port, protocol, service_name, version, banner, raw_service))
        self.conn.commit()
        return cur.lastrowid

    def insert_vulnerability(self, scan_id, vuln_type=None, severity=None,
                              title=None, description=None, cve_id=None,
                              service_id=None, host_id=None, source_type='web'):
        """Insert a vulnerability finding."""
        cur = self.conn.execute("""
            INSERT INTO vulnerabilities (scan_id, service_id, host_id,
                                          source_type, vuln_type, severity,
                                          title, description, cve_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (scan_id, service_id, host_id, source_type,
              vuln_type, severity, title, description, cve_id))
        self.conn.commit()
        return cur.lastrowid

    def insert_web_finding(self, scan_id, url=None, ip=None, port=None,
                           service=None, technologies=None, directories=None,
                           api_endpoints=None, exploits=None, host_id=None):
        """Insert a web scan finding."""
        cur = self.conn.execute("""
            INSERT INTO web_findings (scan_id, host_id, url, ip, port, service,
                                       technologies, directories,
                                       api_endpoints, exploits)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (scan_id, host_id, url, ip, port, service,
              self._json_dump(technologies),
              self._json_dump(directories),
              self._json_dump(api_endpoints),
              self._json_dump(exploits)))
        self.conn.commit()
        return cur.lastrowid

    def insert_ip_analysis(self, scan_id, ip, geolocation=None,
                           asn_info=None, threat_intel=None,
                           port_analysis=None, open_ports_count=0,
                           services_found=None):
        """Insert an IP analysis record."""
        cur = self.conn.execute("""
            INSERT INTO ip_analyses (scan_id, ip, geolocation, asn_info,
                                      threat_intel, port_analysis,
                                      open_ports_count, services_found)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (scan_id, ip,
              self._json_dump(geolocation),
              self._json_dump(asn_info),
              self._json_dump(threat_intel),
              self._json_dump(port_analysis),
              open_ports_count,
              self._json_dump(services_found)))
        self.conn.commit()
        return cur.lastrowid

    def insert_crawler_result(self, scan_id, url, pages_crawled=0,
                               forms_found=0, potential_sqli=None):
        """Insert a crawler/SQLi result."""
        cur = self.conn.execute("""
            INSERT INTO crawler_results (scan_id, url, pages_crawled,
                                          forms_found, potential_sqli)
            VALUES (?, ?, ?, ?, ?)
        """, (scan_id, url, pages_crawled, forms_found,
              self._json_dump(potential_sqli)))
        self.conn.commit()
        return cur.lastrowid

    # ──────────────────────────────────────────────────────────
    # WRITE — Bulk: save a full scan from all_results dict
    # ──────────────────────────────────────────────────────────

    def save_full_scan(self, all_results):
        """Decompose the comprehensive scan dict into normalized DB rows.

        This is the main entry point called from ReconEnhancer.run_comprehensive_scan().
        It takes the same `all_results` dict that gets written to enhanced.json and
        normalizes it across the 7 tables.

        Args:
            all_results: The all_results dict built by run_comprehensive_scan()

        Returns:
            The scan_id of the newly inserted scan.
        """
        try:
            # 1. Insert the scan record
            scan_id = self.insert_scan(
                domain=all_results.get('domain', 'unknown'),
                timestamp=all_results.get('timestamp', datetime.now().isoformat()),
                status='complete',
                subdomains_count=all_results.get('subdomains_count', 0),
                ips_count=all_results.get('ips_count', 0),
                web_targets_count=all_results.get('web_targets_count', 0),
                service_targets_count=all_results.get('service_targets_count', 0),
                scan_duration=all_results.get('scan_duration'),
                ollama_analysis=all_results.get('ollama_analysis')
            )

            # Track IPs → host_ids so we can link services/vulns
            ip_to_host_id = {}

            # 2. Web targets → web_findings + hosts + services + vulns
            for wt in all_results.get('web_targets', []):
                target = wt.get('target', {})
                ip = target.get('ip', '')
                port = target.get('port', '')
                url = target.get('url', '')

                # Ensure host exists
                if ip and ip not in ip_to_host_id:
                    host_id = self.insert_host(scan_id, ip)
                    ip_to_host_id[ip] = host_id

                host_id = ip_to_host_id.get(ip)

                # Insert service for this web target
                service_id = None
                if host_id and port:
                    clean_port = self._parse_port(port)
                    service_id = self.insert_service(
                        host_id=host_id,
                        port=clean_port,
                        service_name=target.get('service', ''),
                        version=target.get('version', ''),
                        raw_service=target.get('raw_service', '')
                    )

                # Insert web finding
                self.insert_web_finding(
                    scan_id=scan_id,
                    url=url,
                    ip=ip,
                    port=str(port),
                    service=target.get('service', ''),
                    technologies=wt.get('technologies'),
                    directories=wt.get('directories'),
                    api_endpoints=wt.get('api_endpoints'),
                    exploits=wt.get('exploits'),
                    host_id=host_id
                )

                # Insert vulnerabilities found on this web target
                for vuln in wt.get('vulnerabilities', []):
                    self.insert_vulnerability(
                        scan_id=scan_id,
                        vuln_type=vuln.get('type', ''),
                        severity=vuln.get('severity', 'low'),
                        title=vuln.get('type', ''),
                        description=vuln.get('description', ''),
                        cve_id=vuln.get('cve', ''),
                        service_id=service_id,
                        host_id=host_id,
                        source_type='web'
                    )

            # 3. Service targets → hosts + services + vulns
            for st in all_results.get('service_targets', []):
                target = st.get('target', {})
                ip = target.get('ip', '')
                port = target.get('port', '')

                # Ensure host exists
                if ip and ip not in ip_to_host_id:
                    host_id = self.insert_host(scan_id, ip)
                    ip_to_host_id[ip] = host_id

                host_id = ip_to_host_id.get(ip)

                # Insert service
                service_id = None
                if host_id and port:
                    clean_port = self._parse_port(port)
                    service_id = self.insert_service(
                        host_id=host_id,
                        port=clean_port,
                        service_name=target.get('service', ''),
                        version=target.get('version', ''),
                        raw_service=target.get('raw_service', '')
                    )

                # Insert exploits as vulnerability records
                for exploit in st.get('exploits', []):
                    self.insert_vulnerability(
                        scan_id=scan_id,
                        vuln_type=exploit.get('attack_vector', ''),
                        severity=exploit.get('severity', 'medium'),
                        title=exploit.get('title', ''),
                        description=exploit.get('description', ''),
                        cve_id=exploit.get('cve', ''),
                        service_id=service_id,
                        host_id=host_id,
                        source_type='service'
                    )

            # 4. IP analyses → ip_analyses
            for ip_data in all_results.get('ip_analyses', []):
                ip_info = ip_data.get('ip_info', {})
                ip_addr = ip_info.get('ip', '')
                self.insert_ip_analysis(
                    scan_id=scan_id,
                    ip=ip_addr,
                    geolocation=ip_info.get('geolocation'),
                    asn_info=ip_info.get('asn_info'),
                    threat_intel=ip_info.get('threat_intelligence'),
                    port_analysis=ip_data.get('port_analysis'),
                    open_ports_count=ip_data.get('open_ports_count', 0),
                    services_found=ip_data.get('services_found')
                )

            # 5. Crawler results → crawler_results
            crawler_data = all_results.get('crawler', {})
            if isinstance(crawler_data, dict):
                for url, data in crawler_data.items():
                    self.insert_crawler_result(
                        scan_id=scan_id,
                        url=url,
                        pages_crawled=data.get('pages_crawled', 0),
                        forms_found=data.get('forms_found', 0),
                        potential_sqli=data.get('potential_sqli')
                    )

            info_msg(f"Scan saved to database (scan_id={scan_id})")
            return scan_id

        except Exception as e:
            error_msg(f"Database save failed: {e}")
            return None

    # ──────────────────────────────────────────────────────────
    # READ — Query Methods
    # ──────────────────────────────────────────────────────────

    def get_all_scans(self):
        """Get a summary list of all scans (for dashboard listing).

        Returns:
            List of dicts with keys matching what hostrecon.get_all_scans() returns.
        """
        rows = self.conn.execute("""
            SELECT id, domain, timestamp, status,
                   subdomains_count, ips_count,
                   web_targets_count, service_targets_count,
                   ollama_analysis
            FROM scans
            ORDER BY timestamp DESC
        """).fetchall()

        scans = []
        for row in rows:
            scans.append({
                'id': row['id'],
                'domain': row['domain'],
                'timestamp': row['timestamp'],
                'status': row['status'],
                'subdomains_count': row['subdomains_count'],
                'ips_count': row['ips_count'],
                'web_targets_count': row['web_targets_count'] or 0,
                'service_targets_count': row['service_targets_count'] or 0,
                'web_count': row['web_targets_count'] or 0,
                'service_count': row['service_targets_count'] or 0,
                'has_ollama': bool(row['ollama_analysis']),
            })
        return scans

    def get_scan_by_id(self, scan_id):
        """Get a single scan record by ID."""
        row = self.conn.execute(
            "SELECT * FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
        return dict(row) if row else None

    def get_hosts_for_scan(self, scan_id):
        """Get all hosts for a scan."""
        rows = self.conn.execute(
            "SELECT * FROM hosts WHERE scan_id = ?", (scan_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_services_for_host(self, host_id):
        """Get all services for a host."""
        rows = self.conn.execute(
            "SELECT * FROM services WHERE host_id = ?", (host_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_vulnerabilities_for_scan(self, scan_id):
        """Get all vulnerabilities for a scan."""
        rows = self.conn.execute(
            "SELECT * FROM vulnerabilities WHERE scan_id = ?", (scan_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_web_findings_for_scan(self, scan_id):
        """Get all web findings for a scan."""
        rows = self.conn.execute(
            "SELECT * FROM web_findings WHERE scan_id = ?", (scan_id,)
        ).fetchall()
        results = []
        for r in rows:
            d = dict(r)
            d['technologies'] = self._json_load(d.get('technologies'))
            d['directories'] = self._json_load(d.get('directories'))
            d['api_endpoints'] = self._json_load(d.get('api_endpoints'))
            d['exploits'] = self._json_load(d.get('exploits'))
            results.append(d)
        return results

    def get_ip_analyses_for_scan(self, scan_id):
        """Get all IP analyses for a scan."""
        rows = self.conn.execute(
            "SELECT * FROM ip_analyses WHERE scan_id = ?", (scan_id,)
        ).fetchall()
        results = []
        for r in rows:
            d = dict(r)
            d['geolocation'] = self._json_load(d.get('geolocation'))
            d['asn_info'] = self._json_load(d.get('asn_info'))
            d['threat_intel'] = self._json_load(d.get('threat_intel'))
            d['port_analysis'] = self._json_load(d.get('port_analysis'))
            d['services_found'] = self._json_load(d.get('services_found'))
            results.append(d)
        return results

    def get_crawler_results_for_scan(self, scan_id):
        """Get all crawler results for a scan."""
        rows = self.conn.execute(
            "SELECT * FROM crawler_results WHERE scan_id = ?", (scan_id,)
        ).fetchall()
        results = []
        for r in rows:
            d = dict(r)
            d['potential_sqli'] = self._json_load(d.get('potential_sqli'))
            results.append(d)
        return results

    # ──────────────────────────────────────────────────────────
    # READ — Full Reconstruction (same shape as enhanced.json)
    # ──────────────────────────────────────────────────────────

    def get_full_scan_as_dict(self, scan_id):
        """Reconstruct the full all_results dict from DB rows.

        This produces the EXACT same structure as enhanced.json so that
        hostrecon.py templates and brute/main.py work without changes.

        Args:
            scan_id: The database ID of the scan.

        Returns:
            A dict matching the enhanced.json layout, or None if not found.
        """
        scan = self.get_scan_by_id(scan_id)
        if not scan:
            return None

        # Web findings → web_targets list
        web_findings = self.get_web_findings_for_scan(scan_id)
        web_targets = []
        for wf in web_findings:
            # Get vulns linked to this web finding's host
            vulns = []
            if wf.get('host_id'):
                vuln_rows = self.conn.execute("""
                    SELECT * FROM vulnerabilities
                    WHERE host_id = ? AND scan_id = ? AND source_type = 'web'
                """, (wf['host_id'], scan_id)).fetchall()
                vulns = [{
                    'type': v['vuln_type'] or '',
                    'severity': v['severity'] or 'low',
                    'description': v['description'] or ''
                } for v in vuln_rows]

            web_targets.append({
                'target': {
                    'type': 'web',
                    'ip': wf.get('ip', ''),
                    'port': wf.get('port', ''),
                    'url': wf.get('url', ''),
                    'service': wf.get('service', ''),
                    'version': '',
                    'raw_service': wf.get('service', '')
                },
                'technologies': wf.get('technologies') or {},
                'directories': wf.get('directories') or [],
                'api_endpoints': wf.get('api_endpoints') or [],
                'vulnerabilities': vulns,
                'exploits': wf.get('exploits') or []
            })

        # Service targets
        service_targets = []
        svc_vulns = self.conn.execute("""
            SELECT v.*, s.port, s.service_name, s.version, s.raw_service,
                   h.ip
            FROM vulnerabilities v
            LEFT JOIN services s ON v.service_id = s.id
            LEFT JOIN hosts h ON v.host_id = h.id
            WHERE v.scan_id = ? AND v.source_type = 'service'
        """, (scan_id,)).fetchall()

        # Group by (ip, port) to reconstruct service target entries
        svc_groups = {}
        for sv in svc_vulns:
            key = (sv['ip'] or '', sv['port'] or '')
            if key not in svc_groups:
                svc_groups[key] = {
                    'target': {
                        'type': 'service',
                        'ip': sv['ip'] or '',
                        'port': str(sv['port'] or ''),
                        'service': sv['service_name'] or '',
                        'version': sv['version'] or '',
                        'raw_service': sv['raw_service'] or ''
                    },
                    'exploits': [],
                    'potential_attacks': []
                }
            svc_groups[key]['exploits'].append({
                'title': sv['title'] or '',
                'attack_vector': sv['vuln_type'] or '',
                'severity': sv['severity'] or 'medium',
                'description': sv['description'] or '',
                'cve': sv['cve_id'] or ''
            })
        service_targets = list(svc_groups.values())

        # Also add services that have no vulnerabilities
        all_hosts = self.get_hosts_for_scan(scan_id)
        for host in all_hosts:
            host_services = self.get_services_for_host(host['id'])
            for svc in host_services:
                key = (host['ip'], str(svc['port'] or ''))
                if key not in svc_groups:
                    # Check if this is a web service (skip, already in web_targets)
                    svc_name = (svc.get('service_name') or '').lower()
                    if svc_name in ('http', 'https', 'http-proxy', 'ssl/http'):
                        continue
                    service_targets.append({
                        'target': {
                            'type': 'service',
                            'ip': host['ip'],
                            'port': str(svc['port'] or ''),
                            'service': svc.get('service_name', ''),
                            'version': svc.get('version', ''),
                            'raw_service': svc.get('raw_service', '')
                        },
                        'exploits': [],
                        'potential_attacks': []
                    })

        # IP analyses
        ip_analyses_rows = self.get_ip_analyses_for_scan(scan_id)
        ip_analyses = []
        for row in ip_analyses_rows:
            ip_analyses.append({
                'ip_info': {
                    'ip': row.get('ip', ''),
                    'geolocation': row.get('geolocation') or {},
                    'asn_info': row.get('asn_info') or {},
                    'threat_intelligence': row.get('threat_intel') or {}
                },
                'port_analysis': row.get('port_analysis') or [],
                'open_ports_count': row.get('open_ports_count', 0),
                'services_found': row.get('services_found') or []
            })

        # Crawler results → dict keyed by URL
        crawler_rows = self.get_crawler_results_for_scan(scan_id)
        crawler_data = {}
        for cr in crawler_rows:
            crawler_data[cr['url']] = {
                'pages_crawled': cr.get('pages_crawled', 0),
                'forms_found': cr.get('forms_found', 0),
                'potential_sqli': cr.get('potential_sqli') or []
            }

        # Assemble the full dict
        result = {
            'domain': scan.get('domain', ''),
            'timestamp': scan.get('timestamp', ''),
            'subdomains_count': scan.get('subdomains_count', 0),
            'ips_count': scan.get('ips_count', 0),
            'web_targets_count': scan.get('web_targets_count', 0),
            'service_targets_count': scan.get('service_targets_count', 0),
            'web_targets': web_targets,
            'service_targets': service_targets,
            'ip_analyses': ip_analyses,
            'crawler': crawler_data,
            'ollama_analysis': scan.get('ollama_analysis'),
            'summary': {}
        }

        return result

    # ──────────────────────────────────────────────────────────
    # SEARCH
    # ──────────────────────────────────────────────────────────

    def search_scans(self, domain=None, date_from=None, date_to=None,
                     severity=None, limit=50):
        """Search scans with optional filters.

        Args:
            domain: Filter by domain (partial match).
            date_from: Filter scans after this ISO date.
            date_to: Filter scans before this ISO date.
            severity: Filter scans that have vulns of this severity.
            limit: Max results.

        Returns:
            List of scan summary dicts.
        """
        query = "SELECT DISTINCT s.* FROM scans s"
        conditions = []
        params = []

        if severity:
            query += " LEFT JOIN vulnerabilities v ON v.scan_id = s.id"
            conditions.append("LOWER(v.severity) = LOWER(?)")
            params.append(severity)

        if domain:
            conditions.append("s.domain LIKE ?")
            params.append(f"%{domain}%")
        if date_from:
            conditions.append("s.timestamp >= ?")
            params.append(date_from)
        if date_to:
            conditions.append("s.timestamp <= ?")
            params.append(date_to)

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY s.timestamp DESC LIMIT ?"
        params.append(limit)

        rows = self.conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def get_scan_statistics(self, scan_id):
        """Get aggregate statistics for a scan.

        Returns:
            Dict with counts for hosts, services, vulns by severity, etc.
        """
        stats = {}

        # Host count
        row = self.conn.execute(
            "SELECT COUNT(*) as cnt FROM hosts WHERE scan_id = ?", (scan_id,)
        ).fetchone()
        stats['hosts_count'] = row['cnt'] if row else 0

        # Service count
        row = self.conn.execute("""
            SELECT COUNT(*) as cnt FROM services s
            JOIN hosts h ON s.host_id = h.id
            WHERE h.scan_id = ?
        """, (scan_id,)).fetchone()
        stats['services_count'] = row['cnt'] if row else 0

        # Vuln counts by severity
        rows = self.conn.execute("""
            SELECT LOWER(severity) as sev, COUNT(*) as cnt
            FROM vulnerabilities WHERE scan_id = ?
            GROUP BY LOWER(severity)
        """, (scan_id,)).fetchall()
        stats['vulns_by_severity'] = {r['sev']: r['cnt'] for r in rows}
        stats['total_vulns'] = sum(stats['vulns_by_severity'].values())

        # Crawler SQLi count
        rows = self.conn.execute(
            "SELECT potential_sqli FROM crawler_results WHERE scan_id = ?",
            (scan_id,)
        ).fetchall()
        sqli_count = 0
        for r in rows:
            sqli = self._json_load(r['potential_sqli'])
            if isinstance(sqli, list):
                sqli_count += len(sqli)
        stats['sqli_targets'] = sqli_count

        return stats


# ──────────────────────────────────────────────────────────────
# MODULE-LEVEL HELPERS (for use by hostrecon/brute)
# ──────────────────────────────────────────────────────────────

def find_db_files(results_dir):
    """Find all nullprotocol.db files under a results directory.

    Args:
        results_dir: Path to the results/ directory.

    Returns:
        List of (domain_dir_name, db_path) tuples.
    """
    db_files = []
    if not os.path.exists(results_dir):
        return db_files

    for domain_dir in os.listdir(results_dir):
        db_path = os.path.join(results_dir, domain_dir, 'FinalReport', 'nullprotocol.db')
        if os.path.exists(db_path):
            db_files.append((domain_dir, db_path))

    return db_files
