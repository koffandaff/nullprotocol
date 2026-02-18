# SQL Queries Reference — NullProtocol

All SQL queries used by the `DatabaseHandler` class in [`db_handler.py`](file:///e:/null_protocol/nullprotocol/recon/db_handler.py), organized by operation type.

## Write Operations

### `insert_scan` — Create a new scan record
**Used by:** `ReconEnhancer.run_comprehensive_scan()` via `save_full_scan()`
```sql
INSERT INTO scans (domain, timestamp, status,
                   subdomains_count, ips_count,
                   web_targets_count, service_targets_count,
                   scan_duration, ollama_analysis)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
```

### `insert_host` — Register a discovered host
**Used by:** `save_full_scan()` for each unique IP in web/service targets
```sql
INSERT INTO hosts (scan_id, ip, hostname, is_alive, os_guess)
VALUES (?, ?, ?, ?, ?)
```

### `insert_service` — Record an open port/service
**Used by:** `save_full_scan()` for each service in web/service targets
```sql
INSERT INTO services (host_id, port, protocol,
                      service_name, version, banner, raw_service)
VALUES (?, ?, ?, ?, ?, ?, ?)
```

### `insert_vulnerability` — Store a vulnerability finding
**Used by:** `save_full_scan()` for web vulns and service exploits
```sql
INSERT INTO vulnerabilities (scan_id, service_id, host_id,
                              source_type, vuln_type, severity,
                              title, description, cve_id)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
```

### `insert_web_finding` — Store web-specific scan data
**Used by:** `save_full_scan()` for each web target
```sql
INSERT INTO web_findings (scan_id, host_id, url, ip, port, service,
                           technologies, directories,
                           api_endpoints, exploits)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
```
> **Note:** `technologies`, `directories`, `api_endpoints`, `exploits` are JSON-serialized strings.

### `insert_ip_analysis` — Store IP intelligence data
**Used by:** `save_full_scan()` for each IP analysis
```sql
INSERT INTO ip_analyses (scan_id, ip, geolocation, asn_info,
                          threat_intel, port_analysis,
                          open_ports_count, services_found)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
```

### `insert_crawler_result` — Store crawler/SQLi findings
**Used by:** `save_full_scan()` for each crawled URL
```sql
INSERT INTO crawler_results (scan_id, url, pages_crawled,
                              forms_found, potential_sqli)
VALUES (?, ?, ?, ?, ?)
```

---

## Read Operations

### `get_all_scans` — List all scans for dashboard
**Used by:** `hostrecon.get_all_scans()`
```sql
SELECT id, domain, timestamp, status,
       subdomains_count, ips_count,
       web_targets_count, service_targets_count,
       ollama_analysis
FROM scans
ORDER BY timestamp DESC
```

### `get_scan_by_id` — single scan record
**Used by:** `get_full_scan_as_dict()`, `get_scan_statistics()`
```sql
SELECT * FROM scans WHERE id = ?
```

### `get_hosts_for_scan` — All hosts for a scan
**Used by:** `get_full_scan_as_dict()` (service target reconstruction)
```sql
SELECT * FROM hosts WHERE scan_id = ?
```

### `get_services_for_host` — Services on a host
**Used by:** `get_full_scan_as_dict()` (service-only targets without vulns)
```sql
SELECT * FROM services WHERE host_id = ?
```

### `get_vulnerabilities_for_scan` — All vulns for a scan
**Used by:** Unit tests, statistics
```sql
SELECT * FROM vulnerabilities WHERE scan_id = ?
```

### Web-specific vulnerability query
**Used by:** `get_full_scan_as_dict()` (web target reconstruction)
```sql
SELECT * FROM vulnerabilities
WHERE host_id = ? AND scan_id = ? AND source_type = 'web'
```

### Service vulnerability join
**Used by:** `get_full_scan_as_dict()` (service target reconstruction with exploit details)
```sql
SELECT v.*, s.port, s.service_name, s.version, s.raw_service, h.ip
FROM vulnerabilities v
LEFT JOIN services s ON v.service_id = s.id
LEFT JOIN hosts h ON v.host_id = h.id
WHERE v.scan_id = ? AND v.source_type = 'service'
```

### `get_web_findings_for_scan` — Web scan results
**Used by:** `get_full_scan_as_dict()`
```sql
SELECT * FROM web_findings WHERE scan_id = ?
```

### `get_ip_analyses_for_scan` — IP intelligence
**Used by:** `get_full_scan_as_dict()`
```sql
SELECT * FROM ip_analyses WHERE scan_id = ?
```

### `get_crawler_results_for_scan` — Crawler data
**Used by:** `get_full_scan_as_dict()`
```sql
SELECT * FROM crawler_results WHERE scan_id = ?
```

---

## Search Operations

### `search_scans` — Filtered scan search
**Used by:** `hostrecon` `/api/search` endpoint
```sql
-- Base query varies by filter combination
SELECT DISTINCT s.*
FROM scans s
LEFT JOIN vulnerabilities v ON v.scan_id = s.id   -- only if severity filter
WHERE s.domain LIKE ?           -- if domain filter
  AND s.timestamp >= ?          -- if date_from filter
  AND s.timestamp <= ?          -- if date_to filter
  AND LOWER(v.severity) = ?     -- if severity filter
ORDER BY s.timestamp DESC
LIMIT ?
```

---

## Statistics Operations

### `get_scan_statistics` — Aggregate counts for a scan
**Used by:** Unit tests, future dashboard enhancements

```sql
-- Host count
SELECT COUNT(*) as cnt FROM hosts WHERE scan_id = ?

-- Service count
SELECT COUNT(*) as cnt
FROM services s JOIN hosts h ON s.host_id = h.id
WHERE h.scan_id = ?

-- Vulnerability counts by severity
SELECT LOWER(severity) as sev, COUNT(*) as cnt
FROM vulnerabilities WHERE scan_id = ?
GROUP BY LOWER(severity)

-- SQLi target count
SELECT COUNT(*) as cnt
FROM crawler_results WHERE scan_id = ? AND potential_sqli IS NOT NULL
```

---

## Schema Management

### `_create_schema` — Table + index creation
**Used by:** `DatabaseHandler.__init__()`
```sql
-- Executes the full SCHEMA_SQL class variable containing all
-- CREATE TABLE IF NOT EXISTS and CREATE INDEX IF NOT EXISTS statements
```

### PRAGMA settings (set on every connection)
```sql
PRAGMA journal_mode=WAL      -- Write-Ahead Logging for better concurrency
PRAGMA foreign_keys=ON       -- Enforce referential integrity
```
