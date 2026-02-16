# SQL Migration Plan

Currently, NullProtocol uses **JSON-based storage** (`enhanced.json`). While simple and portable, this has limitations for large-scale scanning or historical tracking. This document outlines a plan to migrate to a Relational Database (SQL).

## Why Migrate? (Pros/Cons)

| Feature | JSON (Current) | SQL (Proposed) |
| :--- | :--- | :--- |
| **Simplicity** | ✅ No setup required. Just files. | ❌ Requires DB installation (SQLite/Postgres). |
| **Querying** | ❌ Must load full file into RAM to filter. | ✅ SQL queries allow complex filtering/joins. |
| **History** | ❌ Overwrites old scans or creates messy duplicates. | ✅ Can easily track "First Seen" vs "Last Seen". |
| **Data Integrity** | ❌ prone to corruption if crash occurs during write. | ✅ ACID compliant transactions. |
| **Concurrency** | ❌ Multiple tools writing to JSON is hard. | ✅ Handles concurrent writes natively. |

## Proposed Schema

We recommend **SQLite** for local usage (single file, no server) or **PostgreSQL** for team usage.

### Tables

#### 1. `scans`
Tracks individual scan sessions.
- `id` (PK)
- `target_domain` (VARCHAR)
- `start_time` (DATETIME)
- `status` (VARCHAR: running/complete)

#### 2. `hosts`
Unique assets found.
- `id` (PK)
- `scan_id` (FK)
- `ip_address` (VARCHAR)
- `hostname` (VARCHAR)
- `is_alive` (BOOLEAN)
- `os_guess` (VARCHAR)

#### 3. `services`
Open ports on hosts.
- `id` (PK)
- `host_id` (FK)
- `port` (INT)
- `protocol` (VARCHAR: tcp/udp)
- `service_name` (VARCHAR: http, ssh)
- `version` (VARCHAR)
- `banner` (TEXT)

#### 4. `vulnerabilities`
Findings linked to services.
- `id` (PK)
- `service_id` (FK)
- `cve_id` (VARCHAR)
- `title` (VARCHAR)
- `severity` (VARCHAR: Critical/High/etc)
- `description` (TEXT)

#### 5. `web_findings`
Web-specific data.
- `id` (PK)
- `host_id` (FK)
- `url` (VARCHAR)
- `finding_type` (VARCHAR: directory, tech, header)
- `data` (JSON)

## Migration Strategy

1.  **Refactor `utility.py`**: Create a `DatabaseHandler` class.
2.  **Replace JSON Writes**: In `ReconEnhancer.py`, instead of `json.dump`, call `DatabaseHandler.insert_scan(...)`.
3.  **Update Dashboard**: Modify `hostrecon.py` to query SQL instead of reading JSON.
4.  **Backward Compatibility**: Keep an option `--output-json` to generate the old format for tools that expect it.
