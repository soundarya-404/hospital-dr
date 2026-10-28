# HospitalDR - tiered disaster-recovery drill (offline-capable)

Problem: keep critical hospital services recoverable even when the main data centre fails.
Synthetic data only. No internet is needed at runtime.

## Run (Windows / Mac / Linux)
```
pip install cryptography
python app.py
```
Open http://127.0.0.1:8000, sign in, click **Reset & load synthetic data**, then **Run full drill**.

Demo logins (synthetic environment only): `asha / admin@123` (Admin), `ravi / ops@123` (Operator), `meena / audit@123` (Auditor).

Optional settings (environment variables):
- `DR_DIR=D:\dr_site` sends backups to another disk/USB.
- `HTTPS=1` serves the dashboard over TLS with a self-signed certificate (data in transit). Windows PowerShell: `$env:HTTPS=1; python app.py`. The browser warns once; choose Advanced, then Continue.
- `REGION_PRIMARY` / `REGION_DR` change the declared data-residency labels (defaults: Mumbai / Hyderabad, simulated).
- `HOST=0.0.0.0` exposes it on the hospital LAN (demo PINs only; change them first).

## Mapping to the solution goals and success metrics
| Requirement | Where it is |
|---|---|
| Tiered recovery objective per system, justified clinically and by criticality | **Recovery objectives** tab (7 systems, 4 tiers) |
| Repeatable by a 3-person team, no specialist knowledge | One-click **Run full drill**, **Runbook** tab, **Drill history** card |
| 1. Measured recovery time and data loss vs target, live | Drill report table (RTO, RPO, rows lost, PASS/FAIL) |
| 2. Monthly standby cost relative to hospital budget | **Cost estimate** tab (editable assumptions) |
| 3. Runbook completeness - can a judge follow it | **Runbook** tab and `RUNBOOK.md` |
| 4. How failures are detected and reported | Health monitor (1 s), event log with detection latency, **Download report (.md)** |
| Data in India, encrypted at rest and in transit, synthetic only | **Security** tab (live checks; residency is declared, TLS via `HTTPS=1`) |
| Backup/restore limited to named roles and logged | Roles enforced on the server; **Audit log** tab (hash-chained) |

## What is real vs simulated
- Real: tiered SQLite databases, encrypted (Fernet: AES + HMAC) and checksummed backups, versioning, verification on restore, measured RTO/RPO, hash-chained audit log, role checks enforced server-side.
- Simulated: the "main data centre" and "DR site" are two folders on one machine; failure = deleting the primary files. Production would use two physical sites in India (for example Mumbai and Hyderabad regions) with TLS in transit and keys in a KMS.
- Scheduled demo backup intervals are shortened (10-60 s). The real targets/schedules are shown on each tier card.

## Files
- `app.py` - server, backup, restore, drill, monitor, audit log
- `static/index.html` - dashboard (no external libraries or CDNs, works offline)
- `RUNBOOK.md` - step-by-step recovery procedure

Built with AI assistance (disclose if asked); every part should be understood and explainable by the team.
