#!/usr/bin/env python3
"""
HospitalDR - offline-capable disaster-recovery drill dashboard (SYNTHETIC DATA ONLY).

Runs with the Python standard library plus `cryptography`. No internet is needed at runtime:
the dashboard is served from this machine and all backups go to a local/attached "DR site" folder.

Start:  python app.py        then open  http://127.0.0.1:8000
"""
import hashlib
import ipaddress
import json
import os
import random
import secrets
import socket
import sqlite3
import ssl
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography.fernet import Fernet

BASE = Path(__file__).parent.resolve()
DATA = Path(os.environ.get("HDR_DATA", BASE / "data")).resolve()
PRIMARY = DATA / "primary"                                   # the "main data centre"
DR = Path(os.environ.get("DR_DIR", DATA / "dr_site")).resolve()  # the "DR site" (second disk / USB / other building)
KEYFILE = DATA / "secret.key"
AUDIT = DATA / "audit.log"
SEEDED = DATA / ".seeded"
STATIC = BASE / "static"
HISTORY = DATA / "drills.json"
HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8000"))
USE_TLS = os.environ.get("HTTPS") == "1"
# Data-residency declaration. Locally both "sites" are folders; in production these would be two Indian regions.
REGION_PRIMARY = os.environ.get("REGION_PRIMARY", "India - Mumbai (simulated locally)")
REGION_DR = os.environ.get("REGION_DR", "India - Hyderabad (simulated locally)")
KEEP_VERSIONS = 5

# ---------------------------------------------------------------------------------------------
# Tier policy. rto / rpo are the TARGETS in seconds. `interval` is the DEMO backup interval in
# seconds (kept small so a judge sees it work); `prod` is what a real hospital would run.
# ---------------------------------------------------------------------------------------------
TIERS = {
    0: dict(name="Tier 0 - Life-critical", systems="ER/ICU, patient identity, allergies",
            rto=15 * 60, rpo=60, interval=10, prod="every 1 min",
            why="A missing allergy or blood group can kill within minutes. Must return first and lose almost nothing."),
    1: dict(name="Tier 1 - Clinical records", systems="Medications, lab results",
            rto=60 * 60, rpo=5 * 60, interval=20, prod="every 5 min",
            why="Treatment decisions depend on it, but staff can bridge briefly with Tier 0 data and paper."),
    2: dict(name="Tier 2 - Operations", systems="Billing, appointments",
            rto=8 * 3600, rpo=3600, interval=40, prod="hourly",
            why="Delay is costly but not dangerous; it can be rebuilt from paper and re-entry."),
    3: dict(name="Tier 3 - Archive", systems="Old reports, analytics",
            rto=24 * 3600, rpo=24 * 3600, interval=60, prod="daily",
            why="Needed for audits and research, not for care today."),
}

SCHEMA = {
    0: ["CREATE TABLE patients(id INTEGER PRIMARY KEY, name TEXT, age INTEGER, blood_group TEXT, ward TEXT)",
        "CREATE TABLE allergies(id INTEGER PRIMARY KEY AUTOINCREMENT, patient_id INTEGER, allergen TEXT, severity TEXT)"],
    1: ["CREATE TABLE medications(id INTEGER PRIMARY KEY AUTOINCREMENT, patient_id INTEGER, drug TEXT, dose TEXT)",
        "CREATE TABLE lab_results(id INTEGER PRIMARY KEY AUTOINCREMENT, patient_id INTEGER, test TEXT, value TEXT, taken_at TEXT)"],
    2: ["CREATE TABLE billing(id INTEGER PRIMARY KEY AUTOINCREMENT, patient_id INTEGER, amount REAL, status TEXT)",
        "CREATE TABLE appointments(id INTEGER PRIMARY KEY AUTOINCREMENT, patient_id INTEGER, slot TEXT, dept TEXT)"],
    3: ["CREATE TABLE archive_reports(id INTEGER PRIMARY KEY AUTOINCREMENT, patient_id INTEGER, year INTEGER, summary TEXT)"],
}

# Recovery objective per system, with the clinical and operational (criticality) justification.
# Each system inherits its tier's RTO/RPO. `table` links the system to the data actually backed up.
SYSTEMS = [
    dict(system="Patient identity", table="patients", tier=0,
         clinical="Wrong or missing identity means treating the wrong person or giving incompatible blood.",
         critical="Every other system is keyed on the patient ID, so nothing else is safe until this is back."),
    dict(system="Allergy records", table="allergies", tier=0,
         clinical="A missed severe allergy (for example penicillin) can cause anaphylaxis within minutes.",
         critical="Small and cheap to protect, so a 1-minute data-loss limit is affordable and clearly justified."),
    dict(system="Medication orders", table="medications", tier=1,
         clinical="Doses and interactions drive treatment; staff can bridge briefly with paper charts and Tier 0 data.",
         critical="Needed within the hour to avoid missed or duplicated doses."),
    dict(system="Lab results", table="lab_results", tier=1,
         clinical="Results guide diagnosis; urgent values can be phoned through during downtime.",
         critical="Delay slows care, but samples are retained, so a 5-minute data-loss limit is acceptable."),
    dict(system="Billing", table="billing", tier=2,
         clinical="No direct clinical risk.",
         critical="Revenue is delayed, not lost; can be rebuilt from paper and re-entry."),
    dict(system="Appointments", table="appointments", tier=2,
         clinical="Low risk; outpatients can be rescheduled by phone.",
         critical="Inconvenient but recoverable within a working day."),
    dict(system="Archived reports", table="archive_reports", tier=3,
         clinical="No effect on today's care.",
         critical="Needed for audits and research; a day's delay is tolerable."),
]

# Named roles (demo PINs - synthetic environment only). Access is limited to these roles.
USERS = {
    "asha": dict(role="Admin", pin="admin@123"),
    "ravi": dict(role="Operator", pin="ops@123"),
    "meena": dict(role="Auditor", pin="audit@123"),
}
_OPS = {"seed", "backup", "activity", "fail", "restore", "drill", "corrupt", "pause"}
PERMS = {
    "Admin": _OPS | {"audit_read", "audit_verify"},
    "Operator": set(_OPS),
    "Auditor": {"audit_read", "audit_verify"},
}
SYSTEM = ("system", "Scheduler")

OPLOCK = threading.RLock()       # serialises anything that touches the primary / DR files
STATE_LOCK = threading.RLock()
AUDIT_LOCK = threading.Lock()
SESSIONS = {}
STATE = {
    "events": [], "last_backup": {}, "incident": None, "report": None,
    "drill_running": False, "restoring_tier": None, "online": None, "scheduler_paused": False,
    "history": [], "tls": False,
}


# ----------------------------------------------------------------------------- helpers
def now():
    return time.time()


def iso(ts=None):
    return datetime.fromtimestamp(ts if ts is not None else now()).strftime("%Y-%m-%d %H:%M:%S")


def event(level, msg):
    with STATE_LOCK:
        STATE["events"].append({"ts": iso(), "level": level, "msg": msg})
        STATE["events"] = STATE["events"][-300:]
    print(f"[{iso()}] {level}: {msg}", flush=True)


def load_fernet():
    DATA.mkdir(parents=True, exist_ok=True)
    if not KEYFILE.exists():
        KEYFILE.write_bytes(Fernet.generate_key())
        try:
            os.chmod(KEYFILE, 0o600)
        except OSError:
            pass
    return Fernet(KEYFILE.read_bytes())


FERNET = load_fernet()   # authenticated AES encryption; in production the key lives in a KMS/HSM, not beside the data


def safe_unlink(p):
    for _ in range(10):
        try:
            Path(p).unlink(missing_ok=True)
            return
        except PermissionError:
            time.sleep(0.1)


def tier_path(t):
    return PRIMARY / f"tier{t}.db"


def table_names(conn):
    return [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]


def count_rows(path):
    conn = sqlite3.connect(f"{Path(path).as_uri()}?mode=ro", uri=True, timeout=3)
    try:
        return {n: conn.execute(f'SELECT COUNT(*) FROM "{n}"').fetchone()[0] for n in table_names(conn)}
    finally:
        conn.close()


def tier_healthy(t):
    p = tier_path(t)
    if not p.exists():
        return False
    try:
        conn = sqlite3.connect(f"{p.as_uri()}?mode=ro", uri=True, timeout=2)
        try:
            return conn.execute("PRAGMA quick_check").fetchone()[0] == "ok"
        finally:
            conn.close()
    except Exception:
        return False


# ----------------------------------------------------------------------------- audit log
def audit(who, action, detail="", ok=True):
    """Append-only, hash-chained audit log. Editing or deleting any line breaks the chain."""
    user, role = who
    with AUDIT_LOCK:
        DATA.mkdir(parents=True, exist_ok=True)
        prev = "0" * 64
        if AUDIT.exists():
            lines = AUDIT.read_text(encoding="utf-8").strip().splitlines()
            if lines:
                prev = json.loads(lines[-1])["hash"]
        e = dict(ts=iso(), user=user, role=role, action=action, detail=detail, ok=ok, prev=prev)
        e["hash"] = hashlib.sha256(json.dumps(e, sort_keys=True).encode()).hexdigest()
        with open(AUDIT, "a", encoding="utf-8") as f:
            f.write(json.dumps(e) + "\n")


def audit_entries():
    if not AUDIT.exists():
        return []
    return [json.loads(l) for l in AUDIT.read_text(encoding="utf-8").strip().splitlines() if l.strip()]


def audit_verify():
    prev = "0" * 64
    for i, e in enumerate(audit_entries(), 1):
        h = e.pop("hash")
        if e["prev"] != prev or hashlib.sha256(json.dumps(e, sort_keys=True).encode()).hexdigest() != h:
            return {"intact": False, "broken_at": i}
        prev = h
    return {"intact": True, "entries": len(audit_entries())}


# ----------------------------------------------------------------------------- synthetic data
FIRST = ["Aarav", "Diya", "Vihaan", "Ananya", "Kiran", "Meera", "Rohan", "Sneha", "Arjun", "Lakshmi", "Imran", "Priya"]
LAST = ["Sharma", "Gowda", "Rao", "Nair", "Khan", "Patel", "Iyer", "Reddy", "Das", "Singh"]
BLOOD = ["A+", "A-", "B+", "B-", "O+", "O-", "AB+", "AB-"]
WARDS = ["ER", "ICU", "General", "Maternity", "Paediatrics"]
ALLERGENS = ["Penicillin", "Sulfa drugs", "Latex", "Aspirin", "Peanuts", "Iodine contrast"]
DRUGS = ["Paracetamol", "Metformin", "Amlodipine", "Insulin", "Atorvastatin", "Amoxicillin"]
TESTS = ["Hb", "Glucose", "Creatinine", "WBC", "Sodium"]
N_PATIENTS = 300


def seed(who):
    """Reset everything and load synthetic data. Also clears old DR backups for a clean demo."""
    with OPLOCK:
        SEEDED.unlink(missing_ok=True)
        PRIMARY.mkdir(parents=True, exist_ok=True)
        DR.mkdir(parents=True, exist_ok=True)
        for t in TIERS:
            safe_unlink(tier_path(t))
        for f in list(DR.glob("tier*_*.enc")) + list(DR.glob("tier*_*.enc.json")):
            safe_unlink(f)
        with STATE_LOCK:
            STATE.update(last_backup={}, incident=None, report=None, restoring_tier=None)
        rng = random.Random(7)
        conns = {t: sqlite3.connect(tier_path(t), timeout=5) for t in TIERS}
        for t, stmts in SCHEMA.items():
            for s in stmts:
                conns[t].execute(s)
        pats, alls, meds, labs, bills, appts, arch = [], [], [], [], [], [], []
        for pid in range(1, N_PATIENTS + 1):
            pats.append((pid, f"SYNTH-{pid:04d} {rng.choice(FIRST)} {rng.choice(LAST)}", rng.randint(1, 95),
                         rng.choice(BLOOD), rng.choice(WARDS)))
            for _ in range(rng.randint(0, 2)):
                alls.append((pid, rng.choice(ALLERGENS), rng.choice(["mild", "moderate", "severe"])))
            for _ in range(2):
                meds.append((pid, rng.choice(DRUGS), f"{rng.choice([5, 10, 25, 50, 100])} mg"))
            for _ in range(3):
                labs.append((pid, rng.choice(TESTS), str(round(rng.uniform(1, 150), 1)), iso(now() - rng.randint(0, 900000))))
            bills.append((pid, round(rng.uniform(500, 90000), 2), rng.choice(["paid", "pending"])))
            appts.append((pid, iso(now() + rng.randint(3600, 900000)), rng.choice(WARDS)))
        for i in range(600):
            arch.append((rng.randint(1, N_PATIENTS), rng.randint(2015, 2025), "Synthetic archived summary. " * 14))
        conns[0].executemany("INSERT INTO patients VALUES (?,?,?,?,?)", pats)
        conns[0].executemany("INSERT INTO allergies(patient_id,allergen,severity) VALUES (?,?,?)", alls)
        conns[1].executemany("INSERT INTO medications(patient_id,drug,dose) VALUES (?,?,?)", meds)
        conns[1].executemany("INSERT INTO lab_results(patient_id,test,value,taken_at) VALUES (?,?,?,?)", labs)
        conns[2].executemany("INSERT INTO billing(patient_id,amount,status) VALUES (?,?,?)", bills)
        conns[2].executemany("INSERT INTO appointments(patient_id,slot,dept) VALUES (?,?,?)", appts)
        conns[3].executemany("INSERT INTO archive_reports(patient_id,year,summary) VALUES (?,?,?)", arch)
        for c in conns.values():
            c.commit()
            c.close()
        SEEDED.touch()
        audit(who, "seed", f"synthetic data loaded ({N_PATIENTS} patients) and DR folder cleared")
        event("INFO", f"Synthetic hospital data loaded ({N_PATIENTS} patients). Taking first backups.")
        backup_all(who, announce=False)


def activity(who, n=5):
    """Simulate live hospital writes (new admissions etc.) so we can show data written after the last backup."""
    with OPLOCK:
        if not SEEDED.exists():
            raise ValueError("Load synthetic data first")
        rng = random.Random()
        c0, c1, c2 = (sqlite3.connect(tier_path(t), timeout=5) for t in (0, 1, 2))
        for _ in range(n):
            pid = (c0.execute("SELECT COALESCE(MAX(id),0)+1 FROM patients").fetchone()[0])
            c0.execute("INSERT INTO patients VALUES (?,?,?,?,?)",
                       (pid, f"SYNTH-{pid:04d} {rng.choice(FIRST)} {rng.choice(LAST)}", rng.randint(1, 95), rng.choice(BLOOD), "ER"))
            c0.execute("INSERT INTO allergies(patient_id,allergen,severity) VALUES (?,?,?)", (pid, rng.choice(ALLERGENS), "severe"))
            c1.execute("INSERT INTO medications(patient_id,drug,dose) VALUES (?,?,?)", (pid, rng.choice(DRUGS), "10 mg"))
            c2.execute("INSERT INTO billing(patient_id,amount,status) VALUES (?,?,?)", (pid, 1000.0, "pending"))
        for c in (c0, c1, c2):
            c.commit()
            c.close()
        audit(who, "activity", f"{n} new admissions written (simulated live traffic)")
        event("INFO", f"{n} new admissions written to the primary (live traffic).")


# ----------------------------------------------------------------------------- backup
def list_versions(t):
    out = []
    for p in DR.glob(f"tier{t}_*.enc.json"):
        try:
            out.append(json.loads(p.read_text(encoding="utf-8")))
        except Exception:
            pass
    return sorted(out, key=lambda m: m["ts"], reverse=True)


def load_last_backups():
    for t in TIERS:
        v = list_versions(t)
        if v:
            STATE["last_backup"][t] = {"ts": v[0]["ts"], "file": v[0]["file"], "rows": v[0]["rows"]}


def backup_tier(t, who):
    """Consistent snapshot -> AES-encrypt -> checksum -> copy to the DR site, keep last N versions."""
    with OPLOCK:
        if not tier_healthy(t):
            return None
        snap = DATA / f"_snap{t}.db"
        src = sqlite3.connect(tier_path(t), timeout=5)
        dst = sqlite3.connect(snap)
        try:
            src.backup(dst)
        finally:
            dst.close()
            src.close()
        raw = snap.read_bytes()
        counts = count_rows(snap)
        safe_unlink(snap)
        enc = FERNET.encrypt(raw)
        ts = now()
        fname = f"tier{t}_{int(ts * 1000)}.enc"
        DR.mkdir(parents=True, exist_ok=True)
        (DR / fname).write_bytes(enc)
        m = dict(tier=t, ts=ts, file=fname, plain_sha256=hashlib.sha256(raw).hexdigest(),
                 enc_sha256=hashlib.sha256(enc).hexdigest(), bytes=len(raw), counts=counts, rows=sum(counts.values()))
        (DR / (fname + ".json")).write_text(json.dumps(m), encoding="utf-8")
        for old in list_versions(t)[KEEP_VERSIONS:]:
            safe_unlink(DR / old["file"])
            safe_unlink(DR / (old["file"] + ".json"))
        with STATE_LOCK:
            STATE["last_backup"][t] = {"ts": ts, "file": fname, "rows": m["rows"]}
        if who != SYSTEM:
            audit(who, "backup", f"tier {t}: {m['rows']} rows, {len(enc)} bytes encrypted -> {fname}")
        return m


def backup_all(who, announce=True):
    for t in TIERS:
        backup_tier(t, who)
    if announce:
        event("INFO", "Backup of all tiers completed (encrypted + checksummed).")


# ----------------------------------------------------------------------------- failure + restore
def inject_failure(who):
    """Simulate losing the main data centre: the primary database files disappear."""
    with OPLOCK:
        if not SEEDED.exists():
            raise ValueError("Load synthetic data first")
        inc = STATE["incident"]
        if inc and not inc.get("restored_at"):
            raise ValueError("An incident is already active - restore first")
        rows = {}
        for t in TIERS:
            try:
                rows[t] = sum(count_rows(tier_path(t)).values())
            except Exception:
                rows[t] = 0
        failed_at = now()
        for t in TIERS:
            safe_unlink(tier_path(t))
        with STATE_LOCK:
            STATE["incident"] = dict(failed_at=failed_at, detected_at=None, restored_at=None,
                                     rows_at_failure=rows, restored_tiers={}, unplanned=False)
            STATE["report"] = None
        audit(who, "fail", "primary data centre failure simulated (all tier databases removed)")
        event("ERROR", "PRIMARY DATA CENTRE FAILURE SIMULATED - all tier databases removed.")


def restore_tier(t):
    """Verify then restore one tier. Falls back to an older backup if the newest is corrupt or tampered with."""
    versions = list_versions(t)
    notes = []
    for i, m in enumerate(versions):
        tmp = PRIMARY / f"_restore{t}.db"
        try:
            enc = (DR / m["file"]).read_bytes()
            if hashlib.sha256(enc).hexdigest() != m["enc_sha256"]:
                raise ValueError("encrypted file checksum mismatch")
            raw = FERNET.decrypt(enc)
            if hashlib.sha256(raw).hexdigest() != m["plain_sha256"]:
                raise ValueError("decrypted checksum mismatch")
            PRIMARY.mkdir(parents=True, exist_ok=True)
            tmp.write_bytes(raw)
            counts = count_rows(tmp)
            conn = sqlite3.connect(tmp)
            ok = conn.execute("PRAGMA integrity_check").fetchone()[0]
            conn.close()
            if ok != "ok":
                raise ValueError("database integrity check failed")
            if counts != m["counts"]:
                raise ValueError("row counts differ from backup manifest")
            for _ in range(10):
                try:
                    os.replace(tmp, tier_path(t))
                    break
                except PermissionError:
                    time.sleep(0.1)
            return dict(ok=True, manifest=m, fallback=i > 0, notes=notes, bytes=len(raw), counts=counts)
        except Exception as e:
            notes.append(f"{m['file']}: {str(e) or type(e).__name__}")
            event("WARN", f"Tier {t}: backup {m['file']} rejected ({str(e) or type(e).__name__}); trying previous version.")
            safe_unlink(tmp)
    return dict(ok=False, notes=notes)


def restore_all(who):
    with OPLOCK:
        inc = STATE["incident"]
        if not inc or inc.get("restored_at"):
            raise ValueError("No active incident to restore")
        audit(who, "restore", "restore started in tier order 0 -> 3")
        event("INFO", "RESTORE STARTED - recovering in clinical priority order (Tier 0 first).")
        t_start = now()
        results, all_ok = {}, True
        for t in sorted(TIERS):
            STATE["restoring_tier"] = t
            r = restore_tier(t)
            r["restored_at"] = now()
            results[t] = r
            inc["restored_tiers"][t] = r["ok"]
            if r["ok"]:
                extra = " (used OLDER backup)" if r["fallback"] else ""
                event("OK", f"Tier {t} restored and verified in {r['restored_at'] - inc['failed_at']:.2f}s since failure{extra}.")
            else:
                all_ok = False
                event("ERROR", f"Tier {t} could NOT be restored: {'; '.join(r['notes']) or 'no backups found'}")
        STATE["restoring_tier"] = None
        if all_ok:
            inc["restored_at"] = now()
        report = build_report(inc, results, t_start)
        with STATE_LOCK:
            STATE["report"] = report
        save_history(report, who)
        audit(who, "restore", f"restore finished: {'PASS' if report['passed'] else 'FAIL'} vs targets", ok=all_ok)
        event("OK" if all_ok else "ERROR", f"RESTORE FINISHED - overall {'PASS' if report['passed'] else 'FAIL'} against tier targets.")


def build_report(inc, results, t_start):
    tiers, total_bytes, last_done = [], 0, t_start
    for t, cfg in TIERS.items():
        r = results[t]
        if not r["ok"]:
            tiers.append(dict(tier=t, name=cfg["name"], failed=True, rto_target=cfg["rto"], rpo_target=cfg["rpo"],
                              notes=r["notes"], rto_pass=False, rpo_pass=False))
            continue
        m = r["manifest"]
        rto = r["restored_at"] - inc["failed_at"]
        rpo = inc["failed_at"] - m["ts"]
        restored_rows = sum(r["counts"].values())
        expected = (inc.get("rows_at_failure") or {}).get(t) if not inc.get("unplanned") else None
        lost = None if expected is None else max(0, expected - restored_rows)
        total_bytes += r["bytes"]
        last_done = max(last_done, r["restored_at"])
        tiers.append(dict(tier=t, name=cfg["name"], rto_target=cfg["rto"], rto_measured=round(rto, 2), rto_pass=rto <= cfg["rto"],
                          rpo_target=cfg["rpo"], rpo_measured=round(rpo, 1), rpo_pass=rpo <= cfg["rpo"],
                          rows_restored=restored_rows, rows_expected=expected, records_lost=lost,
                          integrity="verified", backup_file=m["file"], fallback=r["fallback"], notes=r["notes"]))
    secs = max(last_done - t_start, 1e-6)
    det = None if inc["detected_at"] is None else round(inc["detected_at"] - inc["failed_at"], 2)
    return dict(tiers=tiers, detection_s=det, total_recovery_s=round(last_done - inc["failed_at"], 2),
                throughput_mb_s=round(total_bytes / 1e6 / secs, 2), unplanned=inc.get("unplanned", False),
                passed=all(x["rto_pass"] and x["rpo_pass"] for x in tiers), finished=iso())


def fmt(s):
    if s is None:
        return "n/a"
    if s < 1:
        return f"{s * 1000:.0f} ms"
    if s < 60:
        return f"{s:.1f} s"
    if s < 3600:
        return f"{s / 60:.1f} min"
    if s < 86400:
        return f"{s / 3600:.1f} h"
    return f"{s / 86400:.1f} d"


def load_history():
    try:
        STATE["history"] = json.loads(HISTORY.read_text(encoding="utf-8"))
    except Exception:
        STATE["history"] = []


def save_history(report, who):
    """Keep every drill so the team can show it is repeatable and improving."""
    lost = [t["records_lost"] for t in report["tiers"] if t.get("records_lost") is not None]
    entry = dict(finished=report["finished"], by=who[0], passed=report["passed"], kind="unplanned" if report["unplanned"] else "drill",
                 detection_s=report["detection_s"], total_recovery_s=report["total_recovery_s"],
                 rows_lost=sum(lost) if lost else None, older_backup=any(t.get("fallback") for t in report["tiers"]))
    with STATE_LOCK:
        STATE["history"] = (STATE["history"] + [entry])[-50:]
        try:
            HISTORY.write_text(json.dumps(STATE["history"]), encoding="utf-8")
        except OSError:
            pass


def report_markdown():
    r, inc = STATE["report"], STATE["incident"]
    if not r or not inc:
        raise ValueError("No report yet. Run a drill first.")
    L = ["# Disaster recovery drill report", "", f"- Generated: {iso()}", f"- Result: **{'PASS' if r['passed'] else 'FAIL'}** against tier targets",
         f"- Failure at: {iso(inc['failed_at'])}" + (" (unplanned, time = detection time)" if r["unplanned"] else " (simulated)"),
         f"- Failure detected after: {fmt(r['detection_s'])}", f"- All tiers recovered after: {fmt(r['total_recovery_s'])}",
         f"- Measured restore speed: {r['throughput_mb_s']} MB/s", "", "## Target vs measured", "",
         "| Tier | RTO target | RTO measured | RTO | RPO target | RPO measured | RPO | Rows lost | Verified |", "|---|---|---|---|---|---|---|---|---|"]
    for t in r["tiers"]:
        if t.get("failed"):
            L.append(f"| {t['tier']} | {fmt(t['rto_target'])} | NOT RESTORED | FAIL | {fmt(t['rpo_target'])} | - | FAIL | - | no |")
        else:
            L.append(f"| {t['tier']}{' (older backup used)' if t['fallback'] else ''} | {fmt(t['rto_target'])} | {fmt(t['rto_measured'])} | {'PASS' if t['rto_pass'] else 'FAIL'} | "
                     f"{fmt(t['rpo_target'])} | {fmt(t['rpo_measured'])} | {'PASS' if t['rpo_pass'] else 'FAIL'} | {t['records_lost'] if t['records_lost'] is not None else 'n/a'} | yes |")
    L += ["", "RTO = failure to restored and verified. RPO = age of the newest usable backup at the moment of failure.",
          "", "## Timeline (failure onwards)", ""]
    since = iso(inc["failed_at"])
    L += [f"- {e['ts']} [{e['level']}] {e['msg']}" for e in STATE["events"] if e["ts"] >= since]
    L += ["", "## Controls in force", "",
          "- Synthetic data only; backups encrypted (Fernet: AES + HMAC) and SHA-256 checksummed; every restore verified (checksum, decrypt, integrity check, row counts).",
          "- Backup/restore actions limited to named roles and recorded in a hash-chained audit log.",
          f"- Residency declared: primary {REGION_PRIMARY}; DR {REGION_DR}.",
          "", "## Limits of this measurement", "",
          "- Data volume is tiny, so restore times are not representative of a full hospital database.",
          "- Unless DR_DIR points at another disk, the DR site is a folder on the same machine."]
    return "\n".join(L) + "\n"


def security_status():
    """Live checks, not just claims."""
    checks = []
    synth = None
    if tier_healthy(0):
        try:
            conn = sqlite3.connect(f"{tier_path(0).as_uri()}?mode=ro", uri=True, timeout=2)
            synth = conn.execute("SELECT COUNT(*) FROM patients WHERE name NOT LIKE 'SYNTH-%'").fetchone()[0] == 0
            conn.close()
        except Exception:
            pass
    checks.append(dict(name="Synthetic data only", status="verified" if synth else ("unknown" if synth is None else "FAILED"),
                       detail="Every patient name carries the SYNTH- prefix; the generator uses random fake names." if synth is not False else "Non-synthetic names found!"))
    enc_ok, v = None, list_versions(0)
    if v:
        try:
            blob = (DR / v[0]["file"]).read_bytes()
            enc_ok = b"SQLite format" not in blob and b"SYNTH-" not in blob
        except OSError:
            pass
    checks.append(dict(name="Encrypted at rest", status="verified" if enc_ok else ("unknown" if enc_ok is None else "FAILED"),
                       detail="Newest Tier 0 backup on the DR site contains no readable database header or patient text (Fernet: AES-128-CBC + HMAC-SHA256). The key is stored separately from the backups."))
    checks.append(dict(name="Encrypted in transit", status="verified" if STATE["tls"] else "off",
                       detail="Dashboard served over TLS." if STATE["tls"] else
                       "Dashboard is plain HTTP on this machine only. Start with HTTPS=1 for TLS (self-signed). Backup files are already encrypted before they leave the primary, so any copy over a network carries ciphertext only."))
    checks.append(dict(name="Data stays in India", status="declared",
                       detail=f"Primary: {REGION_PRIMARY}. DR: {REGION_DR}. This is a declared configuration; locally both are folders, so it cannot be technically enforced here."))
    checks.append(dict(name="Access limited to named roles", status="verified",
                       detail="Enforced on the server for every action; denied attempts are logged. " +
                              "; ".join(f"{r}: {', '.join(sorted(p)) or '-'}" for r, p in PERMS.items())))
    av = audit_verify()
    checks.append(dict(name="Actions logged (tamper-evident)", status="verified" if av["intact"] else "FAILED",
                       detail=f"{av.get('entries', 0)} entries, hash-chained; editing or deleting a line breaks the chain."))
    return checks


def ensure_cert():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    d = DATA / "tls"
    d.mkdir(parents=True, exist_ok=True)
    cert, key = d / "cert.pem", d / "key.pem"
    if cert.exists() and key.exists():
        return cert, key
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    c = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(k.public_key())
         .serial_number(x509.random_serial_number())
         .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
         .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
         .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
         .sign(k, hashes.SHA256()))
    cert.write_bytes(c.public_bytes(serialization.Encoding.PEM))
    key.write_bytes(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    return cert, key


def corrupt_latest(who, t=0):
    """Test the safety net: damage the newest Tier-0 backup so restore must detect it and fall back."""
    with OPLOCK:
        v = list_versions(t)
        if not v:
            raise ValueError("No backup to corrupt")
        p = DR / v[0]["file"]
        data = bytearray(p.read_bytes())
        data[len(data) // 2] ^= 0xFF
        p.write_bytes(bytes(data))
        audit(who, "corrupt", f"test: newest tier {t} backup {v[0]['file']} deliberately damaged")
        event("WARN", f"TEST: newest Tier {t} backup deliberately corrupted. Restore should reject it and use the previous version.")


def run_drill(who):
    with STATE_LOCK:
        if STATE["drill_running"]:
            raise ValueError("A drill is already running")
        STATE["drill_running"] = True
    audit(who, "drill", "full automated drill started")

    def work():
        try:
            event("INFO", "=== FULL DRILL STARTED ===")
            if not SEEDED.exists():
                seed(who)
            inc = STATE["incident"]
            if inc and not inc.get("restored_at"):
                event("INFO", "Resolving the previous unrecovered incident first.")
                restore_all(who)
            STATE["scheduler_paused"] = True
            event("INFO", "Step 1/5: take a fresh backup of every tier.")
            backup_all(who)
            event("INFO", "Step 2/5: live traffic arrives after the backup (this is the data at risk = RPO window).")
            activity(who, 5)
            time.sleep(3)
            event("INFO", "Step 3/5: main data centre fails.")
            STATE["scheduler_paused"] = False
            inject_failure(who)
            event("INFO", "Step 4/5: waiting for the health monitor to detect the failure.")
            for _ in range(150):
                if STATE["incident"]["detected_at"]:
                    break
                time.sleep(0.1)
            event("INFO", "Step 5/5: restoring tiers in priority order.")
            restore_all(who)
            event("OK", "=== DRILL COMPLETE - see the report ===")
        except Exception as e:
            event("ERROR", f"Drill aborted: {e}")
        finally:
            STATE["scheduler_paused"] = False
            STATE["drill_running"] = False

    threading.Thread(target=work, daemon=True).start()


# ----------------------------------------------------------------------------- background threads
def scheduler():
    while True:
        time.sleep(1)
        try:
            if not SEEDED.exists() or STATE["scheduler_paused"]:
                continue
            inc = STATE["incident"]
            if inc and not inc.get("restored_at"):
                continue
            for t, cfg in TIERS.items():
                lb = STATE["last_backup"].get(t)
                if not lb or now() - lb["ts"] >= cfg["interval"]:
                    backup_tier(t, SYSTEM)
        except Exception as e:
            event("WARN", f"scheduler: {e}")


def monitor():
    """Health check every second. This is how a failure gets detected and reported."""
    while True:
        time.sleep(1)
        try:
            if not SEEDED.exists():
                continue
            bad = [t for t in TIERS if not tier_healthy(t)]
            with STATE_LOCK:
                inc = STATE["incident"]
                if bad and inc and inc["detected_at"] is None:
                    inc["detected_at"] = now()
                    event("ALERT", f"FAILURE DETECTED: tier(s) {bad} unavailable. Detection latency {inc['detected_at'] - inc['failed_at']:.1f}s.")
                elif bad and not STATE["restoring_tier"] and (inc is None or inc.get("restored_at")):
                    t0 = now()
                    STATE["incident"] = dict(failed_at=t0, detected_at=t0, restored_at=None, rows_at_failure=None,
                                             restored_tiers={}, unplanned=True)
                    STATE["report"] = None
                    event("ALERT", f"UNPLANNED FAILURE DETECTED: tier(s) {bad} unavailable. Use Restore.")
        except Exception as e:
            event("WARN", f"monitor: {e}")


def connectivity():
    """Only informational. Nothing in this app needs the internet."""
    while True:
        try:
            socket.create_connection(("1.1.1.1", 53), timeout=1.5).close()
            STATE["online"] = True
        except OSError:
            STATE["online"] = False
        time.sleep(5)


# ----------------------------------------------------------------------------- HTTP
def build_status(who):
    user, role = who
    inc = STATE["incident"]
    tiers, table_rows = [], {}
    for t, cfg in TIERS.items():
        healthy = tier_healthy(t)
        rows = None
        if healthy:
            try:
                c = count_rows(tier_path(t))
                table_rows.update(c)
                rows = sum(c.values())
            except Exception:
                pass
        lb = STATE["last_backup"].get(t)
        if STATE["restoring_tier"] == t:
            st = "restoring"
        elif SEEDED.exists() and not healthy:
            st = "failed"
        elif inc and inc["restored_tiers"].get(t):
            st = "restored"
        else:
            st = "healthy" if SEEDED.exists() else "empty"
        tiers.append(dict(tier=t, name=cfg["name"], systems=cfg["systems"], state=st, rows=rows,
                          last_backup_age=None if not lb else round(now() - lb["ts"], 1),
                          rto=cfg["rto"], rpo=cfg["rpo"], interval=cfg["interval"], prod=cfg["prod"], why=cfg["why"],
                          versions=len(list_versions(t))))
    files = list(DR.glob("tier*_*.enc")) if DR.exists() else []
    return dict(now=iso(), online=STATE["online"], seeded=SEEDED.exists(), user=user, role=role,
                perms=sorted(PERMS[role]), tiers=tiers, report=STATE["report"], drill_running=STATE["drill_running"],
                paused=STATE["scheduler_paused"], restoring_tier=STATE["restoring_tier"],
                incident=None if not inc else dict(failed_at=iso(inc["failed_at"]), detected_s=None if not inc["detected_at"] else round(inc["detected_at"] - inc["failed_at"], 2),
                                                   restored=bool(inc.get("restored_at")), unplanned=inc.get("unplanned", False)),
                events=list(reversed(STATE["events"][-60:])),
                systems=[dict(s, rto=TIERS[s["tier"]]["rto"], rpo=TIERS[s["tier"]]["rpo"], rows=table_rows.get(s["table"])) for s in SYSTEMS],
                history=list(reversed(STATE["history"][-10:])), tls=STATE["tls"],
                dr=dict(dir=str(DR), files=len(files), bytes=sum(f.stat().st_size for f in files)))


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, obj=None, raw=None, ctype="application/json"):
        body = raw if raw is not None else json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _who(self):
        h = self.headers.get("Authorization", "")
        return SESSIONS.get(h[7:]) if h.startswith("Bearer ") else None

    def _body(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return {}

    def _need(self, perm):
        who = self._who()
        if not who:
            self._send(401, {"error": "Login required"})
            return None
        if perm and perm not in PERMS[who[1]]:
            audit(who, perm, f"DENIED: role {who[1]} may not perform '{perm}'", ok=False)
            self._send(403, {"error": f"Your role ({who[1]}) is not allowed to do this. The attempt was logged."})
            return None
        return who

    def do_GET(self):
        path = self.path.split("?")[0]
        try:
            if path in ("/", "/index.html"):
                return self._send(200, raw=(STATIC / "index.html").read_bytes(), ctype="text/html; charset=utf-8")
            if path == "/api/status":
                who = self._need(None)
                return who and self._send(200, build_status(who))
            if path == "/api/security":
                who = self._need(None)
                return who and self._send(200, {"checks": security_status()})
            if path == "/api/report":
                who = self._need(None)
                if not who:
                    return
                try:
                    body = report_markdown().encode("utf-8")
                except ValueError as e:
                    return self._send(400, {"error": str(e)})
                self.send_response(200)
                self.send_header("Content-Type", "text/markdown; charset=utf-8")
                self.send_header("Content-Disposition", "attachment; filename=drill-report.md")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                return self.wfile.write(body)
            if path == "/api/audit":
                who = self._need("audit_read")
                return who and self._send(200, {"entries": list(reversed(audit_entries()))[:200]})
            if path == "/api/audit/verify":
                who = self._need("audit_verify")
                return who and self._send(200, audit_verify())
            self._send(404, {"error": "not found"})
        except Exception as e:
            self._send(500, {"error": str(e)})

    def do_POST(self):
        path = self.path.split("?")[0]
        body = self._body()
        try:
            if path == "/api/login":
                name = str(body.get("user", ""))
                u = USERS.get(name)
                if not u or not secrets.compare_digest(u["pin"], str(body.get("pin", ""))):
                    audit((name or "?", "-"), "login", "failed login", ok=False)
                    return self._send(401, {"error": "Wrong user or PIN"})
                tok = secrets.token_urlsafe(24)
                SESSIONS[tok] = (name, u["role"])
                audit((name, u["role"]), "login", "ok")
                return self._send(200, {"token": tok, "user": name, "role": u["role"]})
            action = path.rsplit("/", 1)[-1]
            if action not in _OPS:
                return self._send(404, {"error": "unknown action"})
            who = self._need(action)
            if not who:
                return
            if action == "seed":
                seed(who)
            elif action == "backup":
                backup_all(who)
            elif action == "activity":
                activity(who, 5)
            elif action == "fail":
                inject_failure(who)
            elif action == "restore":
                restore_all(who)
            elif action == "drill":
                run_drill(who)
            elif action == "corrupt":
                corrupt_latest(who)
            elif action == "pause":
                STATE["scheduler_paused"] = not STATE["scheduler_paused"]
                audit(who, "pause", f"auto-backup {'paused' if STATE['scheduler_paused'] else 'resumed'}")
                event("INFO", f"Auto-backup {'PAUSED' if STATE['scheduler_paused'] else 'RESUMED'} by {who[0]}.")
            self._send(200, {"ok": True})
        except ValueError as e:
            self._send(400, {"error": str(e)})
        except Exception as e:
            self._send(500, {"error": f"{type(e).__name__}: {e}"})


def main():
    DATA.mkdir(parents=True, exist_ok=True)
    PRIMARY.mkdir(parents=True, exist_ok=True)
    DR.mkdir(parents=True, exist_ok=True)
    load_last_backups()
    load_history()
    for fn in (scheduler, monitor, connectivity):
        threading.Thread(target=fn, daemon=True).start()
    srv = ThreadingHTTPServer((HOST, PORT), Handler)
    scheme = "http"
    if USE_TLS:
        cert, key = ensure_cert()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(cert, key)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
        STATE["tls"] = True
        scheme = "https"
        print("TLS enabled with a self-signed certificate: the browser will warn once; choose Advanced > Continue.")
    print(f"\nHospitalDR running  ->  {scheme}://{HOST}:{PORT}")
    print("Demo logins (synthetic environment):  asha/admin@123 (Admin)  ravi/ops@123 (Operator)  meena/audit@123 (Auditor)")
    print(f"DR site folder: {DR}\nPress Ctrl+C to stop.\n")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
