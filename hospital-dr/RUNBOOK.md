# HospitalDR - Runbook (for a three-person team, no specialist knowledge)

Goal: bring critical hospital services back after the main data centre fails, in clinical priority order, and prove it worked.

**Roles**
- Incident lead (Admin account `asha`): decides, clicks Restore.
- Operator (`ravi`): runs backups and restores.
- Scribe / Auditor (`meena`): writes down times, verifies the audit log.

## Before any incident (monthly drill)
1. Start the app: `python app.py`, open http://127.0.0.1:8000.
2. Click **Run full drill**. Read the target vs measured table. Save a screenshot.
3. Confirm the DR folder (shown in the console and event log) is on a different disk or building.

## During an incident
1. **Detect** - red INCIDENT banner and `FAILURE DETECTED` in the event log. Scribe notes the time.
2. **Declare** - Incident lead announces it. Wards switch to paper downtime forms.
3. **Sign in** with a named Operator/Admin account.
4. **Restore** - click **Restore**. Tiers return in order 0, 1, 2, 3. Do not interrupt.
5. **Verify** - every tier row must show verified (checksum, decrypt, integrity check, row counts).
6. **Confirm clinically** - a nurse checks three known patients' allergies and blood group against paper. Then declare Tier 0 back in service.
7. **Report** - save the target vs measured table, note any FAIL, "older backup" flag, and records lost.
8. **Review** - Auditor clicks **Verify log integrity** on the Audit tab.

## Troubleshooting
| Symptom | Action |
|---|---|
| "older backup" flag | Newest backup was damaged; previous version used automatically. Expect higher data loss. Record and investigate. |
| Tier shows NOT RESTORED | No usable backup. Attach the second backup disk / correct `DR_DIR`, restore again. |
| Dashboard will not open | On a spare laptop with the DR folder: `python app.py` then open the same address. |
| Button greyed out | Your role is not allowed; ask the Admin. Denied attempts are logged. |
