#!/usr/bin/env python3
"""
incident_manager.py — Interactive DFIR AppSec Incident Reporter

What it is
----------
A terminal-based, SQLite-backed incident manager tailored to the CISO-style
AppSec incident playbook. It lets security engineers create an incident,
iterate through stages, add/remove/update entries at any time, and export a
final report in Markdown (Confluence-friendly) and optional PDF/HTML.

Highlights
---------
• Interactive menus for: metadata, roles, triggers, tasks (by phase),
  evidence (with optional SHA-256), timeline, and executive checklist
• SQLite “db/ir.sqlite3” for persistence, so you can return and edit later
• Pre-populates standard tasks & checklist from your template
• Exports to Markdown (always), HTML (always), and PDF (if reportlab is installed)

Usage
-----
$ python3 incident_manager.py

Optional args:
  --db PATH            Path to SQLite DB file (default: db/ir.sqlite3)
  --export INCIDENT_ID Export incident (ID or numeric row id) and exit

Dependencies
------------
• Standard library only for core features.
• For PDF export, install: pip install reportlab

Note: Times are stored in UTC ISO-8601 with Z suffix.
"""
from __future__ import annotations

import argparse
import datetime as dt
import os
import sqlite3
import textwrap
import hashlib
import shutil
from typing import List, Tuple, Optional

# Optional PDF support
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    PDF_AVAILABLE = True
except Exception:
    PDF_AVAILABLE = False

DB_DEFAULT = os.path.join("db", "ir.sqlite3")
NOW = lambda: dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

# ------------------------------ DB LAYER ------------------------------
SCHEMA = [
    """
    CREATE TABLE IF NOT EXISTS incidents (
      id INTEGER PRIMARY KEY,
      incident_key TEXT,
      name TEXT,
      severity TEXT,
      classification TEXT,
      reported_by TEXT,
      detection_source TEXT,
      incident_start TEXT,
      created_at TEXT,
      updated_at TEXT,
      status TEXT
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS roles (
      id INTEGER PRIMARY KEY,
      incident_id INTEGER,
      role TEXT,
      person TEXT,
      FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE CASCADE
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS triggers (
      id INTEGER PRIMARY KEY,
      incident_id INTEGER,
      description TEXT,
      FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE CASCADE
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS tasks (
      id INTEGER PRIMARY KEY,
      incident_id INTEGER,
      phase TEXT,              -- immediate | next | aftermath
      description TEXT,
      status TEXT,             -- pending | done | na
      time TEXT,
      notes TEXT,
      FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE CASCADE
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS evidence (
      id INTEGER PRIMARY KEY,
      incident_id INTEGER,
      artifact TEXT,
      path TEXT,
      sha256 TEXT,
      notes TEXT,
      FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE CASCADE
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS timeline (
      id INTEGER PRIMARY KEY,
      incident_id INTEGER,
      time TEXT,
      actor TEXT,
      event TEXT,
      decision TEXT,
      FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE CASCADE
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS checklist (
      id INTEGER PRIMARY KEY,
      incident_id INTEGER,
      item TEXT,
      checked INTEGER,         -- 0/1
      FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE CASCADE
    );
    """,
]

DEFAULT_TASKS = {
    "immediate": [
        "Assemble incident channel (IR lead, app owner/dev, SRE/DevOps, SecOps, comms/PR, legal)",
        "Preserve evidence: Snapshot logs/telemetry; capture memory & disk (where feasible)",
        "Triage scope: tenants/objects/accounts/routes/builds; estimate data at risk",
        "Contain: disable route/feature; WAF/RASP rules; revoke sessions/tokens; rotate keys/secrets; isolate infra",
        "Comms: internal exec status; prep external holding lines; engage regulators/law enforcement per policy",
    ],
    "next": [
        "Eradicate: patch root cause; remove backdoors; rebuild from trusted sources",
        "Recover: gradual restore with heightened monitoring; validate no persistence",
        "Notify: customers/regulators as required; provide concrete guidance",
        "Document: timeline, impact, evidence map, decisions, and rationale",
    ],
    "aftermath": [
        "Lessons learned review; convert findings into backlog (code/detections/process)",
        "Update playbooks, metrics (MTTD/MTTR), training, and tabletop scenarios",
    ],
}

DEFAULT_CHECKLIST = [
    "Named app owners & on-call developers in IR rosters",
    "Can revoke all sessions/tokens and disable a route in minutes",
    "API authorization enforced at object level across critical flows",
    "Logging, retention, and evidence preservation DFIR-ready",
    "Monitoring for BOLA/IDOR, mass access, and admin anomalies",
    "MFA/bot defenses for high-risk apps and customers",
    "SBOMs maintained; signed artifacts; build provenance",
    "API breach & supply-chain tabletop in last 6 months",
    "Post-incident actions tracked to closure & audited",
]

SUGGESTED_TRIGGERS = [
    "Unusual API read volumes or IDOR indicators",
    "ATO signals (credential stuffing patterns, session reuse)",
    "Code integrity alert on production artifact",
    "Vendor advisory indicating a malicious update/compromised package",
]


def ensure_db(conn: sqlite3.Connection):
    for ddl in SCHEMA:
        conn.execute(ddl)
    conn.commit()


def connect(db_path: str) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    ensure_db(conn)
    return conn


# ------------------------------ UTIL ------------------------------

def prompt(msg: str, default: Optional[str] = None) -> str:
    if default:
        val = input(f"{msg} [{default}]: ").strip()
        return val or default
    return input(f"{msg}: ").strip()


def pick(rows: List[sqlite3.Row], label_fields: Tuple[str, ...] = ("id", "name")) -> Optional[int]:
    if not rows:
        print("(none)")
        return None
    for i, r in enumerate(rows, 1):
        label = " | ".join(str(r.get(f, r[f])) for f in label_fields if f in r.keys())
        print(f"{i}) {label}")
    sel = input("Select number (or blank to cancel): ").strip()
    if not sel:
        return None
    try:
        idx = int(sel) - 1
        if 0 <= idx < len(rows):
            return rows[idx]["id"]
    except Exception:
        pass
    print("Invalid selection.")
    return None


def sha256_file(path: str) -> str:
    try:
        if not os.path.isfile(path):
            return "N/A (not a file)"
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        return f"N/A ({e})"


# ------------------------------ INCIDENT CRUD ------------------------------

def create_incident(conn: sqlite3.Connection):
    print("\n== Create New Incident ==")
    name = prompt("Incident name")
    incident_key = prompt("Incident ID (ticket/case number)")
    severity = prompt("Severity (e.g., SEV-1/2/3)")
    incident_start = prompt("Incident start time (ISO 8601)", NOW())
    created_at = NOW()
    classification = prompt("Classification (Confidential/Internal/Public)", "Confidential")
    reported_by = prompt("Reported by (name/team/source)")
    detection_source = prompt("Primary detection source (SIEM/WAF/API GW/User report/etc.)")

    cur = conn.execute(
        """
        INSERT INTO incidents(incident_key, name, severity, classification, reported_by,
                              detection_source, incident_start, created_at, updated_at, status)
        VALUES(?,?,?,?,?,?,?,?,?,?)
        """,
        (incident_key, name, severity, classification, reported_by,
         detection_source, incident_start, created_at, created_at, "open"),
    )
    inc_id = cur.lastrowid

    # Pre-populate tasks & checklist
    for phase, items in DEFAULT_TASKS.items():
        for d in items:
            conn.execute(
                "INSERT INTO tasks(incident_id, phase, description, status, time, notes) VALUES(?,?,?,?,?,?)",
                (inc_id, phase, d, "pending", NOW(), ""),
            )
    for item in DEFAULT_CHECKLIST:
        conn.execute(
            "INSERT INTO checklist(incident_id, item, checked) VALUES(?,?,?)",
            (inc_id, item, 0),
        )
    conn.commit()
    print(f"Created incident #{inc_id}: {name}")


def list_incidents(conn: sqlite3.Connection) -> List[sqlite3.Row]:
    cur = conn.execute(
        "SELECT id, incident_key, name, severity, status, created_at FROM incidents ORDER BY id DESC"
    )
    rows = cur.fetchall()
    if not rows:
        print("(no incidents yet)")
    else:
        print("\n-- Incidents --")
        for r in rows:
            print(f"[{r['id']}] {r['incident_key'] or '-'} | {r['name']} | {r['severity'] or '-'} | {r['status']} | {r['created_at']}")
    return rows


def delete_incident(conn: sqlite3.Connection):
    rows = list_incidents(conn)
    if not rows:
        return
    try:
        inc_id = int(prompt("Enter ID to delete (danger!)"))
    except Exception:
        print("Cancelled.")
        return
    conn.execute("DELETE FROM incidents WHERE id=?", (inc_id,))
    conn.commit()
    print("Deleted.")


# ------------------------------ SECTION EDITORS ------------------------------

def edit_metadata(conn: sqlite3.Connection, inc_id: int):
    r = conn.execute("SELECT * FROM incidents WHERE id=?", (inc_id,)).fetchone()
    if not r:
        print("Incident not found")
        return
    print("\n== Edit Metadata ==")
    fields = [
        ("incident_key", "Incident ID"),
        ("name", "Name"),
        ("severity", "Severity"),
        ("classification", "Classification"),
        ("reported_by", "Reported by"),
        ("detection_source", "Detection source"),
        ("incident_start", "Incident start (ISO)"),
        ("status", "Status (open/closed)"),
    ]
    updates = {}
    for col, label in fields:
        cur = r[col]
        val = prompt(label, cur or "")
        updates[col] = val
    updates["updated_at"] = NOW()
    sets = ",".join([f"{k}=?" for k in updates.keys()])
    conn.execute(f"UPDATE incidents SET {sets} WHERE id=?", (*updates.values(), inc_id))
    conn.commit()
    print("Metadata updated.")


def edit_roles(conn: sqlite3.Connection, inc_id: int):
    while True:
        rows = conn.execute("SELECT * FROM roles WHERE incident_id=? ORDER BY id", (inc_id,)).fetchall()
        print("\n-- Roles --")
        if not rows:
            print("(none)")
        else:
            for r in rows:
                print(f"[{r['id']}] {r['role']}: {r['person']}")
        print("a) add  e) edit  d) delete  q) back")
        ch = input("> ").strip().lower()
        if ch == 'a':
            role = prompt("Role (e.g., IR Lead, App Owner)>)")
            person = prompt("Person (name/handle)")
            conn.execute("INSERT INTO roles(incident_id, role, person) VALUES(?,?,?)", (inc_id, role, person))
            conn.commit()
        elif ch == 'e':
            rid = input("ID to edit: ").strip()
            if not rid.isdigit():
                continue
            r = conn.execute("SELECT * FROM roles WHERE id=? AND incident_id=?", (rid, inc_id)).fetchone()
            if not r:
                print("Not found.")
                continue
            role = prompt("Role", r['role'])
            person = prompt("Person", r['person'])
            conn.execute("UPDATE roles SET role=?, person=? WHERE id=?", (role, person, rid))
            conn.commit()
        elif ch == 'd':
            rid = input("ID to delete: ").strip()
            if rid.isdigit():
                conn.execute("DELETE FROM roles WHERE id=? AND incident_id=?", (rid, inc_id))
                conn.commit()
        elif ch == 'q':
            break


def edit_triggers(conn: sqlite3.Connection, inc_id: int):
    while True:
        rows = conn.execute("SELECT * FROM triggers WHERE incident_id=? ORDER BY id", (inc_id,)).fetchall()
        print("\n-- Triggers --")
        if not rows:
            print("(none)")
        else:
            for r in rows:
                print(f"[{r['id']}] {r['description']}")
        print("a) add (pick from suggestions)  c) custom add  e) edit  d) delete  q) back")
        ch = input("> ").strip().lower()
        if ch == 'a':
            for i, s in enumerate(SUGGESTED_TRIGGERS, 1):
                print(f"{i}) {s}")
            sel = input("Select number: ").strip()
            if sel.isdigit():
                idx = int(sel) - 1
                if 0 <= idx < len(SUGGESTED_TRIGGERS):
                    conn.execute("INSERT INTO triggers(incident_id, description) VALUES(?,?)", (inc_id, SUGGESTED_TRIGGERS[idx]))
                    conn.commit()
        elif ch == 'c':
            desc = prompt("Trigger description")
            conn.execute("INSERT INTO triggers(incident_id, description) VALUES(?,?)", (inc_id, desc))
            conn.commit()
        elif ch == 'e':
            tid = input("ID to edit: ").strip()
            if tid.isdigit():
                r = conn.execute("SELECT * FROM triggers WHERE id=? AND incident_id=?", (tid, inc_id)).fetchone()
                if r:
                    desc = prompt("Description", r['description'])
                    conn.execute("UPDATE triggers SET description=? WHERE id=?", (desc, tid))
                    conn.commit()
        elif ch == 'd':
            tid = input("ID to delete: ").strip()
            if tid.isdigit():
                conn.execute("DELETE FROM triggers WHERE id=? AND incident_id=?", (tid, inc_id))
                conn.commit()
        elif ch == 'q':
            break


def edit_tasks(conn: sqlite3.Connection, inc_id: int):
    def manage_phase(phase: str):
        while True:
            rows = conn.execute("SELECT * FROM tasks WHERE incident_id=? AND phase=? ORDER BY id", (inc_id, phase)).fetchall()
            print(f"\n-- Tasks ({phase}) --")
            if not rows:
                print("(none)")
            else:
                for r in rows:
                    print(f"[{r['id']}] {r['description']} | status={r['status']} | time={r['time']} | notes={r['notes'] or ''}")
            print("a) add  s) set status  n) set notes  t) set time  e) edit desc  d) delete  q) back")
            ch = input("> ").strip().lower()
            if ch == 'a':
                desc = prompt("Description")
                conn.execute(
                    "INSERT INTO tasks(incident_id, phase, description, status, time, notes) VALUES(?,?,?,?,?,?)",
                    (inc_id, phase, desc, "pending", NOW(), ""),
                )
                conn.commit()
            elif ch == 's':
                tid = input("ID: ").strip()
                status = prompt("Status (pending/done/na)")
                conn.execute("UPDATE tasks SET status=?, time=? WHERE id=? AND incident_id=?", (status, NOW(), tid, inc_id))
                conn.commit()
            elif ch == 'n':
                tid = input("ID: ").strip()
                notes = prompt("Notes")
                conn.execute("UPDATE tasks SET notes=?, time=? WHERE id=? AND incident_id=?", (notes, NOW(), tid, inc_id))
                conn.commit()
            elif ch == 't':
                tid = input("ID: ").strip()
                t = prompt("Time (ISO)", NOW())
                conn.execute("UPDATE tasks SET time=? WHERE id=? AND incident_id=?", (t, tid, inc_id))
                conn.commit()
            elif ch == 'e':
                tid = input("ID: ").strip()
                desc = prompt("New description")
                conn.execute("UPDATE tasks SET description=? WHERE id=? AND incident_id=?", (desc, tid, inc_id))
                conn.commit()
            elif ch == 'd':
                tid = input("ID to delete: ").strip()
                if tid.isdigit():
                    conn.execute("DELETE FROM tasks WHERE id=? AND incident_id=?", (tid, inc_id))
                    conn.commit()
            elif ch == 'q':
                break

    while True:
        print("\nphases: 1) immediate  2) next (24–72h)  3) aftermath (≤2 weeks)  q) back")
        ch = input("> ").strip().lower()
        if ch == '1':
            manage_phase("immediate")
        elif ch == '2':
            manage_phase("next")
        elif ch == '3':
            manage_phase("aftermath")
        elif ch == 'q':
            break


def edit_evidence(conn: sqlite3.Connection, inc_id: int):
    while True:
        rows = conn.execute("SELECT * FROM evidence WHERE incident_id=? ORDER BY id", (inc_id,)).fetchall()
        print("\n-- Evidence --")
        if not rows:
            print("(none)")
        else:
            for r in rows:
                print(f"[{r['id']}] {r['artifact']} | {r['path']} | sha256={r['sha256']} | {r['notes'] or ''}")
        print("a) add  r) recompute sha256  e) edit  d) delete  q) back")
        ch = input("> ").strip().lower()
        if ch == 'a':
            art = prompt("Artifact description")
            path = prompt("File path")
            sha = sha256_file(path)
            notes = prompt("Notes (optional)")
            conn.execute("INSERT INTO evidence(incident_id, artifact, path, sha256, notes) VALUES(?,?,?,?,?)", (inc_id, art, path, sha, notes))
            conn.commit()
        elif ch == 'r':
            eid = input("ID: ").strip()
            r = conn.execute("SELECT * FROM evidence WHERE id=? AND incident_id=?", (eid, inc_id)).fetchone()
            if r:
                sha = sha256_file(r['path'])
                conn.execute("UPDATE evidence SET sha256=? WHERE id=?", (sha, eid))
                conn.commit()
        elif ch == 'e':
            eid = input("ID: ").strip()
            r = conn.execute("SELECT * FROM evidence WHERE id=? AND incident_id=?", (eid, inc_id)).fetchone()
            if r:
                art = prompt("Artifact", r['artifact'])
                path = prompt("Path", r['path'])
                sha = r['sha256'] if r['path'] == path else sha256_file(path)
                notes = prompt("Notes", r['notes'] or "")
                conn.execute("UPDATE evidence SET artifact=?, path=?, sha256=?, notes=? WHERE id=?", (art, path, sha, notes, eid))
                conn.commit()
        elif ch == 'd':
            eid = input("ID to delete: ").strip()
            if eid.isdigit():
                conn.execute("DELETE FROM evidence WHERE id=? AND incident_id=?", (eid, inc_id))
                conn.commit()
        elif ch == 'q':
            break


def edit_timeline(conn: sqlite3.Connection, inc_id: int):
    while True:
        rows = conn.execute("SELECT * FROM timeline WHERE incident_id=? ORDER BY time", (inc_id,)).fetchall()
        print("\n-- Timeline --")
        if not rows:
            print("(none)")
        else:
            for r in rows:
                print(f"[{r['id']}] {r['time']} | {r['actor']} | {r['event']} | {r['decision']}")
        print("a) add  e) edit  d) delete  q) back")
        ch = input("> ").strip().lower()
        if ch == 'a':
            t = prompt("Time (ISO)", NOW())
            a = prompt("Actor (person/system)")
            e = prompt("Event")
            d = prompt("Decisions/Notes")
            conn.execute("INSERT INTO timeline(incident_id, time, actor, event, decision) VALUES(?,?,?,?,?)", (inc_id, t, a, e, d))
            conn.commit()
        elif ch == 'e':
            tid = input("ID: ").strip()
            r = conn.execute("SELECT * FROM timeline WHERE id=? AND incident_id=?", (tid, inc_id)).fetchone()
            if r:
                t = prompt("Time", r['time'])
                a = prompt("Actor", r['actor'])
                e = prompt("Event", r['event'])
                d = prompt("Decision", r['decision'])
                conn.execute("UPDATE timeline SET time=?, actor=?, event=?, decision=? WHERE id=?", (t, a, e, d, tid))
                conn.commit()
        elif ch == 'd':
            tid = input("ID to delete: ").strip()
            if tid.isdigit():
                conn.execute("DELETE FROM timeline WHERE id=? AND incident_id=?", (tid, inc_id))
                conn.commit()
        elif ch == 'q':
            break


def edit_checklist(conn: sqlite3.Connection, inc_id: int):
    while True:
        rows = conn.execute("SELECT * FROM checklist WHERE incident_id=? ORDER BY id", (inc_id,)).fetchall()
        print("\n-- Executive Checklist --")
        if not rows:
            print("(none)")
        else:
            for r in rows:
                mark = "x" if r['checked'] else " "
                print(f"[{r['id']}] [{mark}] {r['item']}")
        print("a) add  t) toggle  e) edit text  d) delete  q) back")
        ch = input("> ").strip().lower()
        if ch == 'a':
            item = prompt("Checklist item")
            conn.execute("INSERT INTO checklist(incident_id, item, checked) VALUES(?,?,0)", (inc_id, item))
            conn.commit()
        elif ch == 't':
            cid = input("ID: ").strip()
            r = conn.execute("SELECT * FROM checklist WHERE id=? AND incident_id=?", (cid, inc_id)).fetchone()
            if r:
                conn.execute("UPDATE checklist SET checked=? WHERE id=?", (0 if r['checked'] else 1, cid))
                conn.commit()
        elif ch == 'e':
            cid = input("ID: ").strip()
            r = conn.execute("SELECT * FROM checklist WHERE id=? AND incident_id=?", (cid, inc_id)).fetchone()
            if r:
                txt = prompt("Item text", r['item'])
                conn.execute("UPDATE checklist SET item=? WHERE id=?", (txt, cid))
                conn.commit()
        elif ch == 'd':
            cid = input("ID to delete: ").strip()
            if cid.isdigit():
                conn.execute("DELETE FROM checklist WHERE id=? AND incident_id=?", (cid, inc_id))
                conn.commit()
        elif ch == 'q':
            break


# ------------------------------ EXPORT ------------------------------

def fetch_all(conn: sqlite3.Connection, inc_id: int):
    inc = conn.execute("SELECT * FROM incidents WHERE id=?", (inc_id,)).fetchone()
    roles = conn.execute("SELECT * FROM roles WHERE incident_id=? ORDER BY id", (inc_id,)).fetchall()
    triggers = conn.execute("SELECT * FROM triggers WHERE incident_id=? ORDER BY id", (inc_id,)).fetchall()
    tasks_im = conn.execute("SELECT * FROM tasks WHERE incident_id=? AND phase='immediate' ORDER BY id", (inc_id,)).fetchall()
    tasks_nx = conn.execute("SELECT * FROM tasks WHERE incident_id=? AND phase='next' ORDER BY id", (inc_id,)).fetchall()
    tasks_af = conn.execute("SELECT * FROM tasks WHERE incident_id=? AND phase='aftermath' ORDER BY id", (inc_id,)).fetchall()
    evidence = conn.execute("SELECT * FROM evidence WHERE incident_id=? ORDER BY id", (inc_id,)).fetchall()
    timeline = conn.execute("SELECT * FROM timeline WHERE incident_id=? ORDER BY time", (inc_id,)).fetchall()
    checklist = conn.execute("SELECT * FROM checklist WHERE incident_id=? ORDER BY id", (inc_id,)).fetchall()
    return inc, roles, triggers, tasks_im, tasks_nx, tasks_af, evidence, timeline, checklist


def md_escape(s: str) -> str:
    return s.replace("|", "\\|")


def export_markdown(conn: sqlite3.Connection, inc_id: int, out_path: str) -> str:
    inc, roles, triggers, t_im, t_nx, t_af, evid, tl, chk = fetch_all(conn, inc_id)
    if not inc:
        raise RuntimeError("Incident not found")

    def task_lines(rows):
        out = []
        for r in rows:
            mark = {"done": "x", "pending": " ", "na": "-"}.get(r['status'] or "pending", " ")
            out.append(f"- [{mark}] **{r['description']}**\n  - Time: {r['time'] or ''}\n  - Notes: {r['notes'] or ''}")
        return "\n".join(out) or "_No tasks recorded._"

    def checklist_lines(rows):
        out = []
        for r in rows:
            mark = "x" if r['checked'] else " "
            out.append(f"- [{mark}] {r['item']}")
        return "\n".join(out) or "_No checklist items._"

    md = []
    md.append(f"# Incident Report: {inc['name'] or '(unnamed)'}")
    md.append("")
    md.append(f"Generated: {NOW()}")
    md.append("")
    md.append("## Metadata")
    md.append(f"- **Incident ID:** {inc['incident_key'] or 'N/A'}")
    md.append(f"- **Severity:** {inc['severity'] or 'N/A'}")
    md.append(f"- **Classification:** {inc['classification'] or 'Confidential'}")
    md.append(f"- **Reported by:** {inc['reported_by'] or 'N/A'}")
    md.append(f"- **Primary detection source:** {inc['detection_source'] or 'N/A'}")
    md.append(f"- **Incident start (first known):** {inc['incident_start'] or 'N/A'}")
    md.append(f"- **Status:** {inc['status'] or 'open'}")
    md.append("")

    md.append("## Incident Channel / Roles")
    if roles:
        for r in roles:
            md.append(f"- **{r['role']}:** {r['person']}")
    else:
        md.append("_No roles recorded._")
    md.append("")

    md.append("## Triggers")
    if triggers:
        for r in triggers:
            md.append(f"- {r['description']}")
    else:
        md.append("- (none)")
    md.append("")

    md.append("## Immediate Actions (first 60–120 minutes)")
    md.append(task_lines(t_im))
    md.append("")

    md.append("### Evidence Map")
    if evid:
        md.append("| Artifact | Path | SHA-256 | Notes |")
        md.append("|---|---|---|---|")
        for r in evid:
            md.append(f"| {md_escape(r['artifact'] or '')} | `{r['path'] or ''}` | `{r['sha256'] or ''}` | {md_escape(r['notes'] or '')} |")
    else:
        md.append("_No evidence entries recorded._")
    md.append("")

    md.append("## Next 24–72 Hours")
    md.append(task_lines(t_nx))
    md.append("")

    md.append("## Afterwards (≤ 2 weeks)")
    md.append(task_lines(t_af))
    md.append("")

    md.append("## Timeline")
    if tl:
        md.append("| Time (UTC) | Actor | Event | Decisions/Notes |")
        md.append("|---|---|---|---|")
        for r in tl:
            md.append(f"| {md_escape(r['time'] or '')} | {md_escape(r['actor'] or '')} | {md_escape(r['event'] or '')} | {md_escape(r['decision'] or '')} |")
    else:
        md.append("_No timeline events recorded._")
    md.append("")

    md.append("## Executive Checklist")
    md.append(checklist_lines(chk))
    md.append("")

    md.append("## Appendix")
    md.append("- Report generated by incident_manager.py (SQLite-backed DFIR tool)")
    md.append("- Times recorded in UTC (Z)")

    content = "\n".join(md) + "\n"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(content)
    return out_path


def export_html(md_path: str, html_path: str) -> str:
    """Very simple Markdown→HTML wrapper (no external libs).
    We only handle basic paragraphs, headers (#..), lists, and tables already composed in MD.
    For richer HTML, convert with pandoc outside this tool.
    """
    try:
        with open(md_path, "r", encoding="utf-8") as f:
            md = f.read()
        # Extremely lightweight conversion: wrap MD in <pre> to preserve formatting
        html = f"""<!doctype html>
<html><head><meta charset='utf-8'><title>Incident Report</title>
<style>body{{font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; padding: 2rem;}}
pre{{white-space: pre-wrap;}}
</style></head><body><pre>{md}</pre></body></html>"""
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html)
        return html_path
    except Exception as e:
        raise RuntimeError(f"HTML export failed: {e}")


def export_pdf(md_path: str, pdf_path: str) -> Optional[str]:
    if not PDF_AVAILABLE:
        return None
    styles = getSampleStyleSheet()
    story = []
    with open(md_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.rstrip('\n')
            if line.startswith('# '):
                story.append(Paragraph(f"<b>{line[2:]}</b>", styles['Title']))
                story.append(Spacer(1, 12))
            elif line.startswith('## '):
                story.append(Paragraph(f"<b>{line[3:]}</b>", styles['Heading2']))
                story.append(Spacer(1, 8))
            elif line.startswith('### '):
                story.append(Paragraph(f"<b>{line[4:]}</b>", styles['Heading3'])))
                story.append(Spacer(1, 6))
            elif line.startswith('- '):
                story.append(Paragraph(line[2:], styles['Normal']))
            elif line.startswith('|') and line.endswith('|'):
                # Naive table support: collect until non-table line
                table_lines = [line]
                for nextline in f:
                    nl = nextline.rstrip('\n')
                    if nl.startswith('|') and nl.endswith('|'):
                        table_lines.append(nl)
                    else:
                        # push back the consumed non-table line by processing it next
                        remainder = nl + "\n" + f.read()
                        # rebuild iterator by ending loop and processing remainder later
                        # (simple approach: append remainder as paragraphs)
                        if remainder.strip():
                            for para in remainder.splitlines():
                                if para:
                                    story.append(Paragraph(para, styles['Normal']))
                        break
                # Parse table
                cells = [row.strip('|').split('|') for row in table_lines if not set(row.strip()) == {'|', '-'}]
                cells = [[c.strip() for c in row] for row in cells]
                tbl = Table(cells, hAlign='LEFT')
                tbl.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,0), colors.lightgrey),
                    ('GRID', (0,0), (-1,-1), 0.25, colors.grey),
                    ('VALIGN', (0,0), (-1,-1), 'TOP'),
                ]))
                story.append(tbl)
                story.append(Spacer(1, 6))
            elif line.strip() == '':
                story.append(Spacer(1, 6))
            else:
                story.append(Paragraph(line, styles['Normal']))
    doc = SimpleDocTemplate(pdf_path, pagesize=A4)
    doc.build(story)
    return pdf_path


# ------------------------------ VIEW ------------------------------

def quick_view(conn: sqlite3.Connection, inc_id: int):
    inc, roles, triggers, t_im, t_nx, t_af, evid, tl, chk = fetch_all(conn, inc_id)
    if not inc:
        print("Incident not found")
        return
    print(f"\n== {inc['name']} (ID: {inc['incident_key'] or inc_id}) ==")
    print(f"Severity: {inc['severity']} | Status: {inc['status']} | Start: {inc['incident_start']}")
    print("-- Tasks immediate/next/aftermath (done/total) --")
    def stats(rows):
        return sum(1 for r in rows if r['status']== 'done'), len(rows)
    a,b = stats(t_im); c,d = stats(t_nx); e,f = stats(t_af)
    print(f"Immediate: {a}/{b} | Next: {c}/{d} | Aftermath: {e}/{f}")
    print(f"Timeline events: {len(tl)} | Evidence items: {len(evid)} | Checklist: {sum(1 for r in chk if r['checked'])}/{len(chk)}")


# ------------------------------ MENUS ------------------------------

def incident_menu(conn: sqlite3.Connection, inc_id: int):
    while True:
        quick_view(conn, inc_id)
        print(textwrap.dedent("""
        [1] Edit metadata
        [2] Roles
        [3] Triggers
        [4] Tasks
        [5] Evidence
        [6] Timeline
        [7] Executive checklist
        [8] Export
        [9] Close incident (set status closed)
        [q] Back
        """))
        ch = input("> ").strip().lower()
        if ch == '1':
            edit_metadata(conn, inc_id)
        elif ch == '2':
            edit_roles(conn, inc_id)
        elif ch == '3':
            edit_triggers(conn, inc_id)
        elif ch == '4':
            edit_tasks(conn, inc_id)
        elif ch == '5':
            edit_evidence(conn, inc_id)
        elif ch == '6':
            edit_timeline(conn, inc_id)
        elif ch == '7':
            edit_checklist(conn, inc_id)
        elif ch == '8':
            do_export(conn, inc_id)
        elif ch == '9':
            conn.execute("UPDATE incidents SET status=?, updated_at=? WHERE id=?", ("closed", NOW(), inc_id))
            conn.commit()
            print("Status set to closed.")
        elif ch == 'q':
            break


def do_export(conn: sqlite3.Connection, inc_id: int):
    out_dir = os.path.join("exports", f"incident_{inc_id}")
    os.makedirs(out_dir, exist_ok=True)
    md_path = os.path.join(out_dir, "incident_report.md")
    html_path = os.path.join(out_dir, "incident_report.html")
    pdf_path = os.path.join(out_dir, "incident_report.pdf")

    export_markdown(conn, inc_id, md_path)
    export_html(md_path, html_path)
    pdf_done = export_pdf(md_path, pdf_path) if PDF_AVAILABLE else None

    print("\nExports written:")
    print(f"- Markdown: {md_path}")
    print(f"- HTML:     {html_path}")
    if pdf_done:
        print(f"- PDF:      {pdf_path}")
    else:
        print("- PDF:      (install 'reportlab' to enable)")


def select_incident(conn: sqlite3.Connection) -> Optional[int]:
    rows = list_incidents(conn)
    if not rows:
        return None
    try:
        inc_id = int(prompt("Enter incident numeric ID to open"))
        r = conn.execute("SELECT id FROM incidents WHERE id=?", (inc_id,)).fetchone()
        return r['id'] if r else None
    except Exception:
        print("Invalid.")
        return None


def main_menu(conn: sqlite3.Connection):
    while True:
        print(textwrap.dedent("""
        ==== Incident Manager ====
        1) List incidents
        2) Create new incident
        3) Open incident
        4) Export incident
        5) Delete incident
        q) Quit
        """))
        ch = input("> ").strip().lower()
        if ch == '1':
            list_incidents(conn)
        elif ch == '2':
            create_incident(conn)
        elif ch == '3':
            inc_id = select_incident(conn)
            if inc_id:
                incident_menu(conn, inc_id)
        elif ch == '4':
            inc_id = select_incident(conn)
            if inc_id:
                do_export(conn, inc_id)
        elif ch == '5':
            delete_incident(conn)
        elif ch == 'q':
            break


def parse_args():
    ap = argparse.ArgumentParser(description="Interactive DFIR AppSec Incident Reporter")
    ap.add_argument("--db", default=DB_DEFAULT, help="Path to SQLite DB (default: db/ir.sqlite3)")
    ap.add_argument("--export", help="Export incident by numeric ID and exit")
    return ap.parse_args()


def main():
    args = parse_args()
    conn = connect(args.db)

    if args.export:
        try:
            inc_id = int(args.export)
        except ValueError:
            print("--export expects a numeric incident ID")
            return
        do_export(conn, inc_id)
        return

    main_menu(conn)


if __name__ == "__main__":
    main()