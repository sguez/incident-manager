# Incident Manager (DFIR AppSec) 🛡️

Interactive, SQLite-backed incident manager for Digital Forensics & Incident Response (DFIR) with an **application security** focus.  
It guides engineers through CISO-friendly stages (Immediate, Next 24–72h, Aftermath), captures evidence and timelines, and exports clean reports for Confluence/GitHub/leadership.

## Features

- **Interactive TUI** for:
  - Metadata & roles (IR lead, App owner/Dev, SRE/DevOps, SecOps, Comms, Legal)
  - Triggers (with suggested AppSec scenarios)
  - Tasks by phase (Immediate / Next 24–72h / Aftermath)
  - Evidence map (optional SHA-256 hashing)
  - Timeline (UTC ISO-8601)
  - Executive checklist
- **SQLite persistence** (`db/ir.sqlite3`) so you can return and edit later
- **Pre-populated** tasks & checklist aligned to the playbook
- **Exports** to:
  - Markdown (`exports/incident_<ID>/incident_report.md`)
  - HTML (`exports/incident_<ID>/incident_report.html`)
  - PDF (`exports/incident_<ID>/incident_report.pdf`) — if `reportlab` is installed
- **Incident ID format:** `xxxx-YYYY-MM-DD` (4 random lowercase letters/digits + date). You can edit it later if needed.

## Quick Start

```bash
python3 -m venv .venv && source .venv/bin/activate   # optional
python3 -m pip install --upgrade pip
# Optional for PDF export:
python3 -m pip install reportlab

python3 incident_manager.py

## Reference https://blog.sguez.dev/dfir-application-security-a-practical-incident-response-playbook-for-cisos-b31fb4253782
