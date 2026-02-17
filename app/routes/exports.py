"""Export routes - Markdown, HTML, PDF."""
import os
from fastapi import APIRouter, HTTPException, status, Request, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from slowapi import Limiter
from slowapi.util import get_remote_address
from fastapi.responses import FileResponse

from app.models import UserRole
from app.database import Incident as IncidentModel, AuditLog
from app.security import get_current_user, require_role, md_escape, html_escape, RateLimitConfig

router = APIRouter()
limiter = Limiter(key_func=get_remote_address)


async def log_audit(session: AsyncSession, user_id: int, action: str, resource_type: str,
                   resource_id: str = None, incident_id: int = None, ip_address: str = None):
    """Log audit trail."""
    audit_entry = AuditLog(
        user_id=user_id,
        incident_id=incident_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        ip_address=ip_address,
    )
    session.add(audit_entry)
    await session.flush()


@router.post("/{incident_id}/markdown")
@limiter.limit(RateLimitConfig.EXPORT_LIMIT)
async def export_markdown(
    request: Request,
    incident_id: int,
    current_user=Depends(get_current_user),
):
    """Export incident as Markdown."""
    from app.main import AsyncSessionLocal
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(IncidentModel).filter(IncidentModel.id == incident_id)
        )
        incident = result.scalars().first()
        
        if not incident:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
        
        # Generate markdown
        md_content = _generate_markdown(incident)
        
        # Log export action
        await log_audit(
            session,
            user_id=int(current_user.user_id),
            action="export",
            resource_type="incident",
            resource_id=str(incident_id),
            incident_id=incident_id,
            ip_address=request.state.client_ip,
        )
        await session.commit()
        
        # Save to file
        os.makedirs(f"exports/incident_{incident_id}", exist_ok=True)
        file_path = f"exports/incident_{incident_id}/incident_report.md"
        
        with open(file_path, "w") as f:
            f.write(md_content)
        
        return {"path": file_path, "format": "markdown"}


@router.post("/{incident_id}/html")
@limiter.limit(RateLimitConfig.EXPORT_LIMIT)
async def export_html(
    request: Request,
    incident_id: int,
    current_user=Depends(get_current_user),
):
    """Export incident as HTML."""
    from app.main import AsyncSessionLocal
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(IncidentModel).filter(IncidentModel.id == incident_id)
        )
        incident = result.scalars().first()
        
        if not incident:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
        
        # Generate HTML
        html_content = _generate_html(incident)
        
        # Log export action
        await log_audit(
            session,
            user_id=int(current_user.user_id),
            action="export",
            resource_type="incident",
            resource_id=str(incident_id),
            incident_id=incident_id,
            ip_address=request.state.client_ip,
        )
        await session.commit()
        
        # Save to file
        os.makedirs(f"exports/incident_{incident_id}", exist_ok=True)
        file_path = f"exports/incident_{incident_id}/incident_report.html"
        
        with open(file_path, "w") as f:
            f.write(html_content)
        
        return {"path": file_path, "format": "html"}


@router.post("/{incident_id}/pdf")
@limiter.limit(RateLimitConfig.EXPORT_LIMIT)
async def export_pdf(
    request: Request,
    incident_id: int,
    current_user=Depends(get_current_user),
):
    """Export incident as PDF (if reportlab available)."""
    from app.main import AsyncSessionLocal
    
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib import colors
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    except ImportError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="PDF export not available - reportlab not installed",
        )
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(IncidentModel).filter(IncidentModel.id == incident_id)
        )
        incident = result.scalars().first()
        
        if not incident:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
        
        # Log export action
        await log_audit(
            session,
            user_id=int(current_user.user_id),
            action="export",
            resource_type="incident",
            resource_id=str(incident_id),
            incident_id=incident_id,
            ip_address=request.state.client_ip,
        )
        await session.commit()
        
        # Generate PDF
        os.makedirs(f"exports/incident_{incident_id}", exist_ok=True)
        file_path = f"exports/incident_{incident_id}/incident_report.pdf"
        
        doc = SimpleDocTemplate(file_path, pagesize=A4)
        elements = []
        styles = getSampleStyleSheet()
        
        # Add title
        title = Paragraph(f"Incident Report: {incident.incident_key}", styles['Heading1'])
        elements.append(title)
        elements.append(Spacer(1, 12))
        
        # Add metadata
        metadata_text = f"""
        <b>Severity:</b> {incident.severity}<br/>
        <b>Status:</b> {incident.status}<br/>
        <b>Classification:</b> {incident.classification}<br/>
        <b>Reported By:</b> {html_escape(incident.reported_by)}<br/>
        <b>Detection Source:</b> {html_escape(incident.detection_source)}
        """
        elements.append(Paragraph(metadata_text, styles['Normal']))
        elements.append(Spacer(1, 12))
        
        # Build PDF
        doc.build(elements)
        
        return {"path": file_path, "format": "pdf"}


def _generate_markdown(incident) -> str:
    """Generate Markdown export."""
    md = f"""# Incident Report: {incident.incident_key}

## Metadata

| Field | Value |
|-------|-------|
| Name | {md_escape(incident.name)} |
| Severity | {incident.severity} |
| Classification | {incident.classification} |
| Status | {incident.status} |
| Reported By | {md_escape(incident.reported_by)} |
| Detection Source | {md_escape(incident.detection_source)} |
| Incident Start | {incident.incident_start} |
| Created At | {incident.created_at} |

## Roles

| Role | Person |
|------|--------|
"""
    
    for role in incident.roles:
        md += f"| {md_escape(role.role)} | {md_escape(role.person)} |\n"
    
    # Add sections for triggers, tasks, evidence, timeline, checklist
    if incident.triggers:
        md += "\n## Triggers\n\n"
        for trigger in incident.triggers:
            md += f"- {md_escape(trigger.method)} (detected: {trigger.detection_time})\n"
    
    if incident.tasks:
        md += "\n## Tasks\n\n"
        for task in incident.tasks:
            status_str = f" [{task.status}]" if task.status else ""
            md += f"- [{task.phase}] {md_escape(task.description)}{status_str}\n"
    
    if incident.evidence:
        md += "\n## Evidence\n\n"
        for evidence in incident.evidence:
            md += f"- {md_escape(evidence.location)}\n"
            if evidence.hash_sha256:
                md += f"  - SHA256: {evidence.hash_sha256}\n"
    
    if incident.timeline_entries:
        md += "\n## Timeline\n\n"
        for entry in incident.timeline_entries:
            md += f"- {entry.timestamp}: {md_escape(entry.event)} (source: {md_escape(entry.source)})\n"
    
    if incident.checklist_items:
        md += "\n## Executive Checklist\n\n"
        for item in incident.checklist_items:
            check = "✓" if item.completed else "○"
            md += f"- {check} {md_escape(item.item)}\n"
    
    return md


def _generate_html(incident) -> str:
    """Generate HTML export."""
    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Incident Report: {html_escape(incident.incident_key)}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #333; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        .severity-critical {{ color: #d32f2f; font-weight: bold; }}
        .severity-high {{ color: #f57c00; font-weight: bold; }}
        .severity-medium {{ color: #fbc02d; font-weight: bold; }}
        .severity-low {{ color: #388e3c; font-weight: bold; }}
    </style>
</head>
<body>
    <h1>Incident Report: {html_escape(incident.incident_key)}</h1>
    
    <h2>Metadata</h2>
    <table>
        <tr><th>Field</th><th>Value</th></tr>
        <tr><td>Name</td><td>{html_escape(incident.name)}</td></tr>
        <tr><td>Severity</td><td class="severity-{incident.severity}">{incident.severity}</td></tr>
        <tr><td>Classification</td><td>{incident.classification}</td></tr>
        <tr><td>Status</td><td>{incident.status}</td></tr>
        <tr><td>Reported By</td><td>{html_escape(incident.reported_by)}</td></tr>
        <tr><td>Created At</td><td>{incident.created_at}</td></tr>
    </table>
"""
    
    if incident.roles:
        html += "<h2>Roles</h2><table><tr><th>Role</th><th>Person</th></tr>"
        for role in incident.roles:
            html += f"<tr><td>{role.role}</td><td>{html_escape(role.person)}</td></tr>"
        html += "</table>"
    
    html += "</body></html>"
    return html
