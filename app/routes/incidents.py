"""Incident management routes."""
import secrets
from datetime import datetime, timezone
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, or_
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.models import (
    IncidentCreate,
    IncidentUpdate,
    IncidentListItem,
    Incident,
    TaskEntry,
    EvidenceEntry,
    TimelineEntry,
    ChecklistItem,
    UserRole,
)
from app.database import (
    Incident as IncidentModel,
    AuditLog,
    IncidentRole,
    IncidentTask,
    EvidenceEntry as EvidenceModel,
    TimelineEntry as TimelineModel,
    ChecklistItem as ChecklistModel,
    IncidentACL,
)
from app.security import (
    get_current_user,
    require_role,
    InputValidator,
    RateLimitConfig,
    check_incident_permission,
    grant_incident_permissions,
)

router = APIRouter()
limiter = Limiter(key_func=get_remote_address)


def gen_incident_key() -> str:
    """Generate secure incident ID in format: INC-YYYYMMDD-XXXXXX"""
    # Use cryptographically secure random hex (6 chars = 24-bit entropy = 16M combinations)
    random_suffix = secrets.token_hex(3)
    today = datetime.now(timezone.utc)
    return f"INC-{today:%Y%m%d}-{random_suffix.upper()}"


async def log_audit(
    session: AsyncSession,
    user_id: int,
    action: str,
    resource_type: str,
    resource_id: str = None,
    incident_id: int = None,
    changes: dict = None,
    ip_address: str = None,
):
    """Log audit trail for compliance."""
    audit_entry = AuditLog(
        user_id=user_id,
        incident_id=incident_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        changes=changes,
        ip_address=ip_address,
    )
    session.add(audit_entry)
    await session.flush()


@router.post("", response_model=Incident, status_code=status.HTTP_201_CREATED)
@limiter.limit(RateLimitConfig.CREATE_INCIDENT_LIMIT)
async def create_incident(
    request: Request,
    incident_data: IncidentCreate,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(lambda: None),
):
    """Create a new incident."""
    from app.main import AsyncSessionLocal
    
    async with AsyncSessionLocal() as session:
        # Only IR_LEAD, ADMIN can create incidents
        if UserRole.IR_LEAD not in current_user.roles and UserRole.ADMIN not in current_user.roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only IR leads can create incidents",
            )
        
        # Generate incident key
        incident_key = gen_incident_key()
        
        # Create incident
        new_incident = IncidentModel(
            incident_key=incident_key,
            name=incident_data.metadata.name,
            severity=incident_data.metadata.severity.value,
            classification=incident_data.metadata.classification.value,
            reported_by=incident_data.metadata.reported_by,
            detection_source=incident_data.metadata.detection_source,
            incident_start=incident_data.metadata.incident_start,
            created_by_id=int(current_user.user_id),
            status="open",
        )
        
        session.add(new_incident)
        await session.flush()
        
        # Add roles
        for role_assignment in incident_data.roles:
            incident_role = IncidentRole(
                incident_id=new_incident.id,
                role=role_assignment.role.value,
                person=role_assignment.person,
            )
            session.add(incident_role)
        
        # Log audit
        await log_audit(
            session,
            user_id=int(current_user.user_id),
            action="create",
            resource_type="incident",
            resource_id=incident_key,
            incident_id=new_incident.id,
            ip_address=request.state.client_ip,
        )
        
        await session.commit()
        await session.refresh(new_incident)
        
        # Grant creator full permissions on incident
        await grant_incident_permissions(
            incident_id=new_incident.id,
            user_id=int(current_user.user_id),
            can_view=True,
            can_edit=True,
            can_delete=True,
        )
        
        return _incident_to_response(new_incident)


@router.get("", response_model=List[IncidentListItem])
@limiter.limit(RateLimitConfig.DEFAULT_LIMIT)
async def list_incidents(
    request: Request,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    status_filter: str = Query(None),
    severity_filter: str = Query(None),
    current_user=Depends(get_current_user),
):
    """List incidents with pagination and filtering. Only returns incidents user can view."""
    from app.main import AsyncSessionLocal
    
    async with AsyncSessionLocal() as session:
        user_id = int(current_user.user_id)
        
        # Query incidents where user is creator OR has view permission
        query = select(IncidentModel).where(
            or_(
                IncidentModel.created_by_id == user_id,
                IncidentModel.id.in_(
                    select(IncidentACL.incident_id).where(
                        (IncidentACL.user_id == user_id) & (IncidentACL.can_view == True)
                    )
                )
            )
        ).order_by(desc(IncidentModel.created_at))
        
        # Filter by status if provided
        if status_filter:
            query = query.filter(IncidentModel.status == status_filter)
        
        # Filter by severity if provided
        if severity_filter:
            query = query.filter(IncidentModel.severity == severity_filter)
        
        # Apply pagination
        query = query.offset(skip).limit(limit)
        
        result = await session.execute(query)
        incidents = result.scalars().all()
        
        return [
            IncidentListItem(
                id=inc.id,
                incident_key=inc.incident_key,
                name=inc.name,
                severity=inc.severity,
                status=inc.status,
                created_at=inc.created_at,
                updated_at=inc.updated_at,
            )
            for inc in incidents
        ]


@router.get("/{incident_id}", response_model=Incident)
@limiter.limit(RateLimitConfig.DEFAULT_LIMIT)
async def get_incident(
    request: Request,
    incident_id: int,
    current_user=Depends(get_current_user),
):
    """Get incident details. Requires can_view permission."""
    from app.main import AsyncSessionLocal
    
    # Check permission
    has_permission = await check_incident_permission(
        incident_id=incident_id,
        user_id=int(current_user.user_id),
        permission="can_view",
    )
    
    if not has_permission:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to view this incident",
        )
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(IncidentModel).filter(IncidentModel.id == incident_id)
        )
        incident = result.scalars().first()
        
        if not incident:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Incident not found",
            )
        
        # Log audit - view action
        await log_audit(
            session,
            user_id=int(current_user.user_id),
            action="view",
            resource_type="incident",
            resource_id=str(incident_id),
            incident_id=incident_id,
            ip_address=request.state.client_ip,
        )
        
        await session.commit()
        
        return _incident_to_response(incident)


@router.patch("/{incident_id}", response_model=Incident)
@limiter.limit(RateLimitConfig.DEFAULT_LIMIT)
async def update_incident(
    request: Request,
    incident_id: int,
    incident_data: IncidentUpdate,
    current_user=Depends(require_role(UserRole.IR_LEAD, UserRole.ADMIN)),
):
    """Update incident details. Requires can_edit permission."""
    from app.main import AsyncSessionLocal
    
    # Check permission
    has_permission = await check_incident_permission(
        incident_id=incident_id,
        user_id=int(current_user.user_id),
        permission="can_edit",
    )
    
    if not has_permission:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to edit this incident",
        )
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(IncidentModel).filter(IncidentModel.id == incident_id)
        )
        incident = result.scalars().first()
        
        if not incident:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Incident not found",
            )
        
        # Track changes for audit
        changes = {}
        
        # Update metadata
        if incident_data.metadata:
            if incident.name != incident_data.metadata.name:
                changes["name"] = {"old": incident.name, "new": incident_data.metadata.name}
                incident.name = incident_data.metadata.name
            
            if incident.severity != incident_data.metadata.severity.value:
                changes["severity"] = {"old": incident.severity, "new": incident_data.metadata.severity.value}
                incident.severity = incident_data.metadata.severity.value
        
        # Update roles if provided
        if incident_data.roles is not None:
            # Delete existing roles
            await session.execute(
                select(IncidentRole).filter(IncidentRole.incident_id == incident_id).delete()
            )
            
            # Add new roles
            for role_assignment in incident_data.roles:
                incident_role = IncidentRole(
                    incident_id=incident_id,
                    role=role_assignment.role.value,
                    person=role_assignment.person,
                )
                session.add(incident_role)
        
        # Log audit
        await log_audit(
            session,
            user_id=int(current_user.user_id),
            action="update",
            resource_type="incident",
            resource_id=str(incident_id),
            incident_id=incident_id,
            changes=changes if changes else None,
            ip_address=request.state.client_ip,
        )
        
        await session.commit()
        await session.refresh(incident)
        
        return _incident_to_response(incident)


@router.delete("/{incident_id}", status_code=status.HTTP_204_NO_CONTENT)
@limiter.limit(RateLimitConfig.DEFAULT_LIMIT)
async def delete_incident(
    request: Request,
    incident_id: int,
    current_user=Depends(require_role(UserRole.ADMIN)),
):
    """Delete an incident. Requires can_delete permission (admins or incident creator)."""
    from app.main import AsyncSessionLocal
    
    # Check permission
    has_permission = await check_incident_permission(
        incident_id=incident_id,
        user_id=int(current_user.user_id),
        permission="can_delete",
    )
    
    if not has_permission:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to delete this incident",
        )
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(IncidentModel).filter(IncidentModel.id == incident_id)
        )
        incident = result.scalars().first()
        
        if not incident:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Incident not found",
            )
        
        incident_key = incident.incident_key
        
        # Log audit before deletion
        await log_audit(
            session,
            user_id=int(current_user.user_id),
            action="delete",
            resource_type="incident",
            resource_id=incident_key,
            incident_id=incident_id,
            ip_address=request.state.client_ip,
        )
        
        await session.delete(incident)
        await session.commit()


def _incident_to_response(incident: IncidentModel) -> Incident:
    """Convert ORM incident to Pydantic response."""
    return Incident(
        id=incident.id,
        incident_key=incident.incident_key,
        severity=incident.severity,
        status=incident.status,
        created_at=incident.created_at,
        updated_at=incident.updated_at,
        created_by_id=incident.created_by_id,
        metadata={
            "name": incident.name,
            "severity": incident.severity,
            "classification": incident.classification,
            "reported_by": incident.reported_by,
            "detection_source": incident.detection_source,
            "incident_start": incident.incident_start,
        },
        roles=[
            {"role": r.role, "person": r.person}
            for r in incident.roles
        ],
        triggers=[
            {"method": t.method, "detection_time": t.detection_time}
            for t in incident.triggers
        ],
        tasks=[
            {
                "phase": t.phase,
                "task_type": t.task_type,
                "description": t.description,
                "assigned_to": t.assigned_to,
                "status": t.status,
                "due_date": t.due_date,
            }
            for t in incident.tasks
        ],
        evidence=[
            {
                "location": e.location,
                "description": e.description,
                "hash_sha256": e.hash_sha256,
                "collected_at": e.collected_at,
            }
            for e in incident.evidence
        ],
        timeline=[
            {
                "timestamp": t.timestamp,
                "event": t.event,
                "source": t.source,
            }
            for t in incident.timeline_entries
        ],
        checklist=[
            {
                "item": c.item,
                "completed": c.completed,
            }
            for c in incident.checklist_items
        ],
    )
