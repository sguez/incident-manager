"""Audit log routes for compliance."""
from typing import List
from datetime import datetime
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from app.models import AuditLog, UserRole
from app.database import AuditLog as AuditLogModel
from app.security import get_current_user, require_role

router = APIRouter()


@router.get("")
async def get_audit_logs(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    incident_id: int = Query(None),
    user_id: int = Query(None),
    action: str = Query(None),
    current_user=Depends(require_role(UserRole.ADMIN)),
):
    """Get audit logs (admin only). Useful for DFIR investigations."""
    from app.main import AsyncSessionLocal
    
    async with AsyncSessionLocal() as session:
        query = select(AuditLogModel).order_by(desc(AuditLogModel.timestamp))
        
        if incident_id:
            query = query.filter(AuditLogModel.incident_id == incident_id)
        
        if user_id:
            query = query.filter(AuditLogModel.user_id == user_id)
        
        if action:
            query = query.filter(AuditLogModel.action == action)
        
        query = query.offset(skip).limit(limit)
        
        result = await session.execute(query)
        logs = result.scalars().all()
        
        return [
            {
                "id": log.id,
                "user_id": log.user_id,
                "incident_id": log.incident_id,
                "action": log.action,
                "resource_type": log.resource_type,
                "resource_id": log.resource_id,
                "changes": log.changes,
                "timestamp": log.timestamp,
                "ip_address": log.ip_address,
            }
            for log in logs
        ]


@router.get("/incident/{incident_id}")
async def get_incident_audit_logs(
    incident_id: int,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    current_user=Depends(get_current_user),
):
    """Get audit logs for a specific incident."""
    from app.main import AsyncSessionLocal
    
    async with AsyncSessionLocal() as session:
        query = select(AuditLogModel).filter(
            AuditLogModel.incident_id == incident_id
        ).order_by(desc(AuditLogModel.timestamp)).offset(skip).limit(limit)
        
        result = await session.execute(query)
        logs = result.scalars().all()
        
        return [
            {
                "id": log.id,
                "user_id": log.user_id,
                "action": log.action,
                "resource_type": log.resource_type,
                "changes": log.changes,
                "timestamp": log.timestamp,
                "ip_address": log.ip_address,
            }
            for log in logs
        ]
