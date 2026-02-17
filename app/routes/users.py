"""User management routes (admin only)."""
from typing import List
from fastapi import APIRouter, HTTPException, status, Request, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models import User, UserRole
from app.database import User as UserModel
from app.security import get_current_user, require_role

router = APIRouter()


@router.get("", response_model=List[User])
async def list_users(
    request: Request,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    current_user=Depends(require_role(UserRole.ADMIN)),
):
    """List users (admin only)."""
    from app.main import AsyncSessionLocal
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(UserModel).offset(skip).limit(limit)
        )
        users = result.scalars().all()
        
        return [
            User(
                id=u.id,
                username=u.username,
                email=u.email,
                roles=u.roles,
                created_at=u.created_at,
            )
            for u in users
        ]


@router.patch("/{user_id}/roles")
async def update_user_roles(
    request: Request,
    user_id: int,
    roles: List[UserRole],
    current_user=Depends(require_role(UserRole.ADMIN)),
):
    """Update user roles (admin only)."""
    from app.main import AsyncSessionLocal
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(UserModel).filter(UserModel.id == user_id)
        )
        user = result.scalars().first()
        
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
        
        user.roles = [r.value for r in roles]
        await session.commit()
        
        return {"user_id": user_id, "roles": user.roles}


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    request: Request,
    user_id: int,
    current_user=Depends(require_role(UserRole.ADMIN)),
):
    """Delete user (admin only)."""
    from app.main import AsyncSessionLocal
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(UserModel).filter(UserModel.id == user_id)
        )
        user = result.scalars().first()
        
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
        
        await session.delete(user)
        await session.commit()
