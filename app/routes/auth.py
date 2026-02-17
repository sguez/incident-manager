"""Authentication routes."""
from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.models import TokenResponse, UserCreate, LoginRequest
from app.database import User as UserModel
from app.security import (
    get_current_user,
    create_access_token,
    hash_password,
    verify_password,
    RateLimitConfig,
    AuthenticationError,
)

router = APIRouter()
limiter = Limiter(key_func=get_remote_address)


@router.post("/login", response_model=TokenResponse)
@limiter.limit(RateLimitConfig.AUTH_LIMIT)
async def login(
    request: Request,
    credentials: LoginRequest,
    db: AsyncSession = Depends(lambda: None),
):
    """
    Login with validated credentials.
    Returns JWT access token.
    - **username**: Alphanumeric, hyphen, underscore (3-50 chars)
    - **password**: 8-255 characters
    """
    # Get DB session from app state
    from app.main import AsyncSessionLocal
    async with AsyncSessionLocal() as session:
        # Find user by validated username
        result = await session.execute(
            select(UserModel).filter(UserModel.username == credentials.username)
        )
        user = result.scalars().first()
        
        if not user or not verify_password(credentials.password, user.password_hash):
            raise AuthenticationError("Invalid credentials")
        
        if not user.is_active:
            raise AuthenticationError("User account is inactive")
        
        # Create token
        access_token = create_access_token(
            user_id=str(user.id),
            username=user.username,
            roles=user.roles,
        )
        
        return TokenResponse(
            access_token=access_token,
            token_type="bearer",
            expires_in=24 * 3600,  # 24 hours in seconds
        )


@router.post("/register", response_model=TokenResponse)
@limiter.limit(RateLimitConfig.AUTH_LIMIT)
async def register(
    request: Request,
    user_data: UserCreate,
):
    """
    Register a new user.
    Default role is 'viewer'.
    """
    from app.main import AsyncSessionLocal
    
    async with AsyncSessionLocal() as session:
        # Check if user exists
        result = await session.execute(
            select(UserModel).filter(
                (UserModel.username == user_data.username) |
                (UserModel.email == user_data.email)
            )
        )
        existing = result.scalars().first()
        
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Username or email already exists",
            )
        
        # Create user with default viewer role
        new_user = UserModel(
            username=user_data.username,
            email=user_data.email,
            password_hash=hash_password(user_data.password),
            roles=["viewer"],  # Default to viewer
        )
        
        session.add(new_user)
        await session.commit()
        await session.refresh(new_user)
        
        # Create token
        access_token = create_access_token(
            user_id=str(new_user.id),
            username=new_user.username,
            roles=new_user.roles,
        )
        
        return TokenResponse(
            access_token=access_token,
            token_type="bearer",
            expires_in=24 * 3600,
        )


@router.get("/me")
async def get_current_user_info(
    request: Request,
    current_user=Depends(get_current_user),
):
    """Get current logged-in user info."""
    return {
        "user_id": current_user.user_id,
        "username": current_user.username,
        "roles": [r.value for r in current_user.roles],
    }


@router.post("/refresh")
@limiter.limit(RateLimitConfig.AUTH_LIMIT)
async def refresh_token(
    request: Request,
    current_user=Depends(get_current_user),
):
    """Refresh JWT access token."""
    access_token = create_access_token(
        user_id=current_user.user_id,
        username=current_user.username,
        roles=current_user.roles,
    )
    
    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=24 * 3600,
    )
