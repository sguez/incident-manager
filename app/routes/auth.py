"""Authentication routes."""
from datetime import timedelta, datetime
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from slowapi import Limiter
from slowapi.util import get_remote_address
from jose import jwt

from app.models import TokenResponse, UserCreate, LoginRequest, LogoutResponse, CsrfTokenResponse
from app.database import User as UserModel
from app.security import (
    get_current_user,
    create_access_token,
    hash_password,
    verify_password,
    RateLimitConfig,
    AuthenticationError,
    add_token_to_blacklist,
    CsrfSettings,
    SECRET_KEY,
    ALGORITHM,
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
    Returns JWT access token with CSRF token.
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
        access_token, jti = create_access_token(
            user_id=str(user.id),
            username=user.username,
            roles=user.roles,
        )
        
        # Generate CSRF token
        csrf_token = CsrfSettings.generate_token()
        
        return TokenResponse(
            access_token=access_token,
            token_type="bearer",
            expires_in=24 * 3600,
            csrf_token=csrf_token,
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
        access_token, jti = create_access_token(
            user_id=str(new_user.id),
            username=new_user.username,
            roles=new_user.roles,
        )
        
        # Generate CSRF token
        csrf_token = CsrfSettings.generate_token()
        
        return TokenResponse(
            access_token=access_token,
            token_type="bearer",
            expires_in=24 * 3600,
            csrf_token=csrf_token,
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
    access_token, jti = create_access_token(
        user_id=current_user.user_id,
        username=current_user.username,
        roles=current_user.roles,
    )
    
    # Generate CSRF token
    csrf_token = CsrfSettings.generate_token()
    
    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=24 * 3600,
        csrf_token=csrf_token,
    )


@router.post("/logout", response_model=LogoutResponse)
async def logout(
    request: Request,
    current_user=Depends(get_current_user),
):
    """
    Logout user by revoking their token.
    Adds token to blacklist.
    """
    # Extract jti from token via JWT decode (we need to get it from the Authorization header)
    from fastapi.security import HTTPBearer
    auth = HTTPBearer()
    
    try:
        credentials = await auth(request)
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        jti = payload.get("jti")
        exp = payload.get("exp")
        
        if jti and exp:
            exp_dt = datetime.utcfromtimestamp(exp)
            await add_token_to_blacklist(jti, int(current_user.user_id), exp_dt)
        
        return LogoutResponse(
            message="Successfully logged out",
            status="success",
        )
    except Exception as e:
        return LogoutResponse(
            message="Logout completed (token blacklist may not be available)",
            status="success",
        )


@router.get("/csrf-token", response_model=CsrfTokenResponse)
async def get_csrf_token(request: Request):
    """
    Get a CSRF token for form submissions.
    Can be used by unauthenticated clients.
    """
    csrf_token = CsrfSettings.generate_token()
    return CsrfTokenResponse(csrf_token=csrf_token)
