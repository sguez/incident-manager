"""
Security and authentication module following .claude_skills patterns.
Implements JWT-based auth, RBAC, token revocation, ACL, and CSRF protection.
"""
from datetime import datetime, timedelta, timezone
from typing import Optional, List
from functools import lru_cache
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthCredentials
from pydantic import ValidationError
import os
import secrets
import uuid

from app.models import TokenPayload, UserRole, User as UserModel

# Settings
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise ValueError(
        "SECRET_KEY environment variable must be set for production. "
        "Generate with: python -c \"import secrets; print(secrets.token_urlsafe(32))\""
    )
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = int(os.getenv("ACCESS_TOKEN_EXPIRE_HOURS", "24"))

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# HTTP Bearer security
security = HTTPBearer()


class AuthenticationError(HTTPException):
    """Authentication failed."""
    def __init__(self, detail: str = "Authentication failed"):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
            headers={"WWW-Authenticate": "Bearer"},
        )


class AuthorizationError(HTTPException):
    """Authorization failed - insufficient permissions."""
    def __init__(self, detail: str = "Insufficient permissions"):
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=detail,
        )


def hash_password(password: str) -> str:
    """Hash password using bcrypt."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against hash."""
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(
    user_id: str,
    username: str,
    roles: List[UserRole],
    expires_delta: Optional[timedelta] = None,
) -> tuple:
    """
    Create JWT access token with secure expiration.
    Returns: (token, jti) where jti is the JWT ID for blacklist support.
    """
    if expires_delta is None:
        expires_delta = timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)

    expire = datetime.now(timezone.utc) + expires_delta
    jti = str(uuid.uuid4())
    
    to_encode = {
        "sub": user_id,
        "user_id": user_id,
        "username": username,
        "roles": [role.value for role in roles],
        "exp": expire,
        "iat": datetime.utcnow(),
        "jti": jti,
    }
    
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt, jti


async def get_current_user(
    request: Request,
    credentials: HTTPAuthCredentials = Depends(security)
) -> TokenPayload:
    """
    Validate JWT token and extract user info.
    Checks if token is blacklisted (revoked).
    Used as dependency in protected endpoints.
    """
    token = credentials.credentials
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        username: str = payload.get("username")
        roles_data: list = payload.get("roles", [])
        jti: str = payload.get("jti")
        
        if user_id is None or username is None:
            raise AuthenticationError("Invalid token structure")
        
        # Check if token is blacklisted
        if jti:
            is_blacklisted = await check_token_blacklisted(jti)
            if is_blacklisted:
                raise AuthenticationError("Token has been revoked")
        
        # Convert role strings back to UserRole enum
        roles = [UserRole(r) for r in roles_data]
        
        token_data = TokenPayload(
            sub=user_id,
            user_id=user_id,
            username=username,
            roles=roles,
            exp=payload.get("exp"),
        )
        
    except JWTError as e:
        raise AuthenticationError(f"Invalid token: {str(e)}")
    except (ValidationError, ValueError) as e:
        raise AuthenticationError(f"Invalid token payload: {str(e)}")
    
    return token_data


async def check_token_blacklisted(jti: str) -> bool:
    """Check if token (by jti) is blacklisted."""
    try:
        from sqlalchemy import select
        from app.database import TokenBlacklist
        from app.main import AsyncSessionLocal
        
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(TokenBlacklist).filter(TokenBlacklist.jti == jti)
            )
            return result.scalars().first() is not None
    except Exception:
        # If DB check fails, don't fail auth entirely - just continue
        return False


async def add_token_to_blacklist(jti: str, user_id: int, expires_at: datetime) -> bool:
    """Add token to blacklist for logout support."""
    try:
        from app.database import TokenBlacklist
        from app.main import AsyncSessionLocal
        
        async with AsyncSessionLocal() as session:
            blacklist_entry = TokenBlacklist(
                jti=jti,
                user_id=user_id,
                expires_at=expires_at,
            )
            session.add(blacklist_entry)
            await session.commit()
            return True
    except Exception as e:
        print(f"Error blacklisting token: {e}")
        return False


async def cleanup_expired_tokens() -> int:
    """Remove expired tokens from blacklist. Returns count of deleted entries."""
    try:
        from sqlalchemy import delete
        from app.database import TokenBlacklist
        from app.main import AsyncSessionLocal
        
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                delete(TokenBlacklist).where(
                    TokenBlacklist.expires_at < datetime.utcnow()
                )
            )
            await session.commit()
            return result.rowcount
    except Exception as e:
        print(f"Error cleaning up tokens: {e}")
        return 0


async def check_incident_permission(
    incident_id: int,
    user_id: int,
    permission: str = "can_view",
) -> bool:
    """
    Check if user has specific permission on incident.
    Permission can be: can_view, can_edit, can_delete
    Returns True if user is incident creator or has explicit permission.
    """
    try:
        from sqlalchemy import select, or_
        from app.database import Incident as IncidentModel, IncidentACL
        from app.main import AsyncSessionLocal
        
        async with AsyncSessionLocal() as session:
            # Get incident
            result = await session.execute(
                select(IncidentModel).filter(IncidentModel.id == incident_id)
            )
            incident = result.scalars().first()
            
            if not incident:
                return False
            
            # Incident creator always has all permissions
            if incident.created_by_id == user_id:
                return True
            
            # Check explicit ACL permission
            result = await session.execute(
                select(IncidentACL).filter(
                    IncidentACL.incident_id == incident_id,
                    IncidentACL.user_id == user_id,
                )
            )
            acl = result.scalars().first()
            
            if not acl:
                return False
            
            if permission == "can_view":
                return acl.can_view
            elif permission == "can_edit":
                return acl.can_edit
            elif permission == "can_delete":
                return acl.can_delete
            
            return False
    except Exception:
        return False


async def grant_incident_permissions(
    incident_id: int,
    user_id: int,
    can_view: bool = True,
    can_edit: bool = False,
    can_delete: bool = False,
) -> bool:
    """Grant explicit permissions on an incident to a user."""
    try:
        from sqlalchemy import select
        from app.database import IncidentACL
        from app.main import AsyncSessionLocal
        
        async with AsyncSessionLocal() as session:
            # Check if ACL already exists
            result = await session.execute(
                select(IncidentACL).filter(
                    IncidentACL.incident_id == incident_id,
                    IncidentACL.user_id == user_id,
                )
            )
            existing_acl = result.scalars().first()
            
            if existing_acl:
                # Update existing
                existing_acl.can_view = can_view
                existing_acl.can_edit = can_edit
                existing_acl.can_delete = can_delete
            else:
                # Create new
                acl = IncidentACL(
                    incident_id=incident_id,
                    user_id=user_id,
                    can_view=can_view,
                    can_edit=can_edit,
                    can_delete=can_delete,
                )
                session.add(acl)
            
            await session.commit()
            return True
    except Exception as e:
        print(f"Error granting permissions: {e}")
        return False


def require_role(*required_roles: UserRole):
    """
    Decorator to require one or more roles.
    Usage: @require_role(UserRole.ADMIN, UserRole.IR_LEAD)
    """
    async def role_checker(current_user: TokenPayload = Depends(get_current_user)):
        user_roles_set = {role for role in current_user.roles}
        required_roles_set = {role for role in required_roles}
        
        if not user_roles_set.intersection(required_roles_set):
            raise AuthorizationError(
                f"Requires one of: {', '.join(r.value for r in required_roles)}"
            )
        
        return current_user
    
    return role_checker


def require_all_roles(*required_roles: UserRole):
    """Require ALL specified roles."""
    async def role_checker(current_user: TokenPayload = Depends(get_current_user)):
        user_roles_set = {role for role in current_user.roles}
        required_roles_set = {role for role in required_roles}
        
        if not required_roles_set.issubset(user_roles_set):
            raise AuthorizationError(
                f"Requires all of: {', '.join(r.value for r in required_roles)}"
            )
        
        return current_user
    
    return role_checker


# Input validation patterns following OWASP

class InputValidator:
    """Validate and sanitize user inputs."""
    
    @staticmethod
    def validate_string(value: str, min_len: int = 1, max_len: int = 1000) -> str:
        """Validate string length and sanitize."""
        if not isinstance(value, str):
            raise ValueError("Must be a string")
        if len(value) < min_len or len(value) > max_len:
            raise ValueError(f"Length must be between {min_len} and {max_len}")
        return value.strip()
    
    @staticmethod
    def validate_incident_key(key: str) -> str:
        """Validate incident key format: xxxx-YYYY-MM-DD"""
        import re
        if not re.match(r"^[a-z0-9]{4}-\d{4}-\d{2}-\d{2}$", key):
            raise ValueError("Invalid incident key format")
        return key
    
    @staticmethod
    def validate_sha256(hash_value: str) -> str:
        """Validate SHA-256 hash format."""
        import re
        if not re.match(r"^[a-f0-9]{64}$", hash_value):
            raise ValueError("Invalid SHA-256 hash format")
        return hash_value
    
    @staticmethod
    def validate_iso8601(timestamp: str) -> str:
        """Validate ISO-8601 timestamp."""
        try:
            datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            return timestamp
        except (ValueError, AttributeError):
            raise ValueError("Invalid ISO-8601 timestamp")


# Markdown escape for safe export (prevent injection in exports)
def md_escape(text: str) -> str:
    """Escape markdown special characters."""
    if not text:
        return ""
    # Escape markdown special characters
    special_chars = ['\\', '`', '*', '_', '{', '}', '[', ']', '(', ')', '#', '+', '-', '.', '!', '|']
    for char in special_chars:
        text = text.replace(char, f'\\{char}')
    return text


# HTML escape for safe export
def html_escape(text: str) -> str:
    """Escape HTML special characters."""
    if not text:
        return ""
    replacements = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#x27;',
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    return text


class SecurityHeaders:
    """Security headers middleware configuration."""
    
    @staticmethod
    def get_headers() -> dict:
        """Return recommended security headers."""
        return {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
            "Referrer-Policy": "strict-origin-when-cross-origin",
        }


class CsrfSettings:
    """CSRF token generation and validation."""
    
    CSRF_TOKEN_LENGTH = 32
    CSRF_HEADER_NAME = "X-CSRF-Token"
    CSRF_COOKIE_NAME = "csrf_token"
    
    @staticmethod
    def generate_token() -> str:
        """Generate a secure CSRF token."""
        return secrets.token_urlsafe(CsrfSettings.CSRF_TOKEN_LENGTH)
    
    @staticmethod
    def validate_token(client_token: str, session_token: str) -> bool:
        """Validate CSRF token using timing-safe comparison."""
        if not client_token or not session_token:
            return False
        return secrets.compare_digest(client_token, session_token)


class RateLimitConfig:
    """Rate limiting configuration."""
    
    # Global rate limits
    DEFAULT_LIMIT = "100/minute"
    AUTH_LIMIT = "5/minute"  # Stricter for auth endpoints
    EXPORT_LIMIT = "10/minute"
    CREATE_INCIDENT_LIMIT = "20/minute"
