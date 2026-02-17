"""
Security and authentication module following .claude_skills patterns.
Implements JWT-based auth, RBAC, and audit logging.
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
) -> str:
    """Create JWT access token with secure expiration."""
    if expires_delta is None:
        expires_delta = timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)

    expire = datetime.now(timezone.utc) + expires_delta
    
    to_encode = {
        "sub": user_id,
        "user_id": user_id,
        "username": username,
        "roles": [role.value for role in roles],
        "exp": expire,
        "iat": datetime.utcnow(),
    }
    
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(
    request: Request,
    credentials: HTTPAuthCredentials = Depends(security)
) -> TokenPayload:
    """
    Validate JWT token and extract user info.
    Used as dependency in protected endpoints.
    """
    token = credentials.credentials
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        username: str = payload.get("username")
        roles_data: list = payload.get("roles", [])
        
        if user_id is None or username is None:
            raise AuthenticationError("Invalid token structure")
        
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


class RateLimitConfig:
    """Rate limiting configuration."""
    
    # Global rate limits
    DEFAULT_LIMIT = "100/minute"
    AUTH_LIMIT = "5/minute"  # Stricter for auth endpoints
    EXPORT_LIMIT = "10/minute"
    CREATE_INCIDENT_LIMIT = "20/minute"
