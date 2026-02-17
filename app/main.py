"""
Main FastAPI application for Incident Manager.
Follows security patterns: JWT auth, RBAC, input validation, audit logging, rate limiting.
"""
import os
import logging
from contextlib import asynccontextmanager
from typing import Optional
import uuid

from fastapi import FastAPI, Depends, HTTPException, status, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.exception_handlers import http_exception_handler
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import logging.handlers

from app.database import Base
from app.security import SecurityHeaders, RateLimitConfig
from app import routes

# Configure logging
logger = logging.getLogger(__name__)
log_handler = logging.handlers.RotatingFileHandler(
    "logs/app.log",
    maxBytes=10485760,  # 10MB
    backupCount=10,
)
log_formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
log_handler.setFormatter(log_formatter)
logger.addHandler(log_handler)
logger.setLevel(logging.INFO)

# Database setup
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./incidents.db")
engine = create_async_engine(
    DATABASE_URL,
    echo=os.getenv("DEBUG", "false").lower() == "true",
    connect_args={} if "sqlite" in DATABASE_URL else {},
)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def get_db():
    """Get database session."""
    async with AsyncSessionLocal() as session:
        yield session


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events."""
    # Startup
    logger.info("Starting Incident Manager API")
    os.makedirs("logs", exist_ok=True)
    os.makedirs("exports", exist_ok=True)
    
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    logger.info("Database initialized")
    
    yield
    
    # Shutdown
    logger.info("Shutting down Incident Manager API")
    await engine.dispose()


# Rate limiter
limiter = Limiter(key_func=get_remote_address)


# Create FastAPI app
app = FastAPI(
    title="Incident Manager API",
    description="DFIR AppSec incident management system with SQLite persistence",
    version="2.0.0",
    openapi_url="/api/openapi.json",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    lifespan=lifespan,
)

# Add state for database
app.state.db_session = AsyncSessionLocal

# Rate limiting error handler
@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return Response(
        content={"error": "Rate limit exceeded"},
        status_code=429,
    )

# Add rate limiter to app
app.state.limiter = limiter

# ============= Middleware =============

# CORS - adjust origins for production
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:3000,http://localhost:5173").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Trusted hosts - prevent host header attacks
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=os.getenv("ALLOWED_HOSTS", "localhost,127.0.0.1").split(","),
)


# Custom middleware for security headers and request tracking
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Add security headers and request tracking."""
    # Generate request ID for audit trail
    request_id = str(uuid.uuid4())
    request.state.request_id = request_id
    
    # Get client IP for audit logging
    client_ip = request.client.host if request.client else None
    request.state.client_ip = client_ip
    
    # Log request
    logger.info(
        f"[{request_id}] {request.method} {request.url.path} from {client_ip}"
    )
    
    response = await call_next(request)
    
    # Add security headers
    for header_name, header_value in SecurityHeaders.get_headers().items():
        response.headers[header_name] = header_value
    
    # Add request ID to response
    response.headers["X-Request-ID"] = request_id
    
    return response


# ============= Health Check =============

@app.get("/health", tags=["Health"])
@limiter.limit("1000/minute")
async def health_check(request: Request):
    """Health check endpoint."""
    return {
        "status": "ok",
        "version": "2.0.0",
        "request_id": request.state.request_id,
    }


# ============= Include Routes =============

# Auth routes
app.include_router(
    routes.auth.router,
    prefix="/api/auth",
    tags=["Authentication"],
)

# Incidents routes
app.include_router(
    routes.incidents.router,
    prefix="/api/incidents",
    tags=["Incidents"],
)

# Export routes
app.include_router(
    routes.exports.router,
    prefix="/api/exports",
    tags=["Exports"],
)

# Users routes (admin only)
app.include_router(
    routes.users.router,
    prefix="/api/users",
    tags=["Users"],
)

# Audit log routes
app.include_router(
    routes.audit.router,
    prefix="/api/audit",
    tags=["Audit"],
)


# ============= Error Handlers =============

@app.exception_handler(HTTPException)
async def custom_http_exception_handler(request: Request, exc: HTTPException):
    """Custom HTTP exception handler with request ID."""
    return {
        "error": exc.detail,
        "status_code": exc.status_code,
        "request_id": request.state.request_id,
    }


@app.get("/api/openapi.json", tags=["Documentation"])
async def get_openapi():
    """OpenAPI schema endpoint."""
    return app.openapi()


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", "8000")),
        reload=os.getenv("DEBUG", "false").lower() == "true",
        log_level="info",
    )
