"""
Pydantic models for request/response validation following security patterns.
"""
from typing import Optional, List
from datetime import datetime
from enum import Enum
from pydantic import BaseModel, Field, validator, EmailStr


class Severity(str, Enum):
    """Incident severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Classification(str, Enum):
    """Incident classification."""
    DATA_BREACH = "data_breach"
    MALWARE = "malware"
    INSIDER_THREAT = "insider_threat"
    SUPPLY_CHAIN = "supply_chain"
    CONFIG_ERROR = "config_error"
    OTHER = "other"


class Phase(str, Enum):
    """Incident response phases."""
    IMMEDIATE = "immediate"
    NEXT_24_72H = "next_24_72h"
    AFTERMATH = "aftermath"


class Role(str, Enum):
    """User roles in incidents."""
    IR_LEAD = "ir_lead"
    APP_OWNER = "app_owner"
    SRE_DEVOPS = "sre_devops"
    SECOPS = "secops"
    COMMS = "comms"
    LEGAL = "legal"


class UserRole(str, Enum):
    """System user roles for RBAC."""
    ADMIN = "admin"
    IR_LEAD = "ir_lead"
    VIEWER = "viewer"
    REPORTER = "reporter"


# ============= Auth Models =============

class LoginRequest(BaseModel):
    """Login request with validated credentials."""
    username: str = Field(
        ..., 
        min_length=3, 
        max_length=50,
        description="Username (alphanumeric, hyphen, underscore only)"
    )
    password: str = Field(
        ..., 
        min_length=8,
        max_length=255,
        description="Password (8-255 characters)"
    )
    
    @validator('username')
    def validate_username(cls, v):
        """Validate username format."""
        # Allow alphanumeric, hyphen, underscore
        if not all(c.isalnum() or c in '-_' for c in v):
            raise ValueError("Username must contain only alphanumeric characters, hyphens, and underscores")
        return v.lower().strip()


class TokenResponse(BaseModel):
    """JWT token response."""
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class TokenPayload(BaseModel):
    """JWT token payload."""
    sub: str  # user_id
    user_id: str
    username: str
    roles: List[UserRole]
    exp: int


# ============= User Models =============

class UserCreate(BaseModel):
    """User creation request."""
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=8)


class User(BaseModel):
    """User response."""
    id: int
    username: str
    email: str
    roles: List[UserRole]
    created_at: datetime

    class Config:
        from_attributes = True


# ============= Incident Models =============

class IncidentRoleAssignment(BaseModel):
    """Role assignment in incident."""
    role: Role
    person: str = Field(..., min_length=1, max_length=200)


class IncidentMetadata(BaseModel):
    """Incident metadata."""
    name: str = Field(..., min_length=1, max_length=500)
    severity: Severity
    classification: Classification
    reported_by: str = Field(..., min_length=1, max_length=200)
    detection_source: str = Field(..., min_length=1, max_length=500)
    incident_start: str  # ISO-8601 timestamp


class IncidentTrigger(BaseModel):
    """Incident trigger/detection method."""
    method: str = Field(..., min_length=1, max_length=500)
    detection_time: str  # ISO-8601 timestamp


class TaskEntry(BaseModel):
    """Task entry in incident."""
    phase: Phase
    task_type: str  # e.g., 'ir_action', 'forensics_action', 'comms_action'
    description: str = Field(..., min_length=1)
    assigned_to: Optional[str] = None
    status: str = Field("open", regex="^(open|in_progress|completed)$")
    due_date: Optional[str] = None  # ISO-8601


class EvidenceEntry(BaseModel):
    """Evidence entry."""
    location: str = Field(..., min_length=1)
    description: Optional[str] = None
    hash_sha256: Optional[str] = Field(None, regex="^[a-f0-9]{64}$|^$")
    collected_at: str  # ISO-8601


class TimelineEntry(BaseModel):
    """Timeline event."""
    timestamp: str = Field(..., description="ISO-8601 timestamp")
    event: str = Field(..., min_length=1, max_length=1000)
    source: str = Field(..., min_length=1, max_length=200)


class ChecklistItem(BaseModel):
    """Executive checklist item."""
    item: str = Field(..., min_length=1)
    completed: bool = False


class IncidentCreate(BaseModel):
    """Create incident request."""
    metadata: IncidentMetadata
    roles: List[IncidentRoleAssignment]


class IncidentUpdate(BaseModel):
    """Update incident request."""
    metadata: Optional[IncidentMetadata] = None
    roles: Optional[List[IncidentRoleAssignment]] = None


class Incident(BaseModel):
    """Full incident response."""
    id: int
    incident_key: str
    severity: Severity
    status: str
    created_at: datetime
    updated_at: datetime
    created_by_id: int
    
    # Nested data
    metadata: Optional[dict] = None
    roles: List[IncidentRoleAssignment] = []
    triggers: List[IncidentTrigger] = []
    tasks: List[TaskEntry] = []
    evidence: List[EvidenceEntry] = []
    timeline: List[TimelineEntry] = []
    checklist: List[ChecklistItem] = []

    class Config:
        from_attributes = True


class IncidentListItem(BaseModel):
    """Incident list response."""
    id: int
    incident_key: str
    name: str
    severity: Severity
    status: str
    created_at: datetime
    updated_at: datetime


class ExportRequest(BaseModel):
    """Export format request."""
    format: str = Field(..., regex="^(markdown|html|pdf)$")


class AuditLog(BaseModel):
    """Audit log entry."""
    id: int
    user_id: int
    incident_id: Optional[int] = None
    action: str
    resource_type: str
    resource_id: Optional[str] = None
    changes: Optional[dict] = None
    timestamp: datetime
    ip_address: Optional[str] = None

    class Config:
        from_attributes = True


# ============= Error Models =============

class ErrorResponse(BaseModel):
    """Standard error response."""
    error: str
    detail: Optional[str] = None
    request_id: Optional[str] = None


class ValidationErrorResponse(BaseModel):
    """Validation error response."""
    errors: List[dict]
    request_id: Optional[str] = None
