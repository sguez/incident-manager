"""
Database models using SQLAlchemy ORM.
"""
from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, ForeignKey, DateTime, Boolean, JSON, Index
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()


class User(Base):
    """User model for authentication and audit."""
    __tablename__ = "users"
    __table_args__ = (
        Index("ix_users_username", "username", unique=True),
        Index("ix_users_email", "email", unique=True),
    )

    id = Column(Integer, primary_key=True)
    username = Column(String(50), nullable=False, unique=True)
    email = Column(String(255), nullable=False, unique=True)
    password_hash = Column(String(255), nullable=False)
    roles = Column(JSON, default=["viewer"])  # List of UserRole enum values
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    incidents = relationship("Incident", back_populates="created_by")
    audit_logs = relationship("AuditLog", back_populates="user")


class Incident(Base):
    """Incident record."""
    __tablename__ = "incidents"
    __table_args__ = (
        Index("ix_incidents_incident_key", "incident_key", unique=True),
        Index("ix_incidents_created_by", "created_by_id"),
        Index("ix_incidents_status", "status"),
    )

    id = Column(Integer, primary_key=True)
    incident_key = Column(String(20), nullable=False, unique=True)
    name = Column(String(500), nullable=False)
    severity = Column(String(20), nullable=False)  # critical, high, medium, low
    classification = Column(String(50), nullable=False)
    reported_by = Column(String(200), nullable=False)
    detection_source = Column(String(500), nullable=False)
    incident_start = Column(String(30), nullable=False)  # ISO-8601
    status = Column(String(20), default="open", nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    # Relationships
    created_by = relationship("User", back_populates="incidents")
    roles = relationship("IncidentRole", cascade="all, delete-orphan", back_populates="incident")
    triggers = relationship("IncidentTrigger", cascade="all, delete-orphan", back_populates="incident")
    tasks = relationship("IncidentTask", cascade="all, delete-orphan", back_populates="incident")
    evidence = relationship("EvidenceEntry", cascade="all, delete-orphan", back_populates="incident")
    timeline_entries = relationship("TimelineEntry", cascade="all, delete-orphan", back_populates="incident")
    checklist_items = relationship("ChecklistItem", cascade="all, delete-orphan", back_populates="incident")
    audit_logs = relationship("AuditLog", back_populates="incident", cascade="all, delete-orphan")


class IncidentRole(Base):
    """Role assignments in an incident."""
    __tablename__ = "incident_roles"
    __table_args__ = (Index("ix_incident_roles_incident", "incident_id"),)

    id = Column(Integer, primary_key=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False)
    role = Column(String(50), nullable=False)  # ir_lead, app_owner, sre_devops, etc.
    person = Column(String(200), nullable=False)

    # Relationships
    incident = relationship("Incident", back_populates="roles")


class IncidentTrigger(Base):
    """Incident trigger/detection method."""
    __tablename__ = "incident_triggers"
    __table_args__ = (Index("ix_incident_triggers_incident", "incident_id"),)

    id = Column(Integer, primary_key=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False)
    method = Column(String(500), nullable=False)
    detection_time = Column(String(30), nullable=False)  # ISO-8601

    # Relationships
    incident = relationship("Incident", back_populates="triggers")


class IncidentTask(Base):
    """Task entries in an incident."""
    __tablename__ = "incident_tasks"
    __table_args__ = (Index("ix_incident_tasks_incident", "incident_id"),)

    id = Column(Integer, primary_key=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False)
    phase = Column(String(20), nullable=False)  # immediate, next_24_72h, aftermath
    task_type = Column(String(100), nullable=False)  # ir_action, forensics_action, comms_action
    description = Column(Text, nullable=False)
    assigned_to = Column(String(200), nullable=True)
    status = Column(String(20), default="open", nullable=False)  # open, in_progress, completed
    due_date = Column(String(30), nullable=True)  # ISO-8601

    # Relationships
    incident = relationship("Incident", back_populates="tasks")


class EvidenceEntry(Base):
    """Evidence collected during incident."""
    __tablename__ = "evidence"
    __table_args__ = (Index("ix_evidence_incident", "incident_id"),)

    id = Column(Integer, primary_key=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False)
    location = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    hash_sha256 = Column(String(64), nullable=True)  # Optional SHA-256 hash
    collected_at = Column(String(30), nullable=False)  # ISO-8601

    # Relationships
    incident = relationship("Incident", back_populates="evidence")


class TimelineEntry(Base):
    """Timeline events during incident."""
    __tablename__ = "timeline"
    __table_args__ = (Index("ix_timeline_incident", "incident_id"),)

    id = Column(Integer, primary_key=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False)
    timestamp = Column(String(30), nullable=False)  # ISO-8601
    event = Column(String(1000), nullable=False)
    source = Column(String(200), nullable=False)

    # Relationships
    incident = relationship("Incident", back_populates="timeline_entries")


class ChecklistItem(Base):
    """Executive checklist items."""
    __tablename__ = "checklist"
    __table_args__ = (Index("ix_checklist_incident", "incident_id"),)

    id = Column(Integer, primary_key=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False)
    item = Column(String(500), nullable=False)
    completed = Column(Boolean, default=False)

    # Relationships
    incident = relationship("Incident", back_populates="checklist_items")


class AuditLog(Base):
    """Audit log for all mutations (DFIR compliance)."""
    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_logs_incident", "incident_id"),
        Index("ix_audit_logs_user", "user_id"),
        Index("ix_audit_logs_timestamp", "timestamp"),
    )

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=True)
    action = Column(String(100), nullable=False)  # create, update, delete, view, export
    resource_type = Column(String(50), nullable=False)  # incident, task, evidence, etc.
    resource_id = Column(String(100), nullable=True)
    changes = Column(JSON, nullable=True)  # Before/after values for mutations
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    ip_address = Column(String(45), nullable=True)  # IPv4 or IPv6

    # Relationships
    user = relationship("User", back_populates="audit_logs")
    incident = relationship("Incident", back_populates="audit_logs")
