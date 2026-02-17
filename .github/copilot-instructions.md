# Incident Manager - Copilot Instructions

## Project Overview

**Incident Manager** is a web-based DFIR (Digital Forensics & Incident Response) application for managing application security incidents. It follows `.claude_skills` patterns for security, architecture, and deployment.

**Tech Stack:**
- Backend: FastAPI (Python 3.13+)
- Frontend: React + Vite (TypeScript/JSX)
- Database: SQLite with SQLAlchemy ORM
- Deployment: Docker + Kubernetes + Helm

## Running the Application

### Option 1: Docker Compose (Recommended)
```bash
docker-compose up -d
curl http://localhost:8000/api/docs
```

### Option 2: Local Development
```bash
# Backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload

# Frontend (in another terminal)
cd ui && npm install && npm run dev
```

## Architecture

### Project Structure
```
incident-manager/
├── app/                 # FastAPI backend
│   ├── main.py         # App factory, middleware, lifespan
│   ├── models.py       # Pydantic schemas (request/response validation)
│   ├── database.py     # SQLAlchemy ORM models (8 tables)
│   ├── security.py     # JWT auth, RBAC, input validation, audit logging
│   └── routes/
│       ├── auth.py     # Login, register, token refresh
│       ├── incidents.py # CRUD for incidents
│       ├── exports.py  # Export to Markdown/HTML/PDF
│       ├── users.py    # User management (admin only)
│       └── audit.py    # Audit log queries
├── ui/                 # React frontend (Vite)
├── k8s/                # Kubernetes manifests + Helm chart
├── Dockerfile          # Multi-stage production build
├── docker-compose.yml  # Local development environment
├── requirements.txt    # Python dependencies
└── .github/
    └── copilot-instructions.md
```

### Core Layers

1. **Security Layer** (`app/security.py`)
   - JWT authentication with token generation/validation
   - RBAC middleware (`require_role`, `require_all_roles` decorators)
   - Input validation (Pydantic schemas + custom validators)
   - Output escaping (md_escape, html_escape for safe exports)
   - Audit logging for all mutations (DFIR compliance)
   - Rate limiting configuration

2. **Database Layer** (`app/database.py`)
   - SQLAlchemy ORM with async support (`aiosqlite` for SQLite)
   - 8 tables: Users, Incidents, IncidentRoles, IncidentTriggers, IncidentTasks, Evidence, Timeline, ChecklistItems, AuditLogs
   - Foreign keys, cascading deletes, proper indexes
   - Migration support (alembic-ready structure)

3. **API Routes** (`app/routes/`)
   - `auth.py` - Login, register, token refresh, current user
   - `incidents.py` - Create/read/update/delete incidents with CRUD operations
   - `exports.py` - Export to Markdown/HTML/PDF with output escaping
   - `users.py` - User management, role assignment (admin only)
   - `audit.py` - Query audit logs by incident/user/action (admin + incident data)

4. **Application Core** (`app/main.py`)
   - FastAPI app with lifespan (startup/shutdown events)
   - Middleware stack: CORS, TrustedHost, SecurityHeaders
   - Custom middleware for request tracking (request IDs, client IP)
   - Rate limiting (per-endpoint, global)
   - Error handlers with request ID tracking

## Key Patterns (Following .claude_skills)

### Authentication & Authorization
- **JWT tokens** signed with HS256, expire in 24 hours
- **Bcrypt password hashing** (passlib context)
- **RBAC** with 4 roles: Admin, IR Lead, Viewer, Reporter
- **Role-based route decorators**: `@require_role(UserRole.IR_LEAD, UserRole.ADMIN)`
- **Token refresh** endpoint for extending sessions

### Input Validation & Security
- **Pydantic schemas** enforce type safety, length constraints, enum values
- **Custom validators** for complex logic (ISO-8601 timestamps, SHA-256 hashes)
- **SQLAlchemy ORM** prevents SQL injection (parameterized queries)
- **No string interpolation** in any database queries
- **Markdown/HTML escaping** in all export outputs (XSS prevention)

### Audit Logging (DFIR Compliance)
- **Every mutation logged**: create, update, delete, view, export, login
- **Audit entry fields**: user_id, action, resource_type, resource_id, changes, timestamp, ip_address
- **Changes tracked**: Before/after values for mutations
- **Query audit logs** by incident, user, action, or time range
- **Immutable audit trail** - append-only, cannot be modified

### Deployment

**Docker:**
- Multi-stage build (builder + final) reduces image size
- Non-root user (UID 1000) for security
- Read-only filesystem support (tmpfs for /tmp, /logs)
- Health checks with curl
- Volume mounts for persistence (db, exports, logs)

**Kubernetes:**
- Deployment with rolling updates
- PersistentVolumeClaims for database and exports
- ConfigMap for application settings
- Secrets for sensitive data (SECRET_KEY, DATABASE_URL)
- Health probes: liveness, readiness, startup
- Security context: non-root, read-only, dropped capabilities
- Network policies for ingress/egress restriction
- RBAC for pod permissions
- Resource limits and requests

**Helm Chart:**
- Values-driven configuration
- Support for multi-environment deployments
- Customizable replica count, image, storage, ingress

## Conventions

1. **Timestamps** — Always UTC ISO-8601 with `Z` suffix (e.g., `2025-01-15T14:30:00Z`)
   - Stored as strings in SQLite (`STRING` column type)
   - Validated with `InputValidator.validate_iso8601()`

2. **Incident ID** — Format `xxxx-YYYY-MM-DD` (4 random alphanumeric + date)
   - Generated with `gen_incident_key()`
   - Unique constraint in database

3. **Error Handling** — FastAPI exception handlers return structured JSON
   - Status codes follow HTTP standards
   - Optional `request_id` for tracking (added by middleware)
   - Rate limit errors return 429

4. **Async Operations** — All database calls are async
   - Use `async with AsyncSessionLocal() as session:` pattern
   - All SQLAlchemy queries wrapped with `await session.execute()`

5. **Response Models** — Pydantic schemas for all responses
   - Ensures consistent JSON structure
   - OpenAPI docs auto-generated from schemas
   - Type hints for IDE support

## Common Tasks

### Adding a New Endpoint
1. Create route function in `app/routes/<domain>.py`
2. Use `@router.post()`, `@router.get()`, etc. decorators
3. Add authentication with `Depends(get_current_user)`
4. Add role check if needed: `Depends(require_role(UserRole.ADMIN))`
5. Add Pydantic schema for request/response
6. Add audit logging for mutations
7. Include in `app/main.py` with `app.include_router()`

### Adding a Database Field
1. Add column to ORM model in `app/database.py`
2. Add field to Pydantic schema in `app/models.py`
3. Update `_incident_to_response()` helper if needed
4. Update routes that read/write this field
5. Add audit logging for mutations involving this field
6. Test with `pytest`

### Adding a New Export Format
1. Create `export_<format>()` function in `app/routes/exports.py`
2. Add request validation (e.g., format enum)
3. Log audit action: `await log_audit(..., action="export")`
4. Generate content in desired format
5. Save to `exports/incident_{incident_id}/` directory
6. Return path and format in response

### Modifying Security/Auth
- JWT logic: `app/security.py` (create_access_token, get_current_user)
- RBAC decorators: `app/security.py` (require_role, require_all_roles)
- Input validation: `app/models.py` (Pydantic validators) + `app/security.py` (InputValidator)
- Audit logging: Each route calls `await log_audit(...)` for mutations

### Running Tests
```bash
pytest tests/ -v --cov=app
pytest tests/test_auth.py::test_login -v
```

## Key Files to Know

| File | Purpose |
|------|---------|
| `app/main.py` | FastAPI app, middleware, lifespan |
| `app/security.py` | Auth, RBAC, validation, audit logging |
| `app/database.py` | SQLAlchemy ORM models |
| `app/models.py` | Pydantic schemas |
| `app/routes/auth.py` | Authentication endpoints |
| `app/routes/incidents.py` | Incident CRUD |
| `app/routes/exports.py` | Export endpoints |
| `Dockerfile` | Container build |
| `docker-compose.yml` | Local dev environment |
| `k8s/deployment.yaml` | Kubernetes manifests |
| `requirements.txt` | Python dependencies |

## Documentation

- **README.md** - Quick start, features, demo
- **DEPLOYMENT.md** - Docker, Kubernetes, Helm, troubleshooting
- **API.md** - REST API reference with cURL examples
- **SECURITY.md** - Authentication, RBAC, audit logging, hardening
- **.github/copilot-instructions.md** - This file

## Common Development Commands

```bash
# Backend
uvicorn app.main:app --reload              # Dev server with auto-reload
pytest tests/ -v                            # Run tests
black app/                                  # Format code
flake8 app/ --max-line-length=100          # Lint

# Docker
docker-compose up -d                        # Start
docker-compose logs -f                      # View logs
docker-compose down                         # Stop

# Kubernetes
kubectl apply -f k8s/deployment.yaml        # Deploy
kubectl logs -f deployment/incident-manager # View logs
kubectl port-forward svc/incident-manager 8000:80  # Port forward
```

## Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `SECRET_KEY` | `dev-secret-key-...` | JWT signing key (CHANGE IN PRODUCTION) |
| `DATABASE_URL` | `sqlite+aiosqlite:///./incidents.db` | Database connection |
| `DEBUG` | `false` | Debug mode (verbose logging) |
| `CORS_ORIGINS` | `http://localhost:*` | Allowed CORS origins |
| `ALLOWED_HOSTS` | `localhost,127.0.0.1` | Allowed Host headers |
| `PORT` | `8000` | Server port |
| `ACCESS_TOKEN_EXPIRE_HOURS` | `24` | JWT expiration |

## Next Steps

1. Read [DEPLOYMENT.md](../DEPLOYMENT.md) for deployment options
2. Review [SECURITY.md](../SECURITY.md) for security best practices
3. Check [API.md](../API.md) for endpoint reference
4. Explore `app/routes/` to understand route patterns
5. Review `app/security.py` for auth/validation patterns
