# Security Guide

Comprehensive security documentation following `.claude_skills` patterns.

⚠️ **IMPORTANT**: See [SECURITY_AUDIT.md](SECURITY_AUDIT.md) for full security audit findings and remediation roadmap (3 CRITICAL, 6 HIGH, 4 MEDIUM findings with fixes).

## Table of Contents
1. [Security Audit Findings](#security-audit-findings)
2. [Authentication & Authorization](#authentication--authorization)
3. [Input Validation & Output Encoding](#input-validation--output-encoding)
4. [Audit Logging](#audit-logging)
5. [Container Security](#container-security)
6. [Kubernetes Security](#kubernetes-security)
7. [Best Practices](#best-practices)
8. [Security Checklist](#security-checklist)

---

## Security Audit Findings

**Last Audit**: 2026-02-17  
**Status**: 🟠 Partial Compliance - Improvements in Progress

### Critical Issues Addressed
- ✅ Secure SECRET_KEY requirement (no defaults)
- ✅ Input validation on login credentials
- ✅ Secure randomness for incident IDs
- ✅ Timezone-aware JWT expiration

### High Priority Items (In Progress)
- 🔄 Token revocation/blacklist mechanism (Week 1-2)
- 🔄 Incident-level access control (Week 1-2)
- 🔄 CSRF protection middleware (Week 1-2)
- 🔄 Secrets management integration (Week 2-4)

**See [SECURITY_AUDIT.md](SECURITY_AUDIT.md) for detailed findings, risk levels, and remediation roadmap.**

---

## Authentication & Authorization

### JWT Authentication

Tokens are signed with HS256 algorithm and include:
```json
{
  "sub": "1",
  "user_id": "1",
  "username": "john_doe",
  "roles": ["ir_lead"],
  "exp": 1705338000,
  "iat": 1705251600
}
```

**Token Management:**
- Default expiration: 24 hours (configurable via `ACCESS_TOKEN_EXPIRE_HOURS`)
- ✅ Timezone-aware expiration (UTC)
- Use refresh endpoint to get new token before expiration
- Tokens are signed with `SECRET_KEY` (must be set via environment variable)
- Tokens use Bearer scheme in Authorization header

**Secure Token Setup:**
```bash
# 1. Generate secure SECRET_KEY
python -c "import secrets; print(secrets.token_urlsafe(32))"

# 2. Set in environment
export SECRET_KEY="your-generated-key-here"

# 3. Login with validated credentials
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user","password":"pass"}' \
  -c cookies.txt
```

**Secure Token Handling:**
```bash
# DO: Store in secure HTTP-only cookie or secure storage
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user","password":"pass"}' \
  -c cookies.txt  # Save to secure cookie

# DON'T: Store in localStorage (vulnerable to XSS)
# DON'T: Log tokens in console/logs
```

### Role-Based Access Control (RBAC)

Four roles with hierarchical permissions:

| Role | Permissions | Use Case |
|------|-------------|----------|
| `admin` | Create/read/update/delete incidents, manage users, view audit logs | System administrator |
| `ir_lead` | Create/read/update incidents, view audit logs for their incidents | Incident response lead |
| `viewer` | Read-only access to incidents | Stakeholders, analysts |
| `reporter` | Create and read own incidents | External reporters |

**Endpoint Role Requirements:**

```python
# Require specific role(s)
@router.post("/incidents")
async def create_incident(
    current_user=Depends(require_role(UserRole.IR_LEAD, UserRole.ADMIN))
):
    # Only IR_LEAD or ADMIN can create

# Require all roles (rarely used)
@router.get("/admin/settings")
async def get_settings(
    current_user=Depends(require_all_roles(UserRole.ADMIN))
):
    # Must have all listed roles
```

**Checking Roles in Code:**
```python
def check_incident_access(current_user: TokenPayload, incident: Incident) -> bool:
    """Check if user can access incident."""
    if UserRole.ADMIN in current_user.roles:
        return True  # Admins can access anything
    
    if UserRole.IR_LEAD in current_user.roles:
        return incident.created_by_id == int(current_user.user_id) or \
               incident.status == "open"  # Custom logic
    
    if UserRole.VIEWER in current_user.roles:
        return True  # Read-only
    
    return False
```

---

## Input Validation & Output Encoding

### Input Validation

All inputs validated using Pydantic schemas:

```python
from pydantic import BaseModel, Field, validator

class IncidentMetadata(BaseModel):
    name: str = Field(..., min_length=1, max_length=500)
    severity: Severity  # Enum - only valid values
    classification: Classification
    reported_by: str = Field(..., min_length=1, max_length=200)
    detection_source: str = Field(..., min_length=1, max_length=500)
    incident_start: str  # ISO-8601 format validated

    @validator('incident_start')
    def validate_timestamp(cls, v):
        # Custom validation
        InputValidator.validate_iso8601(v)
        return v
```

**Validation Rules:**
- ✅ String length constraints (min/max)
- ✅ Enum types (only allowed values)
- ✅ Regular expressions (format validation)
- ✅ Type hints (prevent type confusion)
- ✅ Custom validators (complex logic)

**SQL Injection Prevention:**
- ✅ SQLAlchemy ORM (parameterized queries)
- ✅ Never use string interpolation in queries
- ✅ Input validated before database access

```python
# SAFE: Using ORM with parameterization
result = await session.execute(
    select(Incident).filter(Incident.name == user_input)
)

# UNSAFE: String interpolation (DON'T DO THIS)
# query = f"SELECT * FROM incidents WHERE name = '{user_input}'"
```

### Output Encoding

Prevents XSS attacks in exported reports:

**Markdown Escaping:**
```python
def md_escape(text: str) -> str:
    """Escape markdown special characters."""
    special_chars = ['\\', '`', '*', '_', '{', '}', '[', ']', '(', ')', '#', '+', '-', '.', '!', '|']
    for char in special_chars:
        text = text.replace(char, f'\\{char}')
    return text

# Usage in exports
md_content = f"# {md_escape(incident.name)}"
md_content = f"**Created by:** {md_escape(incident.created_by.username)}"
```

**HTML Escaping:**
```python
def html_escape(text: str) -> str:
    """Escape HTML special characters."""
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

# Usage in exports
html_content = f'<title>{html_escape(incident.name)}</title>'
html_content = f'<p>Created by: {html_escape(incident.created_by.username)}</p>'
```

**URL Encoding:**
```python
from urllib.parse import quote

# For export filenames
filename = f"incident_{quote(incident.incident_key)}.md"
```

---

## Audit Logging

Every mutation is logged for DFIR compliance and forensic investigation.

### Logged Actions

| Action | Resource | When | Fields Logged |
|--------|----------|------|---------------|
| `create` | incident, user | Resource created | New values |
| `update` | incident, user | Resource modified | Old and new values |
| `delete` | incident, user | Resource deleted | Deletion timestamp |
| `view` | incident | Read access | None (just access record) |
| `export` | incident | Report exported | Export format |
| `login` | user | User authenticated | Success/failure |

### Audit Log Entry

```python
class AuditLog(Base):
    """Audit log for compliance."""
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=True)
    action = Column(String(100), nullable=False)  # create, update, delete
    resource_type = Column(String(50), nullable=False)  # incident, user, task
    resource_id = Column(String(100), nullable=True)  # ID of affected resource
    changes = Column(JSON, nullable=True)  # Before/after values
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    ip_address = Column(String(45), nullable=True)  # IPv4 or IPv6
```

### Logging in Code

```python
async def log_audit(
    session: AsyncSession,
    user_id: int,
    action: str,
    resource_type: str,
    resource_id: str = None,
    incident_id: int = None,
    changes: dict = None,
    ip_address: str = None,
):
    """Log audit trail."""
    audit_entry = AuditLog(
        user_id=user_id,
        incident_id=incident_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        changes=changes,  # {"field": {"old": "val1", "new": "val2"}}
        ip_address=ip_address,
    )
    session.add(audit_entry)
    await session.flush()
```

### Querying Audit Logs

```bash
# View all audit logs (admin only)
curl "http://localhost:8000/api/audit" \
  -H "Authorization: Bearer $TOKEN"

# Filter by incident
curl "http://localhost:8000/api/audit?incident_id=1" \
  -H "Authorization: Bearer $TOKEN"

# Filter by action
curl "http://localhost:8000/api/audit?action=delete" \
  -H "Authorization: Bearer $TOKEN"

# Filter by user
curl "http://localhost:8000/api/audit?user_id=1" \
  -H "Authorization: Bearer $TOKEN"
```

### Audit Log Analysis (DFIR Investigation)

```bash
# Find all incidents modified by specific user
curl "http://localhost:8000/api/audit?action=update&user_id=5" \
  -H "Authorization: Bearer $TOKEN" | jq '.[] | select(.action=="update")'

# Find all deletes (forensic evidence)
curl "http://localhost:8000/api/audit?action=delete" \
  -H "Authorization: Bearer $TOKEN"

# Track incident modifications
curl "http://localhost:8000/api/audit/incident/1" \
  -H "Authorization: Bearer $TOKEN"
```

---

## Container Security

### Dockerfile Best Practices

```dockerfile
# Multi-stage build (reduces image size)
FROM python:3.13-slim as builder
RUN pip wheel --no-cache-dir --no-deps -w /wheels -r requirements.txt

# Final stage
FROM python:3.13-slim
RUN useradd -m -u 1000 appuser  # Non-root user
COPY --from=builder /wheels /wheels
COPY . .
RUN chown -R appuser:appuser /app
USER appuser  # Run as non-root

# Health check
HEALTHCHECK --interval=30s --timeout=10s \
  CMD curl -f http://localhost:8000/health || exit 1

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0"]
```

### Runtime Security

**Run as Non-Root:**
```bash
# In Docker
docker run --user 1000:1000 incident-manager:latest

# Verify
docker inspect incident-manager | grep -i uid
```

**Read-Only Filesystem:**
```bash
# In Docker
docker run --read-only \
  --tmpfs /tmp \
  --tmpfs /app/logs \
  incident-manager:latest

# Or in k8s (see below)
```

**Dropped Capabilities:**
```bash
# Remove unnecessary capabilities
docker run --cap-drop=ALL \
  --cap-add=NET_BIND_SERVICE \
  incident-manager:latest
```

---

## Kubernetes Security

### Pod Security Context

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  fsGroup: 1000  # All volumes owned by this group
  
containerSecurityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop:
      - ALL
  # Add back only if needed:
  # add:
  #   - NET_BIND_SERVICE
```

### Network Policies

Restrict ingress/egress traffic:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: incident-manager
spec:
  podSelector:
    matchLabels:
      app: incident-manager
  
  # Restrict ingress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: incident-manager
    - podSelector:
        matchLabels:
          role: frontend  # Allow frontend pods
    ports:
    - protocol: TCP
      port: 8000
  
  # Restrict egress
  egress:
  - to:
    - namespaceSelector: {}
    ports:
    - protocol: TCP
      port: 53  # DNS only
    - protocol: UDP
      port: 53
```

### RBAC (Role-Based Access Control)

Limit what pods can do in cluster:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: incident-manager

---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: incident-manager
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]  # Minimal permissions

---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: incident-manager
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: incident-manager
subjects:
- kind: ServiceAccount
  name: incident-manager
```

### Secrets Management

Store sensitive data in Kubernetes Secrets:

```bash
# Create secret from literals
kubectl create secret generic incident-manager-secrets \
  --from-literal=SECRET_KEY="$(openssl rand -hex 32)" \
  --from-literal=DATABASE_URL="sqlite+aiosqlite:///./incidents.db" \
  -n incident-manager

# Or from file
echo "new-secret-key-value" > secret.txt
kubectl create secret generic incident-manager-secrets \
  --from-file=SECRET_KEY=secret.txt \
  -n incident-manager

# Use in deployment
env:
- name: SECRET_KEY
  valueFrom:
    secretKeyRef:
      name: incident-manager-secrets
      key: SECRET_KEY
```

---

## Best Practices

### 1. **Change Default Credentials**

```bash
# On startup, force password change for admin
# Generate secure random password
python3 -c "import secrets; print(secrets.token_urlsafe(32))"

# Update admin password via API
TOKEN=$(curl -X POST http://localhost:8000/api/auth/login \
  -d "username=admin&password=change-me" | jq -r '.access_token')

# Don't expose new password in logs!
```

### 2. **Use HTTPS/TLS in Production**

```bash
# With ingress + cert-manager
kubectl apply -f - << 'EOF'
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: incident-manager-cert
  namespace: incident-manager
spec:
  secretName: incident-manager-tls
  issuerRef:
    name: letsencrypt-prod
    kind: ClusterIssuer
  dnsNames:
  - incident-manager.example.com
EOF
```

### 3. **Enable CORS Restrictively**

```bash
# Production: Only allow your frontend domain
export CORS_ORIGINS="https://incident-manager.example.com"

# NOT: "http://localhost:*" or "*"
```

### 4. **Secure Secret Key**

```bash
# Generate strong random key (minimum 32 bytes)
export SECRET_KEY=$(openssl rand -hex 32)

# Store securely:
# - AWS Secrets Manager
# - HashiCorp Vault
# - Kubernetes Secrets
# - Environment variable (in production container/pod)

# DON'T: Hardcode in code or docker-compose.yml
```

### 5. **Regular Backups**

```bash
# Backup SQLite database
docker exec incident-manager cp /app/incidents.db /backups/incidents_$(date +%Y%m%d).db

# Or automated with cron/k8s CronJob
docker exec incident-manager sqlite3 /app/incidents.db ".backup /backups/incidents_$(date +%s).db"

# Test backup restoration
sqlite3 /backups/incidents_2025-01-15.db ".tables"
```

### 6. **Monitor & Alert**

```bash
# Log shipping
docker logs incident-manager | tee app.log

# Monitor health
while true; do
  curl -f http://localhost:8000/health || alert "Health check failed"
  sleep 30
done

# Monitor resource usage
docker stats incident-manager
```

### 7. **Keep Dependencies Updated**

```bash
# Check for vulnerabilities
pip install --upgrade pip
pip check

# Update packages
pip install --upgrade -r requirements.txt

# Use specific versions in production
pip freeze > requirements.lock

# Regular updates (quarterly minimum)
```

---

## Security Checklist

### Before Deployment
- [ ] Generate new `SECRET_KEY` with `openssl rand -hex 32`
- [ ] Change admin password from default
- [ ] Set `DEBUG=false` in production
- [ ] Configure `CORS_ORIGINS` to your domain only
- [ ] Enable HTTPS/TLS certificates
- [ ] Test database backup and restore
- [ ] Review all role assignments
- [ ] Enable audit logging
- [ ] Set up log aggregation/monitoring

### Docker Deployment
- [ ] Run as non-root user
- [ ] Use read-only filesystem (`--read-only`)
- [ ] Drop capabilities (`--cap-drop=ALL`)
- [ ] Set resource limits
- [ ] Enable health checks
- [ ] Use private container registry
- [ ] Scan image for vulnerabilities
- [ ] Sign container images

### Kubernetes Deployment
- [ ] Pod security context: non-root, read-only FS
- [ ] Network policies restrict traffic
- [ ] RBAC configured with minimal permissions
- [ ] Secrets stored in k8s Secrets (not ConfigMaps)
- [ ] PodDisruptionBudget configured
- [ ] Resource requests/limits set
- [ ] Ingress with TLS certificate
- [ ] Pod security standards enforced

### Ongoing Operations
- [ ] Review audit logs weekly
- [ ] Monitor for unusual access patterns
- [ ] Test disaster recovery monthly
- [ ] Update dependencies quarterly
- [ ] Rotate secrets annually
- [ ] Security scan quarterly
- [ ] Load testing before traffic surge

---

## Incident Response

If security incident occurs:

1. **Enable verbose logging:**
   ```bash
   export DEBUG=true
   # Restart application
   ```

2. **Review audit logs:**
   ```bash
   curl "http://localhost:8000/api/audit" \
     -H "Authorization: Bearer $ADMIN_TOKEN" \
     | jq '.[].ip_address' | sort | uniq -c
   ```

3. **Check who accessed incident:**
   ```bash
   curl "http://localhost:8000/api/audit/incident/ID" \
     -H "Authorization: Bearer $ADMIN_TOKEN"
   ```

4. **Disable compromised user:**
   ```bash
   curl -X DELETE http://localhost:8000/api/users/USER_ID \
     -H "Authorization: Bearer $ADMIN_TOKEN"
   ```

5. **Rotate credentials:**
   ```bash
   export SECRET_KEY=$(openssl rand -hex 32)
   # Redeploy/restart application
   ```

---

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [.claude_skills: designing-secure-apis](./claude-skills/designing-secure-apis/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [DFIR Application Security Playbook](https://blog.sguez.dev/dfir-application-security)

---

**Security is Everyone's Responsibility** 🔐
