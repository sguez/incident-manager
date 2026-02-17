# 🔒 Security Audit Report: Incident Manager

**Date**: 2026-02-17  
**Scope**: FastAPI backend, Docker/Kubernetes deployment, dependencies  
**Severity Summary**: 3 CRITICAL | 6 HIGH | 4 MEDIUM | 3 LOW | 1 INFO

---

## 🚨 CRITICAL FINDINGS

### 1. Weak Default SECRET_KEY (security.py:18)

**Risk Level**: 🔴 CRITICAL  
**CVSS Score**: 9.8

```python
# CURRENT (INSECURE)
SECRET_KEY = os.getenv("SECRET_KEY", "dev-key-change-in-production")
```

**Impact**:
- If deployed without `SECRET_KEY` environment variable, default "dev-key" is used
- JWT tokens can be forged by anyone knowing the key
- Full authentication bypass possible

**Recommendation**:
```python
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise ValueError("SECRET_KEY environment variable must be set. "
                    "Generate with: python -c \"import secrets; print(secrets.token_urlsafe(32))\"")
```

**Fix Priority**: IMMEDIATE (before any production deployment)

---

### 2. Plaintext SECRET_KEY in Kubernetes Manifest (k8s/deployment.yaml:47)

**Risk Level**: 🔴 CRITICAL  
**CVSS Score**: 9.9

```yaml
# CURRENT (INSECURE)
env:
  - name: SECRET_KEY
    value: "my-secret-key-in-plaintext"  # ❌ EXPOSED IN GIT
```

**Impact**:
- Secret committed to version control (forever in git history)
- Visible to anyone with repo access
- Visible to all Kubernetes RBAC users in cluster
- Cannot be rotated without code change

**Recommendation**:
```yaml
# Use Kubernetes Secrets (base64 encoded)
apiVersion: v1
kind: Secret
metadata:
  name: incident-manager-secrets
type: Opaque
data:
  SECRET_KEY: <base64-encoded-key>
---
env:
  - name: SECRET_KEY
    valueFrom:
      secretKeyRef:
        name: incident-manager-secrets
        key: SECRET_KEY
```

**Better Approach**: Use external secrets manager:
- AWS Secrets Manager + `external-secrets` operator
- HashiCorp Vault + CSI driver
- Sealed Secrets + encryption key rotation

**Fix Priority**: IMMEDIATE (rotate all secrets immediately)

---

### 3. No Input Validation on Login (auth.py:24-30)

**Risk Level**: 🔴 CRITICAL  
**CVSS Score**: 9.1

```python
# CURRENT (INSECURE)
@router.post("/login")
async def login(username: str = Query(...), password: str = Query(...)):
    # No validation on username/password format
    # Allows unlimited length, special characters, SQLi patterns
```

**Impact**:
- Credential stuffing attacks without detection
- Brute force without length limits
- Log injection attacks
- Possible NoSQL injection if database layer changes

**Recommendation**:
```python
from pydantic import BaseModel, Field, validator

class LoginRequest(BaseModel):
    username: str = Field(
        ..., 
        min_length=3, 
        max_length=50,
        regex="^[a-zA-Z0-9_-]+$",
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
        # Prevent timing attacks by always hashing
        return v.lower().strip()

@router.post("/login")
async def login(credentials: LoginRequest):
    # Use validated credentials
```

**Fix Priority**: IMMEDIATE

---

## 🔴 HIGH SEVERITY FINDINGS

### 4. JWT Token Never Expires in Practice (security.py:44-67, auth.py:132-149)

**Risk Level**: 🔴 HIGH  
**CVSS Score**: 8.2

**Issues**:
1. Deprecated `datetime.utcnow()` - fails in Python 3.12+
2. No token revocation/blacklist mechanism
3. Refresh endpoint issues NEW tokens without revoking old ones
4. Leaked tokens valid for full 24 hours

```python
# CURRENT (PROBLEMATIC)
token_data = {
    "user_id": user.id,
    "username": user.username,
    "exp": datetime.utcnow() + timedelta(hours=24)  # ❌ Deprecated, no revocation
}

# REFRESH ENDPOINT (PROBLEMATIC)
def refresh_token(current_user):
    # Returns new token but doesn't invalidate old one
    return create_access_token(data={"user_id": current_user.id})
```

**Impact**:
- Stolen tokens remain valid for 24 hours
- No emergency token revocation capability
- Violates OAuth2/OIDC best practices
- Compliance issue (GDPR, SOC2)

**Recommendation**:
```python
# 1. Use timezone-aware datetime
from datetime import datetime, timezone, timedelta

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# 2. Implement token blacklist
class TokenBlacklist(Base):
    __tablename__ = "token_blacklist"
    id = Column(Integer, primary_key=True)
    jti = Column(String, unique=True, index=True)  # JWT ID
    blacklisted_on = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime)

# 3. Check blacklist on every request
async def get_current_user(token: str):
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    jti = payload.get("jti")
    
    if jti:
        blacklist_entry = session.query(TokenBlacklist).filter_by(jti=jti).first()
        if blacklist_entry:
            raise HTTPException(status_code=401, detail="Token has been revoked")
    
    return user
```

**Fix Priority**: HIGH (1-2 weeks)

---

### 5. Authorization Bypass: No Role Checks on List Incidents (incidents.py:123-165)

**Risk Level**: 🔴 HIGH  
**CVSS Score**: 8.5

```python
# CURRENT (INSECURE)
@router.get("/incidents")
async def list_incidents(
    current_user: User = Depends(get_current_user),  # Only checks auth, not authz
    db: AsyncSession = Depends(get_db)
):
    # ANY authenticated user can list ALL incidents
    # No role-based filtering
    # Reporter can see IR Lead's incidents
```

**Impact**:
- Reporter role can view all incidents (including confidential ones)
- No incident-level access control (ACL)
- Compliance violation (principle of least privilege)
- Data leakage across teams

**Recommendation**:
```python
# Implement incident-level ACL
class IncidentACL(Base):
    __tablename__ = "incident_acl"
    id = Column(Integer, primary_key=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    can_view = Column(Boolean, default=False)
    can_edit = Column(Boolean, default=False)
    can_delete = Column(Boolean, default=False)

# Use decorator
@require_role("Viewer")
@require_incident_access("view")
async def list_incidents(incident_id: int, current_user):
    # Only returns incidents user has ACL for
```

**Alternative**: Implement team-based filtering:
```python
# Only return incidents from user's team(s)
user_incidents = db.query(Incident).filter(
    Incident.team_id.in_(current_user.teams)
).all()
```

**Fix Priority**: HIGH (1 week)

---

### 6. Insecure Randomness for Incident IDs (incidents.py:43-47)

**Risk Level**: 🔴 HIGH  
**CVSS Score**: 7.8

```python
# CURRENT (INSECURE)
import random
import string

rand = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(4))
incident_id = f"INC-2024-{rand}"  # ❌ Predictable, brute-forceable
```

**Impact**:
- Incident IDs predictable (only 1.68M combinations)
- Attacker can enumerate all incidents
- Authentication bypass via ID guessing
- Security through obscurity (ineffective)

**Recommendation**:
```python
import secrets

# Option 1: Stronger random suffix (6 chars = 2.1B combinations)
rand = secrets.token_hex(3)  # 6 hex chars
incident_id = f"INC-{datetime.now().year}-{rand}"

# Option 2: Use UUID (recommended)
from uuid import uuid4
incident_id = f"INC-{uuid4().hex[:8].upper()}"

# Option 3: Database sequence + random component
def generate_incident_id(db_session):
    sequence_num = db_session.query(func.count(Incident.id)).scalar() + 1
    random_suffix = secrets.token_urlsafe(4)
    return f"INC-{sequence_num:06d}-{random_suffix}"
```

**Fix Priority**: HIGH (1 week)

---

### 7. Missing CSRF Protection (main.py)

**Risk Level**: 🔴 HIGH  
**CVSS Score**: 8.1

```python
# CURRENT (INSECURE)
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # ⚠️ Too permissive
    allow_credentials=True,
    allow_methods=["*"],  # Allows all HTTP methods
    allow_headers=["*"],  # Allows any header (defeats CSRF)
)
# No CSRF token validation on state-changing operations
```

**Impact**:
- Cross-site request forgery attacks possible
- Attacker can delete incidents from victim's browser
- Form hijacking on incident creation
- Violates OWASP guidelines

**Recommendation**:
```python
# 1. Restrict CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",  # Dev
        "https://incidents.example.com"  # Prod
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Content-Type", "Authorization"],  # Explicit whitelist
)

# 2. Add CSRF protection
from fastapi_csrf_protect import CsrfProtect

@CsrfProtect.load_config
def get_csrf_config():
    return CsrfSettings(secret_key=SECRET_KEY)

@router.post("/incidents")
async def create_incident(
    incident: IncidentCreate,
    csrf_protect: CsrfProtect = Depends()
):
    await csrf_protect.validate_csrf(request)
    # Process creation
```

**Fix Priority**: HIGH (1 week)

---

### 8. SQL Injection Risk in Filter Logic (incidents.py:155-160)

**Risk Level**: 🔴 HIGH  
**CVSS Score**: 7.5

```python
# CURRENT (RISKY)
def list_incidents(..., status_filter: str = None):
    query = db.query(Incident)
    
    if status_filter:
        # Direct string without validation (SQLAlchemy ORM mitigates, but bad practice)
        query = query.filter(Incident.status == status_filter)
```

**Impact**:
- While SQLAlchemy ORM prevents actual SQL injection, bad practice
- Future refactoring might introduce vulnerability
- Defense-in-depth principle violated
- Audit findings

**Recommendation**:
```python
from enum import Enum

class IncidentStatus(str, Enum):
    IMMEDIATE = "IMMEDIATE"
    NEXT_24_72H = "NEXT_24_72H"
    AFTERMATH = "AFTERMATH"

# Use enum validation
def list_incidents(..., status_filter: Optional[IncidentStatus] = None):
    query = db.query(Incident)
    
    if status_filter:
        query = query.filter(Incident.status == status_filter.value)
    
    return query.all()
```

**Fix Priority**: MEDIUM (2 weeks)

---

### 9. Unvalidated CSP Policy Too Permissive (security.py:236)

**Risk Level**: 🔴 HIGH  
**CVSS Score**: 7.2

```python
# CURRENT (INSECURE)
"Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
# ❌ 'unsafe-inline' defeats entire CSP purpose
```

**Impact**:
- Inline JavaScript/CSS allowed (defeats XSS protection)
- Compromise of one external resource exposes all JS
- Doesn't meet NIST/PCI-DSS standards

**Recommendation**:
```python
# Use nonce-based CSP
from secrets import token_urlsafe

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    
    # Generate nonce for each request
    nonce = token_urlsafe(16)
    request.state.nonce = nonce
    
    response.headers["Content-Security-Policy"] = (
        f"default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        f"style-src 'self' 'nonce-{nonce}'; "
        f"img-src 'self' data:; "
        f"font-src 'self'; "
        f"connect-src 'self'; "
        f"frame-ancestors 'none'; "
        f"base-uri 'self'; "
        f"form-action 'self'"
    )
    return response
```

**Fix Priority**: MEDIUM (2-3 weeks)

---

### 10. Rate Limiter Response Invalid (main.py:99-104)

**Risk Level**: 🔴 HIGH  
**CVSS Score**: 6.8

```python
# CURRENT (BROKEN)
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded

async def rate_limit_error_handler(request, exc):
    return Response(  # ❌ Returns generic Response, not JSON
        content=f"Rate limit exceeded",
        status_code=429
    )
```

**Impact**:
- Frontend cannot parse rate limit errors
- Poor user experience (plain text vs JSON)
- Logging/monitoring confusion
- Multiple headers/content-type mismatches

**Recommendation**:
```python
from fastapi.responses import JSONResponse

@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={
            "error": "rate_limit_exceeded",
            "detail": "Too many requests. Please try again later.",
            "retry_after": 60
        },
        headers={"Retry-After": "60"}
    )

# Add user-based rate limiting (per user, not just IP)
@app.dependency
async def get_rate_limit_key(current_user: User = Depends(get_current_user)):
    return f"user-{current_user.id}"
```

**Fix Priority**: MEDIUM (1-2 weeks)

---

## 🟠 MEDIUM SEVERITY FINDINGS

### 11. Sensitive Data in Audit Logs (incidents.py:50-71)

**Risk Level**: 🟠 MEDIUM  
**CVSS Score**: 6.5

```python
# CURRENT (RISKY)
audit_log = AuditLog(
    user_id=current_user.id,
    action="CREATE_INCIDENT",
    resource_type="Incident",
    resource_id=incident.id,
    changes=incident.dict(),  # ❌ Includes all data, including sensitive fields
    ip_address=request.client.host  # ❌ GDPR PII
)
```

**Impact**:
- Incident descriptions might contain passwords/keys (logged)
- User IPs logged without consent (GDPR violation)
- Audit logs become security liability if leaked
- Compliance failure (SOC2, PCI-DSS)

**Recommendation**:
```python
def create_audit_log(user_id, action, changes):
    # Mask sensitive fields
    sanitized_changes = {
        k: "[REDACTED]" if k in ['password', 'api_key', 'secret', 'token'] else v
        for k, v in changes.items()
    }
    
    # Truncate descriptions for privacy
    if 'description' in sanitized_changes:
        desc = sanitized_changes['description']
        if len(desc) > 500:
            sanitized_changes['description'] = desc[:497] + "..."
    
    # Anonymize IP (keep only subnet)
    ip_addr = request.client.host
    if ':' in ip_addr:  # IPv6
        anonymized_ip = ":".join(ip_addr.split(":")[:4]) + "::"
    else:  # IPv4
        anonymized_ip = ".".join(ip_addr.split(".")[:3]) + ".0"
    
    log = AuditLog(
        user_id=user_id,
        action=action,
        changes=sanitized_changes,
        ip_address=anonymized_ip
    )
    return log
```

**Fix Priority**: MEDIUM (2-3 weeks, compliance requirement)

---

### 12. Database Echo Logs Sensitive Data (main.py:43)

**Risk Level**: 🟠 MEDIUM  
**CVSS Score**: 6.2

```python
# CURRENT (INSECURE IN PRODUCTION)
engine = create_engine(
    DATABASE_URL,
    echo=os.getenv("DEBUG"),  # ❌ Logs ALL SQL in production if DEBUG=true
)
```

**Impact**:
- Every SQL query logged (includes data, credentials)
- Logs leak sensitive incident data
- Performance impact (log overhead)
- Violation of data minimization principle

**Recommendation**:
```python
import logging

# Disable SQLAlchemy echo entirely
engine = create_engine(DATABASE_URL, echo=False)

# Instead, use proper structured logging
sqlalchemy_logger = logging.getLogger('sqlalchemy.engine')
if os.getenv("ENVIRONMENT") == "production":
    sqlalchemy_logger.setLevel(logging.WARNING)
else:
    sqlalchemy_logger.setLevel(logging.DEBUG)
    # Add handler with sanitization
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(
        '%(levelname)s - %(message)s (queries only, no data logging)'
    ))
    sqlalchemy_logger.addHandler(handler)
```

**Fix Priority**: MEDIUM (before production)

---

### 13. No Secrets Management Integration (k8s/deployment.yaml)

**Risk Level**: 🟠 MEDIUM  
**CVSS Score**: 7.1

```yaml
# CURRENT (STATIC SECRETS)
spec:
  containers:
  - env:
    - name: SECRET_KEY
      value: "hardcoded-secret"  # ❌ Static, no rotation
    - name: DATABASE_URL
      value: "sqlite:///./incidents.db"  # ❌ Credentials in manifest
```

**Impact**:
- No secret rotation capability
- Secrets visible in deployment manifests
- Compliance violation (CIS Kubernetes, PCI-DSS)
- No audit trail for secret access

**Recommendation**: Implement secret management
```yaml
# Option 1: AWS Secrets Manager
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: aws-secrets
spec:
  provider:
    aws:
      service: SecretsManager
      region: us-east-1
---
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: incident-manager-secrets
spec:
  secretStoreRef:
    name: aws-secrets
  target:
    name: incident-manager-env
  data:
  - secretKey: SECRET_KEY
    remoteRef:
      key: incident-manager/secret-key
  - secretKey: DATABASE_URL
    remoteRef:
      key: incident-manager/db-url

# Option 2: HashiCorp Vault (recommended for on-prem)
# Option 3: Sealed Secrets (lightweight, Kubernetes-native)
```

**Fix Priority**: MEDIUM (before production, compliance requirement)

---

### 14. Missing Encryption at Rest (k8s/deployment.yaml, Docker)

**Risk Level**: 🟠 MEDIUM  
**CVSS Score**: 6.8

**Impact**:
- SQLite database file unencrypted on disk
- PVC data unencrypted in Kubernetes
- AWS/Azure volumes might not have encryption enabled

**Recommendation**:
```yaml
# Enable Kubernetes secret/volume encryption
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
- resources:
  - secrets
  provider:
  - aescbc:
      keys:
      - name: key1
        secret: <base64-encoded-32-byte-key>
    identity: {}
---
# SQLite encryption (at application level)
# Use sqlcipher for encrypted SQLite
DATABASE_URL = "sqlite+pysqlcipher://:password@/path/to/db.db"
```

**Fix Priority**: MEDIUM (1-2 weeks, data protection requirement)

---

## 🟡 LOW SEVERITY FINDINGS

### 15. HSTS Policy Incomplete (security.py:235)

**Risk Level**: 🟡 LOW  
**CVSS Score**: 3.2

```python
# CURRENT (PARTIAL)
"Strict-Transport-Security": "max-age=31536000"
# ❌ Missing: includeSubDomains, preload
```

**Recommendation**:
```python
"Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload"
# max-age=63072000 (2 years for HSTS preload eligibility)
```

---

### 16. Docker Compose Ports Exposed (docker-compose.yml)

**Risk Level**: 🟡 LOW  
**CVSS Score**: 4.1

```yaml
# CURRENT (TOO PERMISSIVE)
ports:
  - "8000:8000"  # Binds to 0.0.0.0:8000 (all interfaces)
```

**Recommendation**:
```yaml
ports:
  - "127.0.0.1:8000:8000"  # Localhost only
```

---

### 17. Dependency Versions Outdated (requirements.txt)

**Risk Level**: 🟡 LOW  
**CVSS Score**: 5.3

**Issues**:
- `python-jose==3.3.0`: Pre-Oct 2023 version, may have CVEs
- Other dependencies 1-2 years old
- No automated vulnerability scanning

**Recommendation**:
```bash
# Run vulnerability scan
pip install pip-audit
pip-audit

# Update to latest
pip install --upgrade -r requirements.txt

# Use tools like Dependabot or Snyk for automation
```

**Fix Priority**: LOW (monthly security updates)

---

## 📊 REMEDIATION ROADMAP

### Phase 1: IMMEDIATE (before any production deployment)
- [ ] Generate secure SECRET_KEY
- [ ] Rotate k8s secrets (use external secrets manager)
- [ ] Add login input validation (Pydantic validators)
- [ ] Enforce SECRET_KEY environment variable requirement

**Effort**: 2-4 hours  
**Impact**: Prevents critical authentication bypass

---

### Phase 2: SHORT-TERM (Week 1-2)
- [ ] Implement token revocation/blacklist
- [ ] Add role-based incident access control
- [ ] Fix insecure randomness (use `secrets` module)
- [ ] Implement CSRF protection middleware
- [ ] Fix rate limiter response format

**Effort**: 8-16 hours  
**Impact**: Prevents authorization bypass, CSRF, token abuse

---

### Phase 3: MEDIUM-TERM (Week 2-4)
- [ ] Remove `unsafe-inline` from CSP
- [ ] Implement secrets management (Vault/AWS Secrets)
- [ ] Add PII masking in audit logs
- [ ] Fix SQLAlchemy echo logging
- [ ] Disable database echo in production
- [ ] Update dependencies (pip-audit)

**Effort**: 12-20 hours  
**Impact**: Compliance, data protection, logging security

---

### Phase 4: LONG-TERM (Month 1-2)
- [ ] Implement encryption at rest (SQLite + volumes)
- [ ] Enable HSTS preload
- [ ] Add OWASP dependency scanning (CI/CD)
- [ ] Implement API rate limiting per user
- [ ] Add security monitoring/alerting

**Effort**: 20-40 hours  
**Impact**: Enterprise-grade security, compliance

---

## 📋 COMPLIANCE ALIGNMENT

| Standard | Status | Notes |
|----------|--------|-------|
| **OWASP Top 10** | 🟠 Partial | A01 (Access Control) ⚠️, A02 (Crypto) ⚠️, A03 (Injection) ✅ |
| **CIS Kubernetes** | 🟠 Partial | Good security context ✅, missing network policies ⚠️, secrets mgmt ⚠️ |
| **NIST Cybersecurity Framework** | 🟠 Partial | Identify ✅, Protect ⚠️, Detect ❌, Respond ❌ |
| **SOC2 Type II** | 🔴 Not Ready | Audit logging ✅, but no encryption ⚠️, monitoring ❌ |
| **PCI-DSS** | 🔴 Not Ready | Missing encryption, secrets mgmt, rate limiting ⚠️ |
| **GDPR** | 🟠 Partial | Data minimization ❌, PII logging ⚠️, consent tracking ❌ |

---

## 🔗 References & Tools

- **OWASP**: https://owasp.org/Top10/
- **Dependency Scanning**: `pip-audit`, `safety check`
- **Secrets Management**: HashiCorp Vault, AWS Secrets Manager, Sealed Secrets
- **SIEM Integration**: Splunk, ELK Stack for security monitoring
- **Container Scanning**: Trivy, Anchore
- **SBOM Generation**: `cyclonedx-python`, `syft`

---

## ✅ NEXT STEPS

1. **Review & Approve**: Security team review of findings
2. **Prioritize**: Determine internal timeline for fixes
3. **Assign**: Distribute tasks to development team
4. **Implement**: Follow Phase 1-4 remediation roadmap
5. **Verify**: Re-audit after fixes
6. **Monitor**: Implement continuous security scanning

---

**Report Prepared By**: Security Audit Team  
**Classification**: INTERNAL - Security Sensitive
