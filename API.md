# API Reference

Complete REST API documentation for Incident Manager.

## Base URL
```
http://localhost:8000/api
```

## Authentication
All endpoints (except `/auth/register` and `/auth/login`) require JWT token in `Authorization` header:
```
Authorization: Bearer <token>
```

## Table of Contents
1. [Authentication](#authentication)
2. [Incidents](#incidents)
3. [Exports](#exports)
4. [Users](#users)
5. [Audit Logs](#audit-logs)
6. [Error Handling](#error-handling)

---

## Authentication

### Register
Create a new user account.

**POST** `/auth/register`

**Request:**
```json
{
  "username": "john_doe",
  "email": "john@example.com",
  "password": "secure_password_123"
}
```

**Response:** `200 OK`
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "token_type": "bearer",
  "expires_in": 86400
}
```

**cURL:**
```bash
curl -X POST http://localhost:8000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john_doe",
    "email": "john@example.com",
    "password": "secure_password_123"
  }'
```

---

### Login
Authenticate and get JWT token.

**POST** `/auth/login`

**Request:**
```
Form data:
  username=john_doe
  password=secure_password_123
```

**Response:** `200 OK`
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "token_type": "bearer",
  "expires_in": 86400
}
```

**cURL:**
```bash
curl -X POST http://localhost:8000/api/auth/login \
  -d "username=john_doe&password=secure_password_123"
```

---

### Get Current User
Get logged-in user information.

**GET** `/auth/me`

**Headers:**
```
Authorization: Bearer <token>
```

**Response:** `200 OK`
```json
{
  "user_id": "1",
  "username": "john_doe",
  "roles": ["ir_lead"]
}
```

**cURL:**
```bash
curl http://localhost:8000/api/auth/me \
  -H "Authorization: Bearer $TOKEN"
```

---

### Refresh Token
Get a new JWT token using existing token.

**POST** `/auth/refresh`

**Headers:**
```
Authorization: Bearer <token>
```

**Response:** `200 OK`
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "token_type": "bearer",
  "expires_in": 86400
}
```

---

## Incidents

### Create Incident
Create a new incident (requires `ir_lead` or `admin` role).

**POST** `/incidents`

**Headers:**
```
Authorization: Bearer <token>
Content-Type: application/json
```

**Request:**
```json
{
  "metadata": {
    "name": "Production data breach",
    "severity": "critical",
    "classification": "data_breach",
    "reported_by": "Security Team",
    "detection_source": "WAF Alert on /api/users",
    "incident_start": "2025-01-15T14:30:00Z"
  },
  "roles": [
    {
      "role": "ir_lead",
      "person": "John Doe"
    },
    {
      "role": "app_owner",
      "person": "Jane Smith"
    },
    {
      "role": "secops",
      "person": "Security Ops Team"
    }
  ]
}
```

**Response:** `201 Created`
```json
{
  "id": 1,
  "incident_key": "abcd-2025-01-15",
  "severity": "critical",
  "status": "open",
  "created_at": "2025-01-15T15:00:00",
  "updated_at": "2025-01-15T15:00:00",
  "created_by_id": 1,
  "metadata": {
    "name": "Production data breach",
    "severity": "critical",
    "classification": "data_breach",
    "reported_by": "Security Team",
    "detection_source": "WAF Alert on /api/users",
    "incident_start": "2025-01-15T14:30:00Z"
  },
  "roles": [
    {"role": "ir_lead", "person": "John Doe"},
    {"role": "app_owner", "person": "Jane Smith"},
    {"role": "secops", "person": "Security Ops Team"}
  ],
  "triggers": [],
  "tasks": [],
  "evidence": [],
  "timeline": [],
  "checklist": []
}
```

**cURL:**
```bash
curl -X POST http://localhost:8000/api/incidents \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d @- << 'EOF'
{
  "metadata": {
    "name": "Production data breach",
    "severity": "critical",
    "classification": "data_breach",
    "reported_by": "Security Team",
    "detection_source": "WAF Alert on /api/users",
    "incident_start": "2025-01-15T14:30:00Z"
  },
  "roles": [{"role": "ir_lead", "person": "John Doe"}]
}
EOF
```

---

### List Incidents
Get paginated incident list.

**GET** `/incidents`

**Headers:**
```
Authorization: Bearer <token>
```

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `skip` | int | 0 | Number of incidents to skip |
| `limit` | int | 50 | Max incidents to return (max: 100) |
| `status_filter` | string | null | Filter by status (open, closed) |
| `severity_filter` | string | null | Filter by severity (critical, high, medium, low) |

**Response:** `200 OK`
```json
[
  {
    "id": 1,
    "incident_key": "abcd-2025-01-15",
    "name": "Production data breach",
    "severity": "critical",
    "status": "open",
    "created_at": "2025-01-15T15:00:00",
    "updated_at": "2025-01-15T15:00:00"
  }
]
```

**cURL:**
```bash
# List all (first 50)
curl http://localhost:8000/api/incidents \
  -H "Authorization: Bearer $TOKEN"

# With filtering
curl "http://localhost:8000/api/incidents?severity_filter=critical&limit=10" \
  -H "Authorization: Bearer $TOKEN"
```

---

### Get Incident
Get full incident details.

**GET** `/incidents/{incident_id}`

**Headers:**
```
Authorization: Bearer <token>
```

**Response:** `200 OK`
```json
{
  "id": 1,
  "incident_key": "abcd-2025-01-15",
  "severity": "critical",
  "status": "open",
  "created_at": "2025-01-15T15:00:00",
  "updated_at": "2025-01-15T15:00:00",
  "created_by_id": 1,
  "metadata": {...},
  "roles": [...],
  "triggers": [...],
  "tasks": [...],
  "evidence": [...],
  "timeline": [...],
  "checklist": [...]
}
```

**cURL:**
```bash
curl http://localhost:8000/api/incidents/1 \
  -H "Authorization: Bearer $TOKEN"
```

---

### Update Incident
Update incident details (requires `ir_lead` or `admin` role).

**PATCH** `/incidents/{incident_id}`

**Headers:**
```
Authorization: Bearer <token>
Content-Type: application/json
```

**Request:**
```json
{
  "metadata": {
    "name": "Updated incident name",
    "severity": "high"
  }
}
```

**Response:** `200 OK` (full incident object)

**cURL:**
```bash
curl -X PATCH http://localhost:8000/api/incidents/1 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"metadata": {"severity": "high"}}'
```

---

### Delete Incident
Delete an incident (admin only).

**DELETE** `/incidents/{incident_id}`

**Headers:**
```
Authorization: Bearer <token>
```

**Response:** `204 No Content`

**cURL:**
```bash
curl -X DELETE http://localhost:8000/api/incidents/1 \
  -H "Authorization: Bearer $TOKEN"
```

---

## Exports

### Export as Markdown
Export incident as Markdown format.

**POST** `/exports/{incident_id}/markdown`

**Headers:**
```
Authorization: Bearer <token>
```

**Response:** `200 OK`
```json
{
  "path": "exports/incident_1/incident_report.md",
  "format": "markdown"
}
```

**cURL:**
```bash
curl -X POST http://localhost:8000/api/exports/1/markdown \
  -H "Authorization: Bearer $TOKEN" \
  -o report.md
```

---

### Export as HTML
Export incident as HTML format.

**POST** `/exports/{incident_id}/html`

**Response:** `200 OK`
```json
{
  "path": "exports/incident_1/incident_report.html",
  "format": "html"
}
```

**cURL:**
```bash
curl -X POST http://localhost:8000/api/exports/1/html \
  -H "Authorization: Bearer $TOKEN" \
  -o report.html
```

---

### Export as PDF
Export incident as PDF (requires reportlab).

**POST** `/exports/{incident_id}/pdf`

**Response:** `200 OK` or `503 Service Unavailable` (if reportlab not installed)

**cURL:**
```bash
curl -X POST http://localhost:8000/api/exports/1/pdf \
  -H "Authorization: Bearer $TOKEN" \
  -o report.pdf
```

---

## Users

### List Users
List all users (admin only).

**GET** `/users`

**Headers:**
```
Authorization: Bearer <token>
```

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `skip` | int | 0 | Offset |
| `limit` | int | 50 | Max results |

**Response:** `200 OK`
```json
[
  {
    "id": 1,
    "username": "admin",
    "email": "admin@example.com",
    "roles": ["admin"],
    "created_at": "2025-01-15T15:00:00"
  }
]
```

---

### Update User Roles
Update user roles (admin only).

**PATCH** `/users/{user_id}/roles`

**Request:**
```json
{
  "roles": ["ir_lead", "viewer"]
}
```

**Response:** `200 OK`

---

### Delete User
Delete a user (admin only).

**DELETE** `/users/{user_id}`

**Response:** `204 No Content`

---

## Audit Logs

### Get Audit Logs
Query audit log (admin only). Useful for DFIR investigations.

**GET** `/audit`

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `skip` | int | Offset (default: 0) |
| `limit` | int | Max results (default: 100, max: 1000) |
| `incident_id` | int | Filter by incident |
| `user_id` | int | Filter by user |
| `action` | string | Filter by action (create, update, delete, view, export) |

**Response:** `200 OK`
```json
[
  {
    "id": 1,
    "user_id": 1,
    "incident_id": 1,
    "action": "create",
    "resource_type": "incident",
    "resource_id": "1",
    "changes": null,
    "timestamp": "2025-01-15T15:00:00",
    "ip_address": "192.168.1.100"
  }
]
```

**cURL:**
```bash
# All audit logs
curl http://localhost:8000/api/audit \
  -H "Authorization: Bearer $TOKEN"

# Filter by incident
curl "http://localhost:8000/api/audit?incident_id=1" \
  -H "Authorization: Bearer $TOKEN"

# Filter by action
curl "http://localhost:8000/api/audit?action=delete" \
  -H "Authorization: Bearer $TOKEN"
```

---

### Get Incident Audit Logs
Get audit logs for a specific incident.

**GET** `/audit/incident/{incident_id}`

**Response:** `200 OK` (list of audit entries)

---

## Error Handling

### Error Response Format
All errors return appropriate HTTP status codes with JSON response:

```json
{
  "error": "Error message",
  "detail": "Detailed error description",
  "request_id": "uuid-for-tracking"
}
```

### Status Codes

| Code | Meaning | When |
|------|---------|------|
| 200 | OK | Request successful |
| 201 | Created | Resource created |
| 204 | No Content | Deletion successful |
| 400 | Bad Request | Invalid input |
| 401 | Unauthorized | Missing/invalid auth token |
| 403 | Forbidden | Insufficient permissions |
| 404 | Not Found | Resource not found |
| 409 | Conflict | Duplicate resource (e.g., username exists) |
| 429 | Too Many Requests | Rate limit exceeded |
| 503 | Service Unavailable | Feature not available (e.g., PDF export) |

### Common Errors

**Missing Token:**
```
401 Unauthorized
{
  "error": "Missing authorization header"
}
```

**Invalid Role:**
```
403 Forbidden
{
  "error": "Requires one of: ir_lead, admin"
}
```

**Resource Not Found:**
```
404 Not Found
{
  "error": "Incident not found"
}
```

**Rate Limited:**
```
429 Too Many Requests
{
  "error": "Rate limit exceeded"
}
```

---

## Interactive Documentation

Visit **http://localhost:8000/api/docs** for interactive Swagger UI where you can:
- Try endpoints directly
- See request/response examples
- View all parameters and schemas
- Get real-time error feedback

---

## Rate Limits

| Endpoint | Limit |
|----------|-------|
| `/auth/login`, `/auth/register`, `/auth/refresh` | 5 per minute |
| `/exports/*` | 10 per minute |
| `/incidents` (POST - create) | 20 per minute |
| All other endpoints | 100 per minute |
| Global | 1000 per minute |

---

## Authentication Examples

### Get Token
```bash
TOKEN=$(curl -X POST http://localhost:8000/api/auth/login \
  -d "username=admin&password=change-me" \
  | jq -r '.access_token')

echo $TOKEN
```

### Use Token in Requests
```bash
# All requests need Authorization header:
curl http://localhost:8000/api/incidents \
  -H "Authorization: Bearer $TOKEN"
```

### Refresh Expired Token
```bash
NEW_TOKEN=$(curl -X POST http://localhost:8000/api/auth/refresh \
  -H "Authorization: Bearer $TOKEN" \
  | jq -r '.access_token')
```

---

## Complete Example Workflow

```bash
# 1. Register user
curl -X POST http://localhost:8000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john",
    "email": "john@example.com",
    "password": "secure123"
  }'

# 2. Login to get token
TOKEN=$(curl -X POST http://localhost:8000/api/auth/login \
  -d "username=john&password=secure123" \
  | jq -r '.access_token')

# 3. Create incident
INCIDENT=$(curl -X POST http://localhost:8000/api/incidents \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "metadata": {
      "name": "Test incident",
      "severity": "high",
      "classification": "malware",
      "reported_by": "John",
      "detection_source": "Endpoint Protection",
      "incident_start": "2025-01-15T14:30:00Z"
    },
    "roles": [{"role": "ir_lead", "person": "John"}]
  }')

INCIDENT_ID=$(echo $INCIDENT | jq -r '.id')

# 4. Get incident
curl http://localhost:8000/api/incidents/$INCIDENT_ID \
  -H "Authorization: Bearer $TOKEN"

# 5. Export as Markdown
curl -X POST http://localhost:8000/api/exports/$INCIDENT_ID/markdown \
  -H "Authorization: Bearer $TOKEN" \
  -o report.md

# 6. Check audit log
curl "http://localhost:8000/api/audit?incident_id=$INCIDENT_ID" \
  -H "Authorization: Bearer $TOKEN"
```

---

## SDK/Client Support

For programmatic access, consider:
- **Python**: `requests` library or `httpx` for async
- **Node.js**: `axios` or `fetch` API
- **Go**: `net/http` or `resty` for high-level
- **cURL**: Command-line tool (examples above)

All use standard HTTP methods (GET, POST, PATCH, DELETE) with JSON payloads.
