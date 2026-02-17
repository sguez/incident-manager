# Deployment Guide

Complete deployment instructions for Incident Manager on Docker, Kubernetes, and local development.

## Table of Contents
1. [Docker Standalone](#docker-standalone)
2. [Docker Compose](#docker-compose)
3. [Kubernetes](#kubernetes)
4. [Helm](#helm)
5. [Environment Variables](#environment-variables)
6. [Production Checklist](#production-checklist)
7. [Troubleshooting](#troubleshooting)

---

## Docker Standalone

### Build Image
```bash
docker build -t incident-manager:latest .
```

### Run Container
```bash
docker run -d \
  --name incident-manager \
  -p 8000:8000 \
  -e SECRET_KEY="your-random-secret-key" \
  -e DATABASE_URL="sqlite+aiosqlite:///./incidents.db" \
  -v incidents_db:/app/incidents.db \
  -v incidents_exports:/app/exports \
  -v incidents_logs:/app/logs \
  --healthcheck=interval=30s \
    --health-start-period=10s \
    --health-timeout=5s \
    --health-retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1 \
  incident-manager:latest
```

### View Logs
```bash
docker logs -f incident-manager
```

### Stop Container
```bash
docker stop incident-manager
docker rm incident-manager
```

---

## Docker Compose

### Quick Start
```bash
docker-compose up -d
```

This starts:
- **incident-manager** API on port 8000
- Persistent SQLite database in `./incidents.db`
- Exports directory in `./exports/`

### Access
- **API**: http://localhost:8000
- **Swagger Docs**: http://localhost:8000/api/docs
- **Health Check**: http://localhost:8000/health

### View Logs
```bash
docker-compose logs -f incident-manager
```

### Stop
```bash
docker-compose down

# Keep data
docker-compose down --volumes
```

### Customize
Edit `docker-compose.yml`:

```yaml
environment:
  - SECRET_KEY=your-random-key
  - DEBUG=false  # Set to true for development
  - CORS_ORIGINS=http://localhost:3000,http://yourdomain.com
```

---

## Kubernetes

### Prerequisites
- Kubernetes cluster (1.26+)
- kubectl configured
- Optional: Helm 3.x

### Quick Deploy
```bash
# Create namespace and deploy all resources
kubectl apply -f k8s/deployment.yaml

# Wait for pod to be ready
kubectl wait --for=condition=ready pod \
  -l app=incident-manager \
  -n incident-manager \
  --timeout=300s

# Check status
kubectl get pods -n incident-manager
```

### Access
```bash
# Port forward
kubectl port-forward -n incident-manager svc/incident-manager 8000:80

# Test
curl http://localhost:8000/health
```

### View Logs
```bash
kubectl logs -f -n incident-manager deployment/incident-manager
```

### Delete
```bash
kubectl delete -f k8s/deployment.yaml
```

### Features Included
- **Namespace** - `incident-manager` for isolation
- **Deployment** - 1 replica with rolling updates
- **Service** - ClusterIP (internal access)
- **PersistentVolumeClaims** - For database and exports
- **ConfigMap** - For application settings
- **Secret** - For sensitive data (change SECRET_KEY!)
- **ServiceAccount** - For RBAC
- **NetworkPolicy** - Ingress/Egress restrictions
- **SecurityContext** - Non-root, read-only filesystem
- **Health Probes** - Liveness, readiness, startup

### Production Configuration

#### Expose via Ingress
```bash
cat <<'EOF' | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: incident-manager
  namespace: incident-manager
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - incident-manager.example.com
    secretName: incident-manager-tls
  rules:
  - host: incident-manager.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: incident-manager
            port:
              number: 80
EOF
```

#### Scale Replicas (with PostgreSQL)
```bash
# First migrate to PostgreSQL for multi-instance support
# Then scale:
kubectl scale deployment incident-manager \
  -n incident-manager \
  --replicas=3
```

#### Update Environment
```bash
kubectl set env deployment/incident-manager \
  -n incident-manager \
  SECRET_KEY=your-new-secret-key \
  DEBUG=false
```

#### Update Image
```bash
kubectl set image deployment/incident-manager \
  -n incident-manager \
  incident-manager=incident-manager:v2.0.1 \
  --record
```

---

## Helm

### Install from Chart
```bash
helm install incident-manager k8s/helm/ \
  -n incident-manager \
  --create-namespace
```

### Customize via Values
Create `values-prod.yaml`:
```yaml
replicaCount: 1

image:
  repository: incident-manager
  tag: latest
  pullPolicy: IfNotPresent

persistence:
  enabled: true
  storageClass: fast-ssd
  db:
    size: 20Gi

ingress:
  enabled: true
  className: nginx
  hosts:
    - host: incident-manager.example.com
      paths:
        - path: /
          pathType: Prefix

resources:
  requests:
    cpu: 250m
    memory: 512Mi
  limits:
    cpu: 1000m
    memory: 1Gi

app:
  debug: false
  corsOrigins: "https://incident-manager.example.com"
  allowedHosts: "incident-manager.example.com"
```

### Install with Custom Values
```bash
helm install incident-manager k8s/helm/ \
  -n incident-manager \
  --create-namespace \
  -f values-prod.yaml
```

### Upgrade
```bash
helm upgrade incident-manager k8s/helm/ \
  -n incident-manager \
  -f values-prod.yaml
```

### Uninstall
```bash
helm uninstall incident-manager -n incident-manager
```

### View Release History
```bash
helm history incident-manager -n incident-manager
helm rollback incident-manager 1 -n incident-manager
```

---

## Environment Variables

### Core Settings
| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | `dev-secret-key-...` | **MUST change in production** - JWT signing key |
| `DATABASE_URL` | `sqlite+aiosqlite:///./incidents.db` | Database connection string |
| `DEBUG` | `false` | Enable debug mode (verbose logging, reload on changes) |
| `PORT` | `8000` | Server listen port |

### Security
| Variable | Default | Description |
|----------|---------|-------------|
| `CORS_ORIGINS` | `http://localhost:*` | Allowed CORS origins (comma-separated) |
| `ALLOWED_HOSTS` | `localhost,127.0.0.1` | Allowed Host headers (prevent header spoofing) |
| `ACCESS_TOKEN_EXPIRE_HOURS` | `24` | JWT token expiration time |

### Application
| Variable | Default | Description |
| `SQLALCHEMY_ECHO` | `false` | Log SQL statements (debug only) |

### Examples

#### Development
```bash
export DEBUG=true
export CORS_ORIGINS="*"
export DATABASE_URL="sqlite+aiosqlite:///./incidents.db"
export SECRET_KEY="dev-key-not-secure"
```

#### Production (Docker)
```bash
docker run -d \
  -e SECRET_KEY="$(openssl rand -hex 32)" \
  -e DEBUG=false \
  -e CORS_ORIGINS="https://incident-manager.example.com" \
  -e ALLOWED_HOSTS="incident-manager.example.com" \
  incident-manager:latest
```

#### Production (Kubernetes)
```bash
kubectl set env deployment/incident-manager \
  -n incident-manager \
  SECRET_KEY="$(openssl rand -hex 32)" \
  DEBUG=false \
  CORS_ORIGINS="https://incident-manager.example.com" \
  ALLOWED_HOSTS="incident-manager.example.com"
```

---

## Production Checklist

### Before Going Live
- [ ] **Secret Key**: Generate random SECRET_KEY and store securely
  ```bash
  openssl rand -hex 32  # Generate 64-char hex string
  ```
- [ ] **HTTPS/TLS**: Enable SSL certificates (use cert-manager in k8s)
- [ ] **CORS Origins**: Set `CORS_ORIGINS` to your domain only
- [ ] **Database**: 
  - [ ] Regular backups configured
  - [ ] Backup tested and verified
  - [ ] Consider PostgreSQL for multi-instance setups
- [ ] **Initial User**: Create admin account, change default password
- [ ] **Firewall**: Restrict network access to authorized users only
- [ ] **Monitoring**: Set up logging and alerts
- [ ] **Audit Log**: Review audit logs periodically
- [ ] **Dependencies**: Run `pip install --upgrade -r requirements.txt`
- [ ] **K8s Only**:
  - [ ] Resource limits set appropriately
  - [ ] Network policies enabled
  - [ ] Pod security standards enforced
  - [ ] RBAC configured
  - [ ] Ingress certificate configured
- [ ] **Docker Only**:
  - [ ] Volume mounts point to persistent storage
  - [ ] Health check configured
  - [ ] Restart policy set to `unless-stopped`

### Regular Maintenance
- [ ] Review audit logs weekly
- [ ] Backup database daily
- [ ] Monitor resource usage
- [ ] Apply security patches monthly
- [ ] Update dependencies quarterly

### Security Hardening
```bash
# In Kubernetes, ensure this is set in pod spec:
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  readOnlyRootFilesystem: true
  capabilities:
    drop:
      - ALL

# Enable network policies (default: allow same namespace only)
# See k8s/deployment.yaml for example
```

---

## Troubleshooting

### Container Won't Start
```bash
# Check logs
docker-compose logs incident-manager

# Check environment
docker-compose config | grep -A 20 environment:

# Verify database permissions
docker exec incident-manager ls -la /app/
```

### Pod CrashLoopBackOff
```bash
# Check logs
kubectl logs -n incident-manager deployment/incident-manager

# Check events
kubectl describe pod -n incident-manager -l app=incident-manager

# Check resource limits
kubectl describe node

# Test image locally
docker run --rm incident-manager:latest /bin/sh
```

### Database Lock (SQLite)
```bash
# SQLite has file locking - ensure only one pod runs (replicas=1)
# Or migrate to PostgreSQL for multi-instance support

# Check if file exists
docker exec incident-manager ls -la /app/incidents.db

# Check permissions
docker exec incident-manager stat /app/incidents.db
```

### Health Check Failing
```bash
# Test endpoint directly
curl http://localhost:8000/health

# With auth (if implemented)
TOKEN=$(curl -X POST http://localhost:8000/api/auth/login \
  -d "username=admin&password=change-me" | jq -r '.access_token')

# Check API
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/incidents
```

### CORS Errors
```bash
# Verify CORS settings
docker-compose exec incident-manager env | grep CORS

# Update if needed
docker-compose exec incident-manager \
  env CORS_ORIGINS="http://your-domain.com" sleep infinity
```

### Out of Disk Space
```bash
# Check disk usage
docker system df
docker volume ls

# Clean up old containers/images
docker system prune -a --volumes

# For persistent volume (k8s)
kubectl exec -n incident-manager deployment/incident-manager -- df -h /app
```

### Slow Performance
```bash
# Check if database is being queried frequently
docker-compose logs incident-manager | grep SELECT

# Enable query logging
SQLALCHEMY_ECHO=true docker-compose up

# Consider adding indexes (database.py)
```

---

## Getting Help

- **Logs**: Always check logs first
  - Docker: `docker-compose logs -f`
  - K8s: `kubectl logs -f deployment/incident-manager -n incident-manager`
- **Health**: `curl http://localhost:8000/health`
- **API Docs**: http://localhost:8000/api/docs
- **Issues**: Open a GitHub issue with logs and reproduction steps

---

## Next Steps

After deployment:
1. Access the API: http://localhost:8000/api/docs
2. Create first user via `/api/auth/register`
3. Create first incident via `/api/incidents`
4. Export incident report
5. Review audit logs at `/api/audit`

See [API.md](API.md) for endpoint reference.
See [SECURITY.md](SECURITY.md) for security best practices.
