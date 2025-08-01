# Container Security Guidelines

## Overview
Container security encompasses protecting containerized applications throughout their lifecycle - from development to deployment and runtime. This guide covers Docker, Kubernetes, and general container security best practices.

## Container Image Security

### Base Image Selection
```dockerfile
# Bad: Using generic, potentially vulnerable base images
FROM ubuntu:latest

# Good: Using minimal, security-focused base images
FROM scratch
# OR
FROM distroless/static-debian11
# OR
FROM alpine:3.18  # Keep versions specific and current
```

**Best Practices:**
- Use official, minimal base images
- Avoid `latest` tags - use specific versions
- Regularly update base images
- Use distroless images when possible
- Scan images for vulnerabilities before deployment

### Dockerfile Security
```dockerfile
# Secure Dockerfile example
FROM node:18-alpine3.18

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

# Set working directory
WORKDIR /app

# Copy package files first (better caching)
COPY package*.json ./

# Install dependencies with exact versions
RUN npm ci --only=production && \
    npm cache clean --force

# Copy application code
COPY --chown=nodejs:nodejs . .

# Remove unnecessary packages and files
RUN apk del build-dependencies && \
    rm -rf /tmp/* /var/cache/apk/*

# Switch to non-root user
USER nodejs

# Expose port (informational)
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

# Start application
CMD ["node", "server.js"]
```

### Image Security Checklist
- ✅ Use non-root users in containers
- ✅ Minimize attack surface (remove unnecessary packages)
- ✅ Set specific user IDs (avoid UID 0)
- ✅ Use multi-stage builds to reduce final image size
- ✅ Don't include secrets in images
- ✅ Use .dockerignore to exclude sensitive files
- ✅ Implement proper health checks

## Container Runtime Security

### Docker Security Configuration
```bash
# Run container with security best practices
docker run -d \
  --name secure-app \
  --user 1001:1001 \                    # Non-root user
  --read-only \                         # Read-only filesystem
  --tmpfs /tmp:rw,noexec,nosuid,size=100m \  # Temporary filesystem
  --tmpfs /var/run:rw,noexec,nosuid,size=100m \
  --cap-drop=ALL \                      # Drop all capabilities
  --cap-add=NET_BIND_SERVICE \          # Add only needed capabilities
  --security-opt=no-new-privileges \    # Prevent privilege escalation
  --security-opt=apparmor:docker-default \  # Use AppArmor profile
  --memory=512m \                       # Memory limit
  --cpus="0.5" \                        # CPU limit
  --pids-limit=100 \                    # Process limit
  --restart=unless-stopped \            # Restart policy
  myapp:v1.2.3
```

### Linux Security Modules
```yaml
# AppArmor profile example
#include <tunables/global>

profile docker-nginx flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>

  # Network access
  network inet tcp,
  network inet udp,

  # File access restrictions  
  /etc/nginx/ r,
  /etc/nginx/** r,
  /var/log/nginx/ w,
  /var/log/nginx/** w,
  /var/cache/nginx/ w,
  /var/cache/nginx/** w,
  
  # Deny dangerous capabilities
  deny capability sys_admin,
  deny capability sys_boot,
  deny capability sys_module,
}
```

## Kubernetes Security

### Pod Security Standards
```yaml
# Pod Security Context
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1001
    runAsGroup: 1001
    fsGroup: 1001
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: app
    image: myapp:v1.2.3
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      runAsNonRoot: true
      runAsUser: 1001
      capabilities:
        drop:
        - ALL
        add:
        - NET_BIND_SERVICE
    resources:
      limits:
        memory: "512Mi"
        cpu: "500m"
      requests:
        memory: "256Mi"
        cpu: "250m"
    volumeMounts:
    - name: tmp-volume
      mountPath: /tmp
    - name: cache-volume
      mountPath: /app/cache
  volumes:
  - name: tmp-volume
    emptyDir: {}
  - name: cache-volume
    emptyDir: {}
```

### Network Policies
```yaml
# Restrict network traffic between pods
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all-ingress
  namespace: production
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
  ingress: []  # Deny all ingress
  egress:
  - to: []
    ports:
    - protocol: TCP
      port: 53    # Allow DNS
    - protocol: UDP
      port: 53
  - to:
    - namespaceSelector:
        matchLabels:
          name: kube-system
    ports:
    - protocol: TCP
      port: 443   # Allow API server access
```

### RBAC (Role-Based Access Control)
```yaml
# Minimal RBAC for application
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: production
  name: app-reader
rules:
- apiGroups: [""]
  resources: ["pods", "configmaps", "secrets"]
  verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: app-reader-binding
  namespace: production
subjects:
- kind: ServiceAccount
  name: app-service-account
  namespace: production
roleRef:
  kind: Role
  name: app-reader
  apiGroup: rbac.authorization.k8s.io
```

## Secret Management

### Secure Secret Handling
```yaml
# Kubernetes Secret
apiVersion: v1
kind: Secret
metadata:
  name: app-secrets
  namespace: production
type: Opaque
data:
  database-password: <base64-encoded-password>
  api-key: <base64-encoded-api-key>
---
# Pod using secrets
apiVersion: v1
kind: Pod
metadata:
  name: app-pod
spec:
  containers:
  - name: app
    image: myapp:v1.2.3
    env:
    - name: DB_PASSWORD
      valueFrom:
        secretKeyRef:
          name: app-secrets
          key: database-password
    volumeMounts:
    - name: secret-volume
      mountPath: "/etc/secrets"
      readOnly: true
  volumes:
  - name: secret-volume
    secret:
      secretName: app-secrets
```

### External Secret Management
```yaml
# External Secrets Operator example
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: vault-backend
  namespace: production
spec:
  provider:
    vault:
      server: "https://vault.company.com"
      version: "v2"
      auth:
        kubernetes:
          mountPath: "kubernetes"
          role: "app-role"
---
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: app-secret
  namespace: production
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-backend
    kind: SecretStore
  target:
    name: app-secrets
    creationPolicy: Owner
  data:
  - secretKey: database-password
    remoteRef:
      key: secret/data/app
      property: db_password
```

## Container Scanning & Vulnerability Management

### Image Scanning Tools
```bash
# Trivy scanning
trivy image --severity HIGH,CRITICAL myapp:v1.2.3

# Clair scanning  
clair-scanner --ip localhost myapp:v1.2.3

# Docker Scout (Docker Desktop)
docker scout cves myapp:v1.2.3

# Anchore scanning
anchore-cli image add myapp:v1.2.3
anchore-cli image wait myapp:v1.2.3
anchore-cli image vuln myapp:v1.2.3 all
```

### CI/CD Pipeline Integration
```yaml
# GitHub Actions security scanning
name: Container Security Scan
on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Build Docker image
      run: docker build -t myapp:${{ github.sha }} .
    
    - name: Run Trivy vulnerability scanner
      uses: aquasecurity/trivy-action@master
      with:
        image-ref: 'myapp:${{ github.sha }}'
        format: 'sarif'
        output: 'trivy-results.sarif'
    
    - name: Upload Trivy scan results
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: 'trivy-results.sarif'
    
    - name: Fail build on high/critical vulnerabilities
      uses: aquasecurity/trivy-action@master
      with:
        image-ref: 'myapp:${{ github.sha }}'
        format: 'table'
        exit-code: '1'
        severity: 'HIGH,CRITICAL'
```

## Runtime Security Monitoring

### Falco Rules for Container Security
```yaml
# Custom Falco rules for container security
- rule: Unexpected Network Connection
  desc: Detect unexpected network connections from containers
  condition: >
    inbound_outbound and
    fd.typechar = 4 and
    fd.ip != "0.0.0.0" and
    not proc.name in (nginx, httpd, node) and
    not fd.sport in (80, 443, 8080, 3000)
  output: >
    Unexpected network connection
    (user=%user.name command=%proc.cmdline connection=%fd.name)
  priority: WARNING

- rule: Container Privilege Escalation
  desc: Detect attempts to escalate privileges in containers
  condition: >
    spawned_process and
    container and
    (proc.name = sudo or
     proc.name = su or
     proc.name contains setuid)
  output: >
    Privilege escalation attempt in container
    (user=%user.name command=%proc.cmdline container=%container.name)
  priority: CRITICAL
```

### Runtime Security Best Practices
- Monitor file system changes
- Track network connections
- Log privilege escalation attempts
- Monitor system call patterns
- Detect malware execution
- Track resource usage anomalies

## Compliance & Governance

### CIS Kubernetes Benchmark
Key security controls from CIS Kubernetes Benchmark:

**Control Plane Security:**
- Enable audit logging
- Restrict API server access
- Use TLS encryption for etcd
- Enable admission controllers
- Regularly rotate certificates

**Worker Node Security:**
- Configure kubelet securely
- Use CNI plugin with network policies
- Enable container runtime security features
- Regular node security updates
- Monitor node access patterns

### Compliance Frameworks
- **SOC 2:** System and Organization Controls
- **PCI DSS:** Payment Card Industry Data Security Standard
- **HIPAA:** Health Insurance Portability and Accountability Act
- **GDPR:** General Data Protection Regulation
- **FedRAMP:** Federal Risk and Authorization Management Program

## Security Automation

### Policy as Code
```yaml
# Open Policy Agent (OPA) Gatekeeper policy
apiVersion: templates.gatekeeper.sh/v1beta1
kind: ConstraintTemplate
metadata:
  name: k8srequiredsecuritycontext
spec:
  crd:
    spec:
      names:
        kind: K8sRequiredSecurityContext
      validation:
        properties:
          runAsNonRoot:
            type: boolean
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8srequiredsecuritycontext
        
        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          not container.securityContext.runAsNonRoot
          msg := "Container must run as non-root user"
        }
```

### Automated Remediation
```bash
#!/bin/bash
# Auto-remediation script for security violations

# Check for containers running as root
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{" "}{.metadata.name}{" "}{.spec.securityContext.runAsUser}{"\n"}{end}' | \
while read namespace pod user; do
  if [ "$user" = "0" ] || [ -z "$user" ]; then
    echo "WARNING: Pod $pod in namespace $namespace running as root"
    # Trigger alert or remediation action
    kubectl annotate pod $pod -n $namespace security.compliance/violation="running-as-root"
  fi
done
```

## CyDefender Container Security Integration

### Container Security Assessment
CyDefender can analyze containerized applications for:
- Image vulnerability scanning
- Runtime security policy violations
- Network traffic anomalies
- Privilege escalation attempts
- Resource abuse detection
- Compliance assessment

### Detection Capabilities
- Malicious container behavior
- Unauthorized network connections
- File system tampering
- Container escape attempts
- Resource exhaustion attacks
- Credential theft indicators

## Security Tools Integration

### Popular Container Security Tools
- **Falco:** Runtime security monitoring
- **Trivy:** Vulnerability scanning
- **OPA Gatekeeper:** Policy enforcement
- **Istio:** Service mesh security
- **Cilium:** Network security and observability
- **Notary:** Image signing and verification

### Monitoring Stack
```yaml
# Prometheus monitoring for container security
groups:
- name: container-security
  rules:
  - alert: HighCPUUsage
    expr: rate(container_cpu_usage_seconds_total[5m]) > 0.8
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High CPU usage detected in container {{ $labels.container }}"
      
  - alert: SuspiciousNetworkActivity
    expr: increase(container_network_receive_bytes_total[5m]) > 100000000
    for: 2m
    labels:
      severity: critical
    annotations:
      summary: "Suspicious network activity in container {{ $labels.container }}"
```

## References
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [NIST Container Security Guide SP 800-190](https://csrc.nist.gov/publications/detail/sp/800-190/final)
- [Docker Security Best Practices](https://docs.docker.com/engine/security/)
- [Kubernetes Security Documentation](https://kubernetes.io/docs/concepts/security/)
- [OWASP Container Security Top 10](https://github.com/OWASP/www-project-container-security)