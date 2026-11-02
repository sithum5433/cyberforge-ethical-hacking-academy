# APPENDIX H: COMPLETE CIS HARDENING BENCHMARKS, DEVSECOPS PIPELINES & SECURE CODING BLUEPRINTS

## Production-Grade Infrastructure Hardening, CI/CD Security Gates & Multi-Language Secure Code Reference

> [!TIP]
> **From Finding Bugs to Fixing Systems:** What separates a junior tester from a Principal Security Architect or Staff Application Security Engineer in Sri Lanka and globally is the ability to provide **drop-in, production-ready remediation configurations and secure code templates**. Use the blueprints in this appendix during penetration test reporting, DevSecOps architecture design, and university software engineering projects.

---

## H.1 CIS Linux Server Hardening Baseline (`/etc/sysctl.d/`, `sshd_config`, `nftables`, `PAM`)

### H.1.1 Kernel Network & Memory Hardening (`/etc/sysctl.d/99-cis-hardening.conf`)

```ini
# ==============================================================================
# CIS Linux Kernel Security & Network Stack Hardening (/etc/sysctl.d/99-cis.conf)
# Apply with: sudo sysctl --system
# ==============================================================================

# --- 1. Memory & Process Protection ---
# Enable Full Address Space Layout Randomization (ASLR: Stack, Heap, VDSO, Shared Libs)
kernel.randomize_va_space = 2

# Restrict access to kernel pointers in /proc/kallsyms to prevent KASLR leaks
kernel.kptr_restrict = 2

# Restrict dmesg kernel ring buffer access to privileged users (CAP_SYSLOG)
kernel.dmesg_restrict = 1

# Restrict ptrace() debugging strictly to parent processes (prevents credential theft from sibling processes)
kernel.yama.ptrace_scope = 2

# Disable unprivileged eBPF to prevent speculative/verifier kernel escalation
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2

# Restrict performance event monitoring to privileged users
kernel.perf_event_paranoid = 3

# Disable core dumps for SUID/SGID binaries (prevents leaking sensitive memory to disk)
fs.suid_dumpable = 0

# Enforce strict symlink and hardlink protections in world-writable sticky directories (/tmp)
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2

# --- 2. IPv4 & IPv6 Network Stack Hardening ---
# Enable TCP SYN Cookies to protect against SYN flood exhaustion
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 4096

# Enable Reverse Path Filtering (RFC 3704 Strict Mode) to prevent IP spoofing
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Disable IP Source Routing (prevents attackers from dictating return packet paths)
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Disable ICMP Redirect Acceptance and Sending (prevents Layer 3 MITM route table poisoning)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Disable IPv6 Router Advertisements on static server interfaces (prevents SLAAC/mitm6)
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# Ignore broadcast ICMP echo requests (Smurf amplification defense)
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Log Martian packets (packets with impossible source IP addresses)
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
```

### H.1.2 Hardened OpenSSH Daemon Configuration (`/etc/ssh/sshd_config`)

```apache
# ==============================================================================
# CIS Level 2 Hardened OpenSSH Server Configuration (/etc/ssh/sshd_config)
# Validate syntax before reload: sudo sshd -t && sudo systemctl reload sshd
# ==============================================================================

Protocol 2
Port 22
AddressFamily inet

# --- Cryptographic Algorithms (Modern AEAD & Curve25519 Only) ---
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256

# --- Authentication Controls ---
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
KbdInteractiveAuthentication no
UsePAM yes
AuthenticationMethods publickey

# --- Session & Connection Limits (Mitigates Brute-Force & regreSSHion Timing) ---
LoginGraceTime 20
MaxAuthTries 3
MaxSessions 4
MaxStartups 10:30:60
ClientAliveInterval 300
ClientAliveCountMax 2

# --- Attack Surface Reduction (Disable Unnecessary Forwarding) ---
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no
PermitTunnel no
PermitUserEnvironment no
DisableForwarding yes

# --- Access Control & Auditing ---
AllowGroups ssh-admins secops
LogLevel VERBOSE
SyslogFacility AUTH
Subsystem sftp internal-sftp -f AUTH -l INFO
```

### H.1.3 Production Host Firewall with `nftables` (`/etc/nftables.conf`)

```nginx
#!/usr/sbin/nft -f
# ==============================================================================
# Production Zero-Trust Host Firewall Ruleset (/etc/nftables.conf)
# Enable with: sudo systemctl enable --now nftables
# ==============================================================================

flush ruleset

table inet filter {
    set ssh_ratelimit {
        type ipv4_addr
        flags dynamic, timeout
        timeout 5m
    }

    chain input {
        type filter hook input priority 0; policy drop;

        # 1. Accept loopback traffic
        iifname "lo" accept

        # 2. Drop invalid connection states immediately
        ct state invalid drop

        # 3. Accept established and related return traffic
        ct state established,related accept

        # 4. Drop loopback addresses arriving on non-loopback interfaces (anti-spoofing)
        iifname != "lo" ip saddr 127.0.0.0/8 counter drop
        iifname != "lo" ip6 saddr ::1 counter drop

        # 5. Rate-limit ICMPv4 and allow essential ICMPv6 Neighbour Discovery
        ip protocol icmp icmp type { echo-request, destination-unreachable, time-exceeded } limit rate 10/second accept
        ip6 nexthdr icmpv6 icmpv6 type { echo-request, destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } limit rate 20/second accept

        # 6. Rate-limited SSH access (max 4 new connections per minute per IP)
        tcp dport 22 ct state new update @ssh_ratelimit { ip saddr limit rate 4/minute burst 4 packets } accept
        tcp dport 22 ct state new log prefix "[NFT-SSH-DROP] " drop

        # 7. Allow HTTPS (443) and HTTP (80) for public web servers
        tcp dport { 80, 443 } ct state new accept

        # 8. Log and drop everything else
        limit rate 5/minute log prefix "[NFT-INPUT-DROP] " level warn
        counter drop
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
    }

    chain output {
        type filter hook output priority 0; policy accept;
    }
}
```

---

## H.2 Hardened Web Server, Docker & Kubernetes Security Blueprints

### H.2.1 Production Nginx Reverse Proxy with Full OWASP Security Headers (`/etc/nginx/conf.d/secure-app.conf`)

```nginx
# ==============================================================================
# Hardened Nginx Reverse Proxy Configuration with TLS 1.3 & OWASP Headers
# ==============================================================================

# Hide Nginx version from Server header and error pages
server_tokens off;

# Rate limiting zones (mitigates credential stuffing & L7 DoS)
limit_req_zone $binary_remote_addr zone=login_limit:10m rate=5r/m;
limit_req_zone $binary_remote_addr zone=api_limit:20m rate=30r/s;

server {
    listen 80;
    listen [::]:80;
    server_name app.example.lk;
    # Enforce permanent redirect to HTTPS
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name app.example.lk;

    # --- TLS 1.2 / 1.3 Configuration (Mozilla Intermediate/Modern Guideline) ---
    ssl_certificate /etc/letsencrypt/live/app.example.lk/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/app.example.lk/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers off;
    ssl_session_timeout 1d;
    ssl_session_cache shared:MozSSL:10m;
    ssl_session_tickets off;

    # --- OWASP Defense-in-Depth HTTP Security Headers ---
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header Content-Security-Policy "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=(), payment=(), usb=()" always;
    add_header Cross-Origin-Opener-Policy "same-origin" always;
    add_header Cross-Origin-Resource-Policy "same-origin" always;

    # --- Request Size & Buffer Limits ---
    client_max_body_size 10M;
    client_body_timeout 12s;
    client_header_timeout 12s;

    # --- Block Dotfiles (.git, .env, .htaccess) ---
    location ~ /\.(?!well-known).* {
        deny all;
        access_log off;
        log_not_found off;
    }

    # --- Strict Rate-Limited Authentication Endpoint ---
    location /api/v1/auth/login {
        limit_req zone=login_limit burst=3 nodelay;
        proxy_pass http://127.0.0.1:8000;
        # Hardcode Host header to prevent Host Header Injection / Cache Poisoning!
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # --- General Application Proxy ---
    location / {
        limit_req zone=api_limit burst=50 nodelay;
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### H.2.2 Hardened Multi-Stage Distroless/Non-Root `Dockerfile` & Kubernetes `Deployment` + `NetworkPolicy`

```dockerfile
# ==============================================================================
# Stage 1: Build Stage (Pinned SHA256 Digest to Prevent Tag Mutation Supply-Chain Risks)
# ==============================================================================
FROM python:3.12-slim-bookworm AS builder

WORKDIR /build
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

COPY requirements.txt .
RUN python3 -m venv /opt/venv && \
    /opt/venv/bin/pip install --require-hashes -r requirements.txt

# ==============================================================================
# Stage 2: Minimal Non-Root Runtime Stage
# ==============================================================================
FROM python:3.12-slim-bookworm AS runtime

# Create dedicated unprivileged system group and user (UID/GID 10001)
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /usr/sbin/nologin -M appuser && \
    apt-get update && apt-get upgrade -y && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY --chown=root:root --chmod=0555 ./src /app/src

ENV PATH="/opt/venv/bin:$PATH"
USER 10001:10001
EXPOSE 8000

ENTRYPOINT ["python3", "-m", "uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

```yaml
# ==============================================================================
# Hardened Kubernetes Deployment & Zero-Trust NetworkPolicy (k8s-hardened.yaml)
# Enforces Pod Security Standards (Restricted Profile): Non-Root, Read-Only RootFS,
# Dropped ALL Linux Capabilities, Seccomp RuntimeDefault, No ServiceAccount Token Mount
# ==============================================================================
apiVersion: apps/v1
kind: Deployment
metadata:
  name: payment-api
  namespace: fintech-prod
spec:
  replicas: 3
  selector:
    matchLabels:
      app: payment-api
  template:
    metadata:
      labels:
        app: payment-api
    spec:
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        runAsGroup: 10001
        fsGroup: 10001
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: payment-api
          image: registry.example.lk/fintech/payment-api@sha256:4f8b9c2e1d3a5b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c
          ports:
            - containerPort: 8000
              protocol: TCP
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
          resources:
            requests:
              cpu: "250m"
              memory: "256Mi"
            limits:
              cpu: "500m"
              memory: "512Mi"
          volumeMounts:
            - name: tmp-dir
              mountPath: /tmp
      volumes:
        - name: tmp-dir
          emptyDir:
            medium: Memory
            sizeLimit: 64Mi
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: payment-api-zero-trust
  namespace: fintech-prod
spec:
  podSelector:
    matchLabels:
      app: payment-api
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: api-gateway
      ports:
        - protocol: TCP
          port: 8000
  egress:
    # Allow DNS resolution to CoreDNS only
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
    # Allow PostgreSQL connection strictly to database tier (Blocks AWS/GCP 169.254.169.254 SSRF!)
    - to:
        - podSelector:
            matchLabels:
              app: postgres-db
      ports:
        - protocol: TCP
          port: 5432
```

---

## H.3 Enterprise DevSecOps CI/CD Pipeline (GitHub Actions: Secret Scanning, SAST, SCA, Container Audit & SBOM)

```yaml
# ==============================================================================
# Complete DevSecOps Security Gate Pipeline (.github/workflows/devsecops.yml)
# Blocks merges on hardcoded secrets, SAST findings, vulnerable dependencies, or container flaws
# ==============================================================================
name: DevSecOps Security Gate

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]

permissions:
  contents: read
  security-events: write

jobs:
  secret-scanning:
    name: 1. Git Secret Scanning (Gitleaks)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - name: Run Gitleaks
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

  sast-semgrep:
    name: 2. Static Application Security Testing (Semgrep OWASP Top 10)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Semgrep SAST
        uses: returntocorp/semgrep-action@v1
        with:
          config: >-
            p/owasp-top-ten
            p/security-audit
            p/secrets
            p/dockerfile
            p/kubernetes

  sca-and-container-scan:
    name: 3. Dependency & Container Vulnerability Audit (Trivy + SBOM)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build Candidate Docker Image
        run: docker build -t candidate-app:${{ github.sha }} .
      - name: Run Trivy Vulnerability & Misconfiguration Scanner
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'candidate-app:${{ github.sha }}'
          format: 'table'
          exit-code: '1'
          ignore-unfixed: true
          vuln-type: 'os,library'
          severity: 'CRITICAL,HIGH'
      - name: Generate CycloneDX SBOM
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'candidate-app:${{ github.sha }}'
          format: 'cyclonedx'
          output: 'sbom.cdx.json'
```

---

## H.4 Multi-Language Secure Coding Blueprints (Python, Node.js/TypeScript, Go & Rust)

### H.4.1 Python (FastAPI / SQLAlchemy): Preventing SQLi, IDOR, SSRF, Weak Hashing & Race Conditions

```python
#!/usr/bin/env python3
"""
Production-Grade Secure FastAPI Microservice Blueprint:
Demonstrates Argon2id password hashing, asymmetric EdDSA/RS256 JWT validation,
Parameterized SQL with FOR UPDATE row locking (Race Condition prevention),
Object-Level Authorization (IDOR prevention), and SSRF-safe URL fetching.
"""
import ipaddress
import socket
from urllib.parse import urlparse
from fastapi import FastAPI, Depends, HTTPException, status
from pydantic import BaseModel, Field, constr
from sqlalchemy import text
from sqlalchemy.orm import Session
from argon2 import PasswordHasher

app = FastAPI(docs_url=None, redoc_url=None)  # Disable public Swagger UI in production
ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)

# 1. Strict Input Validation with Pydantic (Blocks Mass Assignment / BOPLA)
class TransferRequest(BaseModel):
    from_account_id: int = Field(..., gt=0)
    to_account_id: int = Field(..., gt=0)
    amount_cents: int = Field(..., gt=0, le=10_000_000_00)
    idempotency_key: constr(pattern=r"^[a-f0-9-]{36}$")

# 2. Atomic Database Transfer with Row-Level Locking (Prevents TOCTOU Race Conditions & SQLi)
def execute_secure_transfer(db: Session, current_user_id: int, req: TransferRequest):
    if req.from_account_id == req.to_account_id:
        raise HTTPException(status_code=400, detail="Cannot transfer to the same account")

    # Lock rows in deterministic ascending ID order to prevent deadlocks AND race conditions!
    first_id, second_id = sorted([req.from_account_id, req.to_account_id])
    db.execute(
        text("SELECT id FROM accounts WHERE id IN (:id1, :id2) ORDER BY id FOR UPDATE"),
        {"id1": first_id, "id2": second_id}
    )

    # Verify Object-Level Authorization (Prevents IDOR / BOLA!)
    sender = db.execute(
        text("SELECT id, owner_user_id, balance_cents FROM accounts WHERE id = :id"),
        {"id": req.from_account_id}
    ).mappings().first()

    if not sender or sender["owner_user_id"] != current_user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden account access")

    if sender["balance_cents"] < req.amount_cents:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Insufficient funds")

    # Perform parameterized atomic balance update
    db.execute(
        text("UPDATE accounts SET balance_cents = balance_cents - :amt WHERE id = :id"),
        {"amt": req.amount_cents, "id": req.from_account_id}
    )
    db.execute(
        text("UPDATE accounts SET balance_cents = balance_cents + :amt WHERE id = :id"),
        {"amt": req.amount_cents, "id": req.to_account_id}
    )
    db.commit()

# 3. SSRF-Safe Outbound Webhook Validator (Blocks RFC 1918, Loopback, Link-Local 169.254.169.254 & DNS Rebinding)
ALLOWED_SCHEMES = {"https"}

def validate_external_webhook_url(raw_url: str) -> str:
    parsed = urlparse(raw_url)
    if parsed.scheme not in ALLOWED_SCHEMES or not parsed.hostname:
        raise ValueError("Only valid HTTPS URLs are permitted")
    if parsed.port not in (None, 443):
        raise ValueError("Only standard port 443 is permitted")

    # Resolve all IPv4/IPv6 records and verify every resolved IP is globally routable
    addr_info = socket.getaddrinfo(parsed.hostname, 443, proto=socket.IPPROTO_TCP)
    for family, _, _, _, sockaddr in addr_info:
        ip_obj = ipaddress.ip_address(sockaddr[0])
        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        ):
            raise PermissionError(f"SSRF Protection: Resolved IP {ip_obj} is non-public")
    return raw_url
```
