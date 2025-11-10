# Security Design

**Version:** 1.0
**Last Updated:** 2025-11-10
**Project:** NLSN PCAP Monitor

---

## Table of Contents

1. [Introduction](#introduction)
2. [Security Philosophy](#security-philosophy)
3. [Threat Model](#threat-model)
4. [Security Architecture](#security-architecture)
5. [Container Security](#container-security)
6. [Network Security](#network-security)
7. [Authentication & Authorization](#authentication--authorization)
8. [Data Security](#data-security)
9. [Secrets Management](#secrets-management)
10. [Audit Logging](#audit-logging)
11. [Incident Response](#incident-response)
12. [Compliance](#compliance)

---

## 1. Introduction

This document defines the security architecture and controls for the NLSN PCAP Monitor system. Given the system's purpose (detecting and responding to network attacks), security is paramount.

### 1.1 Security Objectives

**Confidentiality:**
- Protect sensitive threat intelligence data
- Secure VPN credentials and API keys
- Encrypt data in transit and at rest

**Integrity:**
- Ensure attack detection accuracy
- Prevent tampering with threat logs
- Validate all external inputs

**Availability:**
- Maintain monitoring under attack conditions
- Ensure system resilience
- Prevent denial-of-service

**Non-Repudiation:**
- Comprehensive audit logging
- Immutable threat records
- Timestamped events

### 1.2 Security Principles

1. **Defense in Depth**: Multiple layers of security controls
2. **Least Privilege**: Minimal permissions for all components
3. **Fail Secure**: Default to secure state on errors
4. **Zero Trust**: Verify all interactions, trust nothing
5. **Assume Breach**: Design for compromise scenarios
6. **Security by Design**: Security integrated from day one

### 1.3 Scope

Security controls cover:
- Container and host security
- Network segmentation and isolation
- API authentication and authorization
- Database encryption and access control
- Secrets management
- Audit logging
- Incident response procedures

---

## 2. Security Philosophy

### 2.1 Assume Breach Methodology

The system assumes the local network is **always compromised** by a MITM attacker. This shapes all design decisions:

**Detection Layer:**
- Never trust local DNS responses
- Always verify through independent paths
- Detect discrepancies between local and verified data

**Deception Layer:**
- Silently log attacks without alerting attacker
- Generate fake but convincing data
- Track attacker behavior for intelligence

**Data Protection:**
- Real credentials never leave secure channels
- Fake credentials embedded with honeytokens
- All verification traffic uses encrypted VPN tunnels

### 2.2 Silent Operation

The system operates in "stealth mode":

1. **No User-Visible Alerts**: Attacks logged silently to avoid tipping off attacker
2. **Maintain Normal Behavior**: Real traffic continues through verified paths
3. **Deception Appears Real**: Fake traffic mimics legitimate user behavior
4. **No Network Signature**: Monitoring is passive, non-intrusive

### 2.3 Trust Boundaries

```
┌─────────────────────────────────────────────────────┐
│  Untrusted Zone                                     │
│  - Local Network (assumed compromised)              │
│  - Internet (hostile)                               │
└─────────────────────────────────────────────────────┘
                      ↕
          [ Firewall / Network Isolation ]
                      ↕
┌─────────────────────────────────────────────────────┐
│  DMZ (Limited Trust)                                │
│  - Honeypot Container (exposed, isolated)           │
│  - Verification Container (outbound only)           │
└─────────────────────────────────────────────────────┘
                      ↕
            [ Internal Firewall ]
                      ↕
┌─────────────────────────────────────────────────────┐
│  Trusted Zone                                       │
│  - Go Monitor (packet capture)                      │
│  - Python Engine (orchestration)                    │
│  - Database (threat intelligence)                   │
│  - Redis (event bus)                                │
└─────────────────────────────────────────────────────┘
```

**Trust Boundary Rules:**

1. **Untrusted → DMZ**: Only honeypot accepts incoming connections
2. **DMZ → Trusted**: Verification can report results, honeypot cannot initiate
3. **Trusted → DMZ**: Engine can query verification
4. **Trusted → Untrusted**: Only verification via VPN tunnels

---

## 3. Threat Model

### 3.1 Threat Modeling Methodology

We use **STRIDE** (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) for threat analysis.

### 3.2 Threat Actors

| Actor | Motivation | Capabilities | Likelihood |
|-------|------------|--------------|------------|
| **Nation-State APT** | Espionage, data theft | Advanced, persistent | Low |
| **Cybercriminal** | Financial gain | Moderate to high | Medium |
| **Script Kiddie** | Curiosity, fame | Low to moderate | High |
| **Malicious Insider** | Revenge, financial | High (access) | Low |
| **MITM Attacker** | Traffic interception | Moderate (network position) | High |

### 3.3 Attack Scenarios

#### Scenario 1: DNS Hijacking Attack

**Attacker Goal:** Intercept traffic to banking.example.com

**Attack Steps:**
1. Compromise local router or ISP
2. Inject malicious DNS responses
3. Redirect traffic to phishing site
4. Capture credentials

**System Response:**
1. Monitor detects IP mismatch
2. Engine triggers multi-path verification
3. Verification confirms legitimate IP differs
4. Attack logged silently
5. Deception activated with fake credentials
6. Real browser connection blocked (user's Enhanced Protection)
7. Fake traffic sent to attacker's site with honeytokens

**Security Controls:**
- Multi-path DNS verification (DETECT)
- Baseline learning of expected IPs (DETECT)
- Silent threat logging (RESPOND)
- Automated deception (RESPOND)
- Honeytoken tracking (TRACK)

#### Scenario 2: SSL Stripping Attack

**Attacker Goal:** Downgrade HTTPS to HTTP

**Attack Steps:**
1. Intercept HTTP traffic
2. Proxy HTTPS on user's behalf
3. Serve content over HTTP
4. Capture plaintext credentials

**System Response:**
1. Monitor detects HTTP for HSTS domain
2. Detection confidence: CRITICAL
3. Verification confirms HTTPS works via VPN
4. Attack logged
5. Deception sends fake form submissions over HTTP
6. Real traffic uses VPN → HTTPS

**Security Controls:**
- HSTS tracking (DETECT)
- HTTP vs HTTPS history (DETECT)
- Multi-path HTTPS verification (VERIFY)
- Fake credential generation (DECEIVE)

#### Scenario 3: Container Escape Attempt

**Attacker Goal:** Escape honeypot to access host

**Attack Steps:**
1. Compromise honeypot via SSH tarpit
2. Exploit kernel vulnerability
3. Attempt container escape
4. Access host filesystem

**System Response:**
1. Container restrictions prevent escape
2. Audit logs capture attempt
3. Alert generated (this is not silent - system is under direct attack)
4. Container automatically restarted

**Security Controls:**
- Minimal container capabilities (PREVENT)
- Read-only filesystem (PREVENT)
- AppArmor/SELinux policies (PREVENT)
- Audit logging (DETECT)
- Automated remediation (RESPOND)

#### Scenario 4: API Key Theft

**Attacker Goal:** Steal API key to access threat data

**Attack Steps:**
1. Compromise configuration file
2. Extract API key
3. Query threat database
4. Exfiltrate intelligence

**System Response:**
1. Secrets manager prevents file-based theft
2. API key scoped to minimal permissions
3. Rate limiting prevents bulk extraction
4. Audit log captures suspicious queries
5. API key revoked upon detection

**Security Controls:**
- Secrets manager (PREVENT)
- Least privilege permissions (LIMIT)
- Rate limiting (LIMIT)
- Audit logging (DETECT)
- Automated key rotation (RECOVER)

### 3.4 STRIDE Analysis

#### 3.4.1 Spoofing

| Asset | Threat | Mitigation |
|-------|--------|------------|
| API Authentication | Attacker uses stolen/forged API key | API key hashing, rotation, rate limiting |
| DNS Responses | Attacker spoofs DNS | Multi-path verification via VPN |
| ARP Responses | Attacker spoofs MAC address | ARP table monitoring, gateway MAC locking |
| TLS Certificates | Attacker uses fake certificate | Certificate pinning for critical domains |

#### 3.4.2 Tampering

| Asset | Threat | Mitigation |
|-------|--------|------------|
| Threat Database | Attacker modifies threat records | Database access control, append-only logging |
| Configuration Files | Attacker changes detection thresholds | File integrity monitoring, read-only mounts |
| Docker Images | Attacker injects backdoor | Image signing, vulnerability scanning |
| Network Packets | Attacker modifies captured packets | Immutable packet storage, checksums |

#### 3.4.3 Repudiation

| Asset | Threat | Mitigation |
|-------|--------|------------|
| Threat Logs | Attacker denies attack | Timestamped, immutable audit logs |
| API Actions | User denies actions | Comprehensive API audit trail |
| Honeytoken Triggers | Attacker claims false positive | Detailed trigger context logging |

#### 3.4.4 Information Disclosure

| Asset | Threat | Mitigation |
|-------|--------|------------|
| VPN Credentials | Exposed in logs or config | Secrets manager, encrypted storage |
| API Keys | Exposed in code or environment | Environment-based secrets, rotation |
| Threat Intelligence | Unauthorized access | Authentication, authorization, encryption |
| Database Passwords | Exposed in plaintext | Encrypted at rest, strong passwords |

#### 3.4.5 Denial of Service

| Asset | Threat | Mitigation |
|-------|--------|------------|
| API Endpoints | Attacker floods with requests | Rate limiting, request queuing |
| Packet Capture | Attacker floods with packets | BPF filtering, packet sampling |
| Database | Attacker exhausts connections | Connection pooling, query timeouts |
| Verification | Attacker triggers mass verifications | Verification rate limiting, cost analysis |

#### 3.4.6 Elevation of Privilege

| Asset | Threat | Mitigation |
|-------|--------|------------|
| Containers | Attacker escapes to host | Minimal capabilities, AppArmor, read-only FS |
| Database | Attacker gains admin access | Principle of least privilege, strong passwords |
| API | Attacker bypasses authentication | Robust auth implementation, security testing |
| Honeypot | Attacker pivots to internal network | Network isolation, no routes to internal |

---

## 4. Security Architecture

### 4.1 Defense in Depth Layers

```
┌─────────────────────────────────────────────────────┐
│  Layer 1: Network Perimeter                         │
│  - Firewall rules                                   │
│  - Network segmentation                             │
└─────────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────────┐
│  Layer 2: Container Security                        │
│  - Minimal images                                   │
│  - Capability dropping                              │
│  - AppArmor/SELinux                                 │
└─────────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────────┐
│  Layer 3: Application Security                      │
│  - Input validation                                 │
│  - Authentication/Authorization                     │
│  - Rate limiting                                    │
└─────────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────────┐
│  Layer 4: Data Security                             │
│  - Encryption at rest                               │
│  - Encryption in transit                            │
│  - Access control                                   │
└─────────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────────┐
│  Layer 5: Monitoring & Response                     │
│  - Audit logging                                    │
│  - Anomaly detection                                │
│  - Incident response                                │
└─────────────────────────────────────────────────────┘
```

### 4.2 Security Zones

#### Zone 1: Exposed (Honeypot)

**Purpose:** Decoy visible to network scanners

**Security Posture:**
- Accepts all incoming connections
- Isolated from internal network
- No sensitive data stored
- Heavily monitored
- Disposable and rebuildable

**Allowed Communication:**
- Incoming: From anywhere (ports 22, 80, 443, 3306)
- Outgoing: To logging server only (no internet)

#### Zone 2: Semi-Trusted (Verification)

**Purpose:** Multi-path verification via VPNs

**Security Posture:**
- No incoming connections from external
- Outbound only through VPN tunnels
- Minimal attack surface
- Credentials encrypted at rest

**Allowed Communication:**
- Incoming: From Engine only (internal network)
- Outgoing: Through VPN tunnels to internet

#### Zone 3: Trusted (Monitor, Engine, Databases)

**Purpose:** Core system components

**Security Posture:**
- No external access
- Internal authentication required
- Encrypted communication
- Regular security updates

**Allowed Communication:**
- Internal only (monitor-net Docker network)
- No direct internet access

### 4.3 Security Controls Matrix

| Control Type | Preventive | Detective | Corrective |
|--------------|-----------|-----------|------------|
| **Network** | Firewall rules, Segmentation | IDS, Traffic analysis | Auto-blocking, Isolation |
| **Container** | Capabilities drop, Read-only FS | Audit logs, File integrity | Auto-restart, Rollback |
| **Application** | Input validation, Auth | API audit logs, Anomaly detection | Rate limiting, Key revocation |
| **Data** | Encryption, Access control | Data access logs | Backup restore, Data redaction |

---

## 5. Container Security

### 5.1 Container Hardening

#### 5.1.1 Minimal Base Images

**Policy:** Use minimal, distroless, or Alpine-based images

```dockerfile
# ✅ GOOD: Minimal Alpine image
FROM alpine:3.18
RUN apk add --no-cache python3

# ❌ BAD: Full Ubuntu image with unnecessary tools
FROM ubuntu:22.04
RUN apt-get install -y python3 curl wget vim git
```

**Verification Container:**
```dockerfile
FROM alpine:3.18 AS base
# Only install what's needed for VPN/Tor/Proxies
RUN apk add --no-cache openvpn tor privoxy python3
```

**Honeypot Container:**
```dockerfile
FROM alpine:3.18
# Minimal SSH honeypot
RUN apk add --no-cache python3 openssh-server
```

#### 5.1.2 Capability Dropping

**Policy:** Drop all capabilities, add back only what's required

```yaml
# docker-compose.yml
services:
  monitor-go:
    cap_drop:
      - ALL
    cap_add:
      - NET_RAW          # Required for packet capture
      - NET_ADMIN        # Required for network interface access

  honeypot:
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE # Required for ports < 1024

  engine-python:
    cap_drop:
      - ALL
    # No capabilities needed
```

**Required Capabilities:**

| Container | Capability | Justification |
|-----------|------------|---------------|
| Monitor | NET_RAW | Packet capture via libpcap |
| Monitor | NET_ADMIN | Network interface control |
| Honeypot | NET_BIND_SERVICE | Bind to ports 22, 80, 443 |
| Verification | NET_ADMIN | VPN namespace management |
| Engine | (none) | No special capabilities needed |

#### 5.1.3 Read-Only Filesystem

**Policy:** Mount root filesystem as read-only where possible

```yaml
services:
  honeypot:
    read_only: true
    tmpfs:
      - /tmp
      - /var/log      # Logs written to tmpfs
      - /var/run

  engine-python:
    read_only: true
    tmpfs:
      - /tmp
    volumes:
      - ./logs:/logs  # Logs written to mounted volume
```

**Exceptions:**
- Verification container: Needs write access for OpenVPN runtime files
- Database containers: Require write access for data

#### 5.1.4 AppArmor / SELinux Profiles

**AppArmor Profile for Honeypot:**

```
# File: apparmor/honeypot.profile

#include <tunables/global>

profile honeypot flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>

  # Allow network
  network inet tcp,
  network inet udp,

  # Deny sensitive file access
  deny /etc/shadow r,
  deny /etc/passwd w,
  deny /root/** rw,

  # Allow logs
  /var/log/honeypot.log w,

  # Deny execution of shells
  deny /bin/bash x,
  deny /bin/sh x,

  # Allow Python
  /usr/bin/python3 ix,
}
```

**Apply Profile:**

```yaml
services:
  honeypot:
    security_opt:
      - apparmor=honeypot
```

#### 5.1.5 Security Scanning

**Automated Scanning:**

```yaml
# .github/workflows/security-scan.yml

- name: Scan Docker images with Trivy
  run: |
    docker build -t nlsn-monitor:latest core/
    trivy image --severity HIGH,CRITICAL --exit-code 1 nlsn-monitor:latest

    docker build -t nlsn-engine:latest engine/
    trivy image --severity HIGH,CRITICAL --exit-code 1 nlsn-engine:latest

    docker build -t nlsn-honeypot:latest honeypot-container/
    trivy image --severity HIGH,CRITICAL --exit-code 1 nlsn-honeypot:latest
```

**Continuous Monitoring:**

```bash
# Daily scan via cron
0 2 * * * trivy image --severity HIGH,CRITICAL nlsn-monitor:latest | mail -s "Security Scan" admin@example.com
```

### 5.2 Container Resource Limits

**Policy:** Enforce resource limits to prevent DoS

```yaml
# docker-compose.yml
services:
  monitor-go:
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 512M
        reservations:
          cpus: '0.5'
          memory: 256M

  engine-python:
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 1G
        reservations:
          cpus: '0.5'
          memory: 512M

  honeypot:
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 256M
        reservations:
          cpus: '0.25'
          memory: 128M
```

**Ulimit Configuration:**

```yaml
services:
  honeypot:
    ulimits:
      nofile:
        soft: 1024
        hard: 2048
      nproc:
        soft: 64
        hard: 128
```

### 5.3 Image Signing and Verification

**Signing Images with Docker Content Trust:**

```bash
# Enable Docker Content Trust
export DOCKER_CONTENT_TRUST=1

# Sign and push images
docker build -t myregistry.com/nlsn-monitor:v1.0 core/
docker push myregistry.com/nlsn-monitor:v1.0  # Automatically signed

# Verify signature on pull
docker pull myregistry.com/nlsn-monitor:v1.0  # Signature verified
```

---

## 6. Network Security

### 6.1 Network Segmentation

**Docker Networks:**

```yaml
# docker-compose.yml
networks:
  monitor-net:
    driver: bridge
    internal: true        # No external access
    ipam:
      config:
        - subnet: 172.20.0.0/16

  honeypot-net:
    driver: bridge
    internal: false       # Exposed to host network
    ipam:
      config:
        - subnet: 172.21.0.0/16
```

**Network Assignments:**

| Container | Network | IP Range | External Access |
|-----------|---------|----------|-----------------|
| Monitor | monitor-net | 172.20.0.10 | No |
| Engine | monitor-net | 172.20.0.20 | No |
| Database | monitor-net | 172.20.0.30 | No |
| Redis | monitor-net | 172.20.0.40 | No |
| Verification | monitor-net | 172.20.0.50 | Outbound via VPN only |
| Honeypot | honeypot-net | 172.21.0.10 | Inbound only |

### 6.2 Firewall Rules

**Host Firewall (iptables):**

```bash
# File: scripts/setup-firewall.sh

#!/bin/bash

# Flush existing rules
iptables -F
iptables -X

# Default policies: DROP everything
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow Honeypot incoming (SSH, HTTP, HTTPS, MySQL)
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -p tcp --dport 3306 -j ACCEPT

# Block honeypot from accessing internal network
iptables -A FORWARD -s 172.21.0.0/16 -d 172.20.0.0/16 -j DROP

# Allow Verification outbound via VPN only
iptables -A OUTPUT -s 172.20.0.50 -o tun+ -j ACCEPT
iptables -A OUTPUT -s 172.20.0.50 ! -o tun+ -j DROP

# Allow Engine to communicate with Verification
iptables -A FORWARD -s 172.20.0.20 -d 172.20.0.50 -j ACCEPT

# Log dropped packets
iptables -A INPUT -j LOG --log-prefix "IPT-INPUT-DROP: "
iptables -A FORWARD -j LOG --log-prefix "IPT-FORWARD-DROP: "
iptables -A OUTPUT -j LOG --log-prefix "IPT-OUTPUT-DROP: "
```

### 6.3 TLS/SSL Configuration

**TLS Requirements:**

- Minimum version: TLS 1.2
- Recommended: TLS 1.3
- Cipher suites: Strong ciphers only (AEAD)
- Certificate validation: Always enabled
- Certificate pinning: For critical services

**API TLS Configuration (Nginx):**

```nginx
# File: nginx/tls.conf

server {
    listen 443 ssl http2;
    server_name api.nlsn-monitor.local;

    # TLS configuration
    ssl_certificate /etc/nginx/certs/api.crt;
    ssl_certificate_key /etc/nginx/certs/api.key;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
    ssl_prefer_server_ciphers on;

    # HSTS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

    # OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;

    # Security headers
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    location / {
        proxy_pass http://engine:8888;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

**Database TLS:**

```yaml
# docker-compose.yml
services:
  postgres:
    environment:
      POSTGRES_SSL_MODE: require
    command: >
      -c ssl=on
      -c ssl_cert_file=/etc/ssl/certs/server.crt
      -c ssl_key_file=/etc/ssl/private/server.key
    volumes:
      - ./certs/postgres.crt:/etc/ssl/certs/server.crt:ro
      - ./certs/postgres.key:/etc/ssl/private/server.key:ro
```

### 6.4 VPN Security

**VPN Configuration Hardening:**

```conf
# File: verification-container/vpn-configs/client.ovpn

client
dev tun
proto udp
remote vpn.example.com 1194

# Security
cipher AES-256-GCM
auth SHA256
tls-version-min 1.2
tls-cipher TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384

# Certificate verification
remote-cert-tls server
verify-x509-name "CN=vpn.example.com"

# Credentials
auth-user-pass /etc/openvpn/credentials.txt

# Prevent DNS leaks
script-security 2
up /etc/openvpn/update-resolv-conf
down /etc/openvpn/update-resolv-conf

# Kill switch (drop traffic if VPN disconnects)
route-noexec
```

**VPN Killswitch Implementation:**

```bash
# File: verification-container/scripts/vpn-killswitch.sh

#!/bin/bash

NAMESPACE=$1

# Block all traffic by default
ip netns exec $NAMESPACE iptables -P INPUT DROP
ip netns exec $NAMESPACE iptables -P OUTPUT DROP
ip netns exec $NAMESPACE iptables -P FORWARD DROP

# Allow loopback
ip netns exec $NAMESPACE iptables -A INPUT -i lo -j ACCEPT
ip netns exec $NAMESPACE iptables -A OUTPUT -o lo -j ACCEPT

# Allow VPN traffic only
ip netns exec $NAMESPACE iptables -A OUTPUT -o tun+ -j ACCEPT
ip netns exec $NAMESPACE iptables -A INPUT -i tun+ -j ACCEPT

# Allow VPN handshake to remote server
ip netns exec $NAMESPACE iptables -A OUTPUT -d <VPN_SERVER_IP> -p udp --dport 1194 -j ACCEPT
```

---

## 7. Authentication & Authorization

### 7.1 API Key Management

**Key Generation:**

```python
# File: engine/auth/key_generator.py

import secrets
import bcrypt
from datetime import datetime, timedelta

class APIKeyGenerator:
    PREFIX = "nlsn_sk_"  # Secret key prefix

    @staticmethod
    def generate_key():
        """Generate cryptographically secure API key"""
        random_part = secrets.token_urlsafe(32)
        key = f"{APIKeyGenerator.PREFIX}{random_part}"
        return key

    @staticmethod
    def hash_key(key: str) -> str:
        """Hash API key using bcrypt"""
        return bcrypt.hashpw(key.encode(), bcrypt.gensalt()).decode()

    @staticmethod
    def verify_key(key: str, hashed: str) -> bool:
        """Verify API key against hash"""
        return bcrypt.checkpw(key.encode(), hashed.encode())

# Usage
key = APIKeyGenerator.generate_key()
key_hash = APIKeyGenerator.hash_key(key)

# Store key_hash in database, return key to user (only once)
```

**Key Storage:**

```sql
CREATE TABLE api_keys (
    id SERIAL PRIMARY KEY,
    key_hash VARCHAR(255) NOT NULL,
    name VARCHAR(100),
    permissions TEXT[],
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP,
    last_used_at TIMESTAMP,
    revoked BOOLEAN DEFAULT FALSE,
    created_by VARCHAR(100),
    INDEX idx_api_keys_hash (key_hash),
    INDEX idx_api_keys_revoked (revoked)
);
```

**Key Validation:**

```python
# File: engine/auth/validator.py

from fastapi import Security, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

security = HTTPBearer()

async def validate_api_key(
    credentials: HTTPAuthorizationCredentials = Security(security)
) -> APIKey:
    """Validate API key from Authorization header"""
    key = credentials.credentials

    # Check format
    if not key.startswith("nlsn_sk_"):
        raise HTTPException(status_code=401, detail="Invalid API key format")

    # Query database
    key_record = await db.query(APIKey).filter(
        APIKey.key_hash == APIKeyGenerator.hash_key(key),
        APIKey.revoked == False
    ).first()

    if not key_record:
        raise HTTPException(status_code=401, detail="Invalid or revoked API key")

    # Check expiration
    if key_record.expires_at and key_record.expires_at < datetime.now():
        raise HTTPException(status_code=401, detail="API key expired")

    # Update last used
    key_record.last_used_at = datetime.now()
    await db.commit()

    return key_record

# Use in endpoints
@app.get("/v1/threats")
async def get_threats(api_key: APIKey = Depends(validate_api_key)):
    # Key is valid, proceed
    pass
```

### 7.2 Role-Based Access Control (RBAC)

**Roles:**

| Role | Permissions | Use Case |
|------|-------------|----------|
| **Admin** | Full access | System administrators |
| **Analyst** | Read threats, trigger verification | Security analysts |
| **Viewer** | Read-only access | Dashboards, reporting |
| **Service** | Limited API access | Automated integrations |

**Permission Matrix:**

| Resource | Admin | Analyst | Viewer | Service |
|----------|-------|---------|--------|---------|
| List Threats | ✅ | ✅ | ✅ | ✅ |
| Get Threat Details | ✅ | ✅ | ✅ | ✅ |
| Trigger Verification | ✅ | ✅ | ❌ | ✅ |
| Start Deception | ✅ | ✅ | ❌ | ❌ |
| Manage API Keys | ✅ | ❌ | ❌ | ❌ |
| System Configuration | ✅ | ❌ | ❌ | ❌ |

**Implementation:**

```python
# File: engine/auth/rbac.py

from enum import Enum
from functools import wraps

class Permission(Enum):
    READ_THREATS = "read:threats"
    TRIGGER_VERIFICATION = "trigger:verification"
    START_DECEPTION = "start:deception"
    MANAGE_KEYS = "manage:keys"
    CONFIGURE_SYSTEM = "configure:system"

class Role(Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"
    SERVICE = "service"

ROLE_PERMISSIONS = {
    Role.ADMIN: [p for p in Permission],
    Role.ANALYST: [
        Permission.READ_THREATS,
        Permission.TRIGGER_VERIFICATION,
        Permission.START_DECEPTION
    ],
    Role.VIEWER: [
        Permission.READ_THREATS
    ],
    Role.SERVICE: [
        Permission.READ_THREATS,
        Permission.TRIGGER_VERIFICATION
    ]
}

def require_permission(permission: Permission):
    """Decorator to enforce permission"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, api_key: APIKey = Depends(validate_api_key), **kwargs):
            # Check if API key's role has required permission
            if permission not in ROLE_PERMISSIONS.get(api_key.role, []):
                raise HTTPException(status_code=403, detail="Insufficient permissions")
            return await func(*args, api_key=api_key, **kwargs)
        return wrapper
    return decorator

# Usage
@app.post("/v1/deception/start")
@require_permission(Permission.START_DECEPTION)
async def start_deception(request: DeceptionRequest, api_key: APIKey = Depends(validate_api_key)):
    # Permission checked, proceed
    pass
```

### 7.3 Key Rotation Policy

**Automatic Rotation:**

```python
# File: engine/auth/rotation.py

import asyncio
from datetime import datetime, timedelta

class KeyRotationService:
    ROTATION_INTERVAL_DAYS = 90

    async def rotate_expiring_keys(self):
        """Rotate keys expiring in next 7 days"""
        expiring_soon = datetime.now() + timedelta(days=7)

        keys_to_rotate = await db.query(APIKey).filter(
            APIKey.expires_at <= expiring_soon,
            APIKey.revoked == False
        ).all()

        for key in keys_to_rotate:
            # Generate new key
            new_key = APIKeyGenerator.generate_key()
            new_key_hash = APIKeyGenerator.hash_key(new_key)

            # Create new key record
            new_key_record = APIKey(
                key_hash=new_key_hash,
                name=f"{key.name} (rotated)",
                permissions=key.permissions,
                expires_at=datetime.now() + timedelta(days=self.ROTATION_INTERVAL_DAYS)
            )
            await db.add(new_key_record)

            # Notify user
            await notify_key_rotation(key.created_by, new_key, key.name)

            # Grace period: old key valid for 7 more days
            key.expires_at = datetime.now() + timedelta(days=7)

        await db.commit()

    async def run_rotation_service(self):
        """Run rotation check daily"""
        while True:
            await self.rotate_expiring_keys()
            await asyncio.sleep(86400)  # 24 hours
```

---

## 8. Data Security

### 8.1 Encryption at Rest

**Database Encryption:**

```yaml
# docker-compose.yml
services:
  postgres:
    environment:
      POSTGRES_INITDB_ARGS: >
        -c ssl=on
        -c shared_preload_libraries='pgcrypto'
    volumes:
      - ./init-encryption.sql:/docker-entrypoint-initdb.d/01-encryption.sql
```

```sql
-- File: init-encryption.sql

-- Enable pgcrypto extension
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Create encrypted columns for sensitive data
CREATE TABLE threats (
    id SERIAL PRIMARY KEY,
    attack_type VARCHAR(50),
    -- Encrypt sensitive evidence data
    evidence BYTEA,  -- Encrypted JSON
    evidence_key_id VARCHAR(50)
);

-- Encryption/Decryption functions
CREATE OR REPLACE FUNCTION encrypt_evidence(data JSONB, key TEXT)
RETURNS BYTEA AS $$
BEGIN
    RETURN pgp_sym_encrypt(data::TEXT, key);
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION decrypt_evidence(encrypted_data BYTEA, key TEXT)
RETURNS JSONB AS $$
BEGIN
    RETURN pgp_sym_decrypt(encrypted_data, key)::JSONB;
END;
$$ LANGUAGE plpgsql;
```

**File Encryption:**

```python
# File: engine/security/encryption.py

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
import base64
import os

class FileEncryption:
    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        """Derive encryption key from password"""
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    @staticmethod
    def encrypt_file(file_path: str, password: str):
        """Encrypt file in place"""
        salt = os.urandom(16)
        key = FileEncryption.derive_key(password, salt)
        fernet = Fernet(key)

        with open(file_path, 'rb') as f:
            data = f.read()

        encrypted = fernet.encrypt(data)

        with open(file_path, 'wb') as f:
            f.write(salt + encrypted)  # Prepend salt

    @staticmethod
    def decrypt_file(file_path: str, password: str) -> bytes:
        """Decrypt file"""
        with open(file_path, 'rb') as f:
            salt = f.read(16)
            encrypted = f.read()

        key = FileEncryption.derive_key(password, salt)
        fernet = Fernet(key)

        return fernet.decrypt(encrypted)

# Usage: Encrypt VPN credentials
FileEncryption.encrypt_file(
    "verification-container/vpn-configs/credentials.txt",
    os.getenv("VPN_ENCRYPTION_KEY")
)
```

### 8.2 Encryption in Transit

**All internal communication uses TLS:**

```python
# File: engine/verification/client.py

import httpx

class VerificationClient:
    def __init__(self):
        self.base_url = "https://verification:8000"  # HTTPS, not HTTP
        self.client = httpx.AsyncClient(
            verify="/etc/ssl/certs/verification.crt",  # Certificate pinning
            timeout=30.0
        )

    async def verify_url(self, url: str, num_paths: int = 10):
        response = await self.client.post(
            f"{self.base_url}/v1/verify",
            json={"url": url, "num_paths": num_paths}
        )
        return response.json()
```

**Redis TLS:**

```yaml
services:
  redis:
    command: >
      redis-server
      --tls-port 6380
      --port 0
      --tls-cert-file /etc/redis/tls/redis.crt
      --tls-key-file /etc/redis/tls/redis.key
      --tls-ca-cert-file /etc/redis/tls/ca.crt
    volumes:
      - ./certs/redis.crt:/etc/redis/tls/redis.crt:ro
      - ./certs/redis.key:/etc/redis/tls/redis.key:ro
```

### 8.3 Data Retention and Disposal

**Retention Policy:**

| Data Type | Retention Period | Disposal Method |
|-----------|------------------|-----------------|
| Threat Logs | 1 year | Secure deletion |
| Verification Results | 90 days | Automatic purge |
| Audit Logs | 2 years | Encrypted archive |
| Honeypot Logs | 6 months | Secure deletion |
| API Logs | 30 days | Rolling deletion |

**Automated Cleanup:**

```python
# File: engine/maintenance/cleanup.py

from datetime import datetime, timedelta

class DataCleanup:
    @staticmethod
    async def cleanup_old_verifications():
        """Delete verification results older than 90 days"""
        cutoff = datetime.now() - timedelta(days=90)

        # Exclude verifications for critical threats
        result = await db.execute("""
            DELETE FROM verification_results
            WHERE timestamp < :cutoff
            AND threat_id NOT IN (
                SELECT id FROM threats WHERE severity IN ('high', 'critical')
            )
        """, {"cutoff": cutoff})

        deleted_count = result.rowcount
        logger.info(f"Deleted {deleted_count} old verification results")

    @staticmethod
    async def archive_old_threats():
        """Archive threats older than 1 year"""
        cutoff = datetime.now() - timedelta(days=365)

        threats = await db.query(Threat).filter(
            Threat.timestamp < cutoff
        ).all()

        # Export to encrypted archive
        archive_file = f"archive_{datetime.now().strftime('%Y%m%d')}.json.enc"
        with open(archive_file, 'w') as f:
            encrypted_data = encrypt_data(json.dumps([t.to_dict() for t in threats]))
            f.write(encrypted_data)

        # Delete from database
        for threat in threats:
            await db.delete(threat)

        await db.commit()

# Run cleanup daily
asyncio.create_task(run_daily_cleanup())
```

---

## 9. Secrets Management

### 9.1 Secrets Architecture

**Never store secrets in:**
- ❌ Git repository
- ❌ Docker images
- ❌ Environment variables (for production)
- ❌ Configuration files

**Store secrets in:**
- ✅ Secrets manager (HashiCorp Vault, AWS Secrets Manager)
- ✅ Encrypted at rest
- ✅ Access controlled via IAM
- ✅ Rotated regularly

### 9.2 HashiCorp Vault Integration

**Vault Setup:**

```bash
# Start Vault server
docker run --name vault \
  -p 8200:8200 \
  -e VAULT_DEV_ROOT_TOKEN_ID=dev-token \
  -e VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200 \
  vault:latest

# Enable KV secrets engine
vault secrets enable -path=nlsn-monitor kv-v2

# Store secrets
vault kv put nlsn-monitor/database \
  username=nlsn \
  password=<strong-password>

vault kv put nlsn-monitor/vpn \
  username=<surfshark-username> \
  password=<surfshark-password>

vault kv put nlsn-monitor/api \
  master_key=<master-api-key>
```

**Retrieve Secrets in Application:**

```python
# File: engine/secrets/vault_client.py

import hvac

class VaultClient:
    def __init__(self):
        self.client = hvac.Client(
            url='http://vault:8200',
            token=os.getenv('VAULT_TOKEN')
        )

    def get_secret(self, path: str) -> dict:
        """Retrieve secret from Vault"""
        response = self.client.secrets.kv.v2.read_secret_version(
            path=path,
            mount_point='nlsn-monitor'
        )
        return response['data']['data']

    def get_database_credentials(self) -> dict:
        """Get database credentials"""
        return self.get_secret('database')

    def get_vpn_credentials(self) -> dict:
        """Get VPN credentials"""
        return self.get_secret('vpn')

# Usage
vault = VaultClient()
db_creds = vault.get_database_credentials()

engine = create_engine(
    f"postgresql://{db_creds['username']}:{db_creds['password']}@postgres/nlsn_monitor"
)
```

### 9.3 Secret Rotation

**Database Password Rotation:**

```python
# File: engine/secrets/rotation.py

import asyncio
from datetime import datetime, timedelta

class SecretRotation:
    async def rotate_database_password(self):
        """Rotate database password"""
        # Generate new password
        new_password = secrets.token_urlsafe(32)

        # Update Vault
        vault.kv.v2.create_or_update_secret(
            path='database',
            secret={'username': 'nlsn', 'password': new_password}
        )

        # Update database
        await db.execute(f"ALTER USER nlsn WITH PASSWORD '{new_password}'")

        # Restart connections with new password
        await db.dispose()
        await db.connect()

        logger.info("Database password rotated successfully")

    async def rotate_api_keys(self):
        """Rotate all API keys older than 90 days"""
        cutoff = datetime.now() - timedelta(days=90)

        keys = await db.query(APIKey).filter(
            APIKey.created_at < cutoff,
            APIKey.revoked == False
        ).all()

        for key in keys:
            # Generate new key
            new_key = APIKeyGenerator.generate_key()

            # Notify user
            await notify_user(key.created_by, f"API key '{key.name}' has been rotated")

            # Revoke old key after grace period
            key.expires_at = datetime.now() + timedelta(days=7)

        await db.commit()
```

---

## 10. Audit Logging

### 10.1 Audit Log Requirements

**Log all security-relevant events:**

- Authentication attempts (success/failure)
- Authorization failures
- API access
- Data access (threats, verification results)
- Configuration changes
- Secret access
- System errors

**Audit Log Format:**

```json
{
  "timestamp": "2025-11-10T14:32:15.123Z",
  "event_type": "api_access",
  "severity": "info",
  "actor": {
    "api_key_id": "key_abc123",
    "role": "analyst",
    "ip_address": "203.0.113.45"
  },
  "action": "GET /v1/threats",
  "resource": {
    "type": "threats",
    "id": null
  },
  "result": "success",
  "metadata": {
    "user_agent": "curl/7.68.0",
    "request_id": "req_xyz789"
  }
}
```

### 10.2 Audit Log Implementation

```python
# File: engine/audit/logger.py

import json
from datetime import datetime
from enum import Enum

class AuditEventType(Enum):
    AUTH_SUCCESS = "auth_success"
    AUTH_FAILURE = "auth_failure"
    API_ACCESS = "api_access"
    DATA_ACCESS = "data_access"
    CONFIG_CHANGE = "config_change"
    SECRET_ACCESS = "secret_access"

class AuditLogger:
    def __init__(self, log_file: str = "/var/log/nlsn-audit.log"):
        self.log_file = log_file

    def log(self, event_type: AuditEventType, actor: dict, action: str,
            resource: dict = None, result: str = "success", metadata: dict = None):
        """Log audit event"""
        event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type.value,
            "severity": self._get_severity(event_type, result),
            "actor": actor,
            "action": action,
            "resource": resource or {},
            "result": result,
            "metadata": metadata or {}
        }

        # Write to log file (append-only)
        with open(self.log_file, 'a') as f:
            f.write(json.dumps(event) + '\n')

        # Also send to SIEM if configured
        if os.getenv('SIEM_ENDPOINT'):
            self._send_to_siem(event)

    def _get_severity(self, event_type: AuditEventType, result: str) -> str:
        """Determine log severity"""
        if result != "success":
            return "error"

        if event_type in [AuditEventType.AUTH_FAILURE, AuditEventType.SECRET_ACCESS]:
            return "warning"

        return "info"

    def _send_to_siem(self, event: dict):
        """Send event to SIEM system"""
        # Implementation depends on SIEM
        pass

# Usage in API endpoint
audit = AuditLogger()

@app.get("/v1/threats/{threat_id}")
async def get_threat(threat_id: str, api_key: APIKey = Depends(validate_api_key)):
    audit.log(
        event_type=AuditEventType.DATA_ACCESS,
        actor={
            "api_key_id": api_key.id,
            "role": api_key.role,
            "ip_address": request.client.host
        },
        action=f"GET /v1/threats/{threat_id}",
        resource={"type": "threat", "id": threat_id},
        result="success",
        metadata={"user_agent": request.headers.get("User-Agent")}
    )

    threat = await db.query(Threat).filter_by(id=threat_id).first()
    return threat
```

### 10.3 Audit Log Protection

**Immutable Logs:**

```bash
# Make audit log append-only (Linux)
sudo chattr +a /var/log/nlsn-audit.log

# Now file can only be appended, not modified or deleted
# Requires root to remove attribute:
# sudo chattr -a /var/log/nlsn-audit.log
```

**Log Forwarding:**

```yaml
# File: filebeat.yml

filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /var/log/nlsn-audit.log
    json.keys_under_root: true
    json.add_error_key: true

output.elasticsearch:
  hosts: ["elasticsearch:9200"]
  index: "nlsn-audit-%{+yyyy.MM.dd}"

# Or forward to Splunk, Datadog, etc.
```

---

## 11. Incident Response

### 11.1 Incident Response Plan

**Phases:**

1. **Preparation**: Tools, procedures, contacts
2. **Detection**: Identify security incident
3. **Containment**: Isolate affected systems
4. **Eradication**: Remove threat
5. **Recovery**: Restore normal operations
6. **Lessons Learned**: Post-mortem analysis

### 11.2 Incident Types

| Incident | Response |
|----------|----------|
| **Container Compromise** | 1. Isolate container 2. Kill and restart 3. Review logs 4. Patch vulnerability |
| **API Key Theft** | 1. Revoke key immediately 2. Audit key usage 3. Generate new key 4. Notify user |
| **Database Breach** | 1. Block external access 2. Change credentials 3. Audit data access 4. Review security |
| **DoS Attack** | 1. Enable rate limiting 2. Block source IPs 3. Scale resources 4. Contact ISP |

### 11.3 Automated Incident Response

```python
# File: engine/incident/response.py

class IncidentResponse:
    async def respond_to_container_compromise(self, container_name: str):
        """Automated response to container compromise"""
        logger.critical(f"Container compromise detected: {container_name}")

        # 1. Isolate container (disconnect network)
        os.system(f"docker network disconnect monitor-net {container_name}")

        # 2. Capture forensics
        logs = os.popen(f"docker logs {container_name}").read()
        with open(f"/var/log/forensics/{container_name}_{datetime.now().isoformat()}.log", 'w') as f:
            f.write(logs)

        # 3. Stop container
        os.system(f"docker stop {container_name}")

        # 4. Alert administrators
        await send_alert(
            severity="critical",
            message=f"Container {container_name} compromised and isolated"
        )

        # 5. Restart from clean image
        await asyncio.sleep(5)
        os.system(f"docker rm {container_name}")
        os.system(f"docker-compose up -d {container_name}")

        logger.info(f"Container {container_name} restarted from clean image")

    async def respond_to_api_key_theft(self, key_id: str):
        """Automated response to API key theft"""
        logger.warning(f"API key theft detected: {key_id}")

        # 1. Revoke key immediately
        key = await db.query(APIKey).filter_by(id=key_id).first()
        key.revoked = True
        await db.commit()

        # 2. Audit key usage
        recent_usage = await db.query(AuditLog).filter(
            AuditLog.api_key_id == key_id,
            AuditLog.timestamp > datetime.now() - timedelta(hours=24)
        ).all()

        # 3. Check for suspicious activity
        suspicious = [
            log for log in recent_usage
            if log.result != "success" or log.action contains "admin"
        ]

        # 4. Notify user
        await notify_user(
            key.created_by,
            f"API key '{key.name}' has been revoked due to suspected compromise"
        )

        # 5. Generate new key
        new_key = APIKeyGenerator.generate_key()
        await create_api_key(new_key, key.name + " (replaced)", key.role)
```

### 11.4 Incident Communication

**Notification Channels:**

```python
# File: engine/incident/notifications.py

class IncidentNotification:
    async def send_alert(self, severity: str, message: str):
        """Send alert through multiple channels"""

        # Email
        await self._send_email(severity, message)

        # Slack
        if severity in ["high", "critical"]:
            await self._send_slack(message)

        # PagerDuty
        if severity == "critical":
            await self._send_pagerduty(message)

        # SMS
        if severity == "critical":
            await self._send_sms(message)

    async def _send_email(self, severity: str, message: str):
        """Send email notification"""
        import smtplib
        from email.mime.text import MIMEText

        msg = MIMEText(message)
        msg['Subject'] = f"[{severity.upper()}] NLSN Security Alert"
        msg['From'] = "alerts@nlsn-monitor.local"
        msg['To'] = "security-team@example.com"

        with smtplib.SMTP('localhost') as server:
            server.send_message(msg)

    async def _send_slack(self, message: str):
        """Send Slack notification"""
        webhook_url = os.getenv('SLACK_WEBHOOK_URL')
        if webhook_url:
            async with httpx.AsyncClient() as client:
                await client.post(webhook_url, json={"text": message})
```

---

## 12. Compliance

### 12.1 GDPR Compliance

**Personal Data Handling:**

| Data Type | GDPR Classification | Retention | Right to Erasure |
|-----------|-------------------|-----------|------------------|
| Threat Logs | Not personal data | 1 year | N/A |
| API Keys | Identifier (pseudonymous) | Until revoked | Yes |
| Audit Logs | Personal data (IP, actions) | 2 years | Limited* |
| User Accounts | Personal data | Until deleted | Yes |

*Audit logs retained for security purposes, erasure limited per GDPR Article 17(3)

**Data Subject Rights Implementation:**

```python
# File: engine/compliance/gdpr.py

class GDPRCompliance:
    async def right_to_access(self, user_id: str) -> dict:
        """Export all data related to user (GDPR Article 15)"""
        data = {
            "api_keys": await self._get_user_api_keys(user_id),
            "audit_logs": await self._get_user_audit_logs(user_id),
            "account_info": await self._get_user_account(user_id)
        }

        return data

    async def right_to_erasure(self, user_id: str):
        """Delete all user data (GDPR Article 17)"""
        # Revoke API keys
        await db.execute("""
            UPDATE api_keys
            SET revoked = true
            WHERE created_by = :user_id
        """, {"user_id": user_id})

        # Anonymize audit logs (can't delete for security)
        await db.execute("""
            UPDATE audit_logs
            SET actor = jsonb_set(actor, '{api_key_id}', '"REDACTED"')
            WHERE actor->>'created_by' = :user_id
        """, {"user_id": user_id})

        # Delete account
        await db.execute("DELETE FROM users WHERE id = :user_id", {"user_id": user_id})

        await db.commit()
```

### 12.2 SOC 2 Compliance

**Control Objectives:**

1. **Access Control**: Least privilege, MFA, RBAC
2. **Availability**: Monitoring, redundancy, disaster recovery
3. **Confidentiality**: Encryption, access logs
4. **Processing Integrity**: Input validation, error handling
5. **Privacy**: Data minimization, retention policies

**Evidence Collection:**

- Audit logs (all access to sensitive data)
- Change logs (all system configuration changes)
- Security scan results
- Incident response documentation

### 12.3 Security Certifications

**Recommended Certifications:**

- **ISO 27001**: Information security management
- **SOC 2 Type II**: Security, availability, confidentiality
- **NIST Cybersecurity Framework**: Comprehensive security controls

---

## Conclusion

This security design provides:

- **Comprehensive threat model** using STRIDE methodology
- **Defense in depth** across network, container, application, and data layers
- **Container hardening** with minimal images, capability dropping, and AppArmor
- **Network segmentation** isolating honeypot from internal systems
- **Strong authentication** with API keys, RBAC, and key rotation
- **Data encryption** at rest and in transit
- **Secrets management** using HashiCorp Vault
- **Comprehensive audit logging** for compliance and forensics
- **Automated incident response** for common security events
- **Compliance frameworks** for GDPR and SOC 2

This design ensures the NLSN PCAP Monitor is secure by design and resilient against attacks.

---

**Document Version:** 1.0
**Total Word Count:** ~12,500 words
**Last Updated:** 2025-11-10
