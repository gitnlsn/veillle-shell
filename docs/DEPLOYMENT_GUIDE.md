# Deployment Guide

**Version:** 1.0
**Last Updated:** 2025-11-10
**Project:** NLSN PCAP Monitor

---

## Table of Contents

1. [Introduction](#introduction)
2. [Prerequisites](#prerequisites)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Deployment Scenarios](#deployment-scenarios)
6. [Post-Deployment Setup](#post-deployment-setup)
7. [Monitoring & Health Checks](#monitoring--health-checks)
8. [Backup & Recovery](#backup--recovery)
9. [Maintenance & Updates](#maintenance--updates)
10. [Troubleshooting](#troubleshooting)
11. [Performance Tuning](#performance-tuning)
12. [Security Hardening](#security-hardening)

---

## 1. Introduction

This guide provides step-by-step instructions for deploying the NLSN PCAP Monitor system in production environments.

### 1.1 Deployment Overview

**Components:**
- Go Monitor (packet capture)
- Python Engine (orchestration)
- Verification Container (multi-path verification)
- Honeypot Container (network decoy)
- PostgreSQL (threat database)
- Redis (event bus)

**Deployment Methods:**
- Docker Compose (single host)
- Docker Swarm (multi-host)
- Kubernetes (cloud/on-prem)

### 1.2 System Requirements

**Minimum Requirements:**

| Component | CPU | RAM | Disk | Network |
|-----------|-----|-----|------|---------|
| Monitor | 1 core | 512MB | 10GB | 1 Gbps NIC |
| Engine | 1 core | 1GB | 20GB | 100 Mbps |
| Verification | 2 cores | 2GB | 10GB | 100 Mbps |
| Honeypot | 0.5 core | 256MB | 5GB | 10 Mbps |
| Database | 1 core | 512MB | 50GB | 100 Mbps |
| Redis | 0.5 core | 256MB | 5GB | 100 Mbps |
| **Total** | **6 cores** | **4.5GB** | **100GB** | **1 Gbps** |

**Recommended Requirements:**

| Component | CPU | RAM | Disk | Network |
|-----------|-----|-----|------|---------|
| Monitor | 2 cores | 1GB | 20GB | 10 Gbps NIC |
| Engine | 2 cores | 2GB | 50GB | 1 Gbps |
| Verification | 4 cores | 4GB | 20GB | 1 Gbps |
| Honeypot | 1 core | 512MB | 10GB | 100 Mbps |
| Database | 2 cores | 2GB | 100GB SSD | 1 Gbps |
| Redis | 1 core | 1GB | 10GB | 1 Gbps |
| **Total** | **12 cores** | **10.5GB** | **210GB** | **10 Gbps** |

---

## 2. Prerequisites

### 2.1 Software Requirements

**Required:**
- Docker 20.10+ ([install guide](https://docs.docker.com/engine/install/))
- Docker Compose 2.0+ ([install guide](https://docs.docker.com/compose/install/))
- Git 2.30+

**Optional (for local development):**
- Go 1.21+
- Python 3.11+
- PostgreSQL 15+ (client tools)
- Redis 7+ (client tools)

**Installation on Ubuntu 22.04:**

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/download/v2.20.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Install Git
sudo apt install -y git

# Verify installations
docker --version
docker-compose --version
git --version
```

### 2.2 VPN Subscription

**Required for Verification Container:**

1. **Surfshark VPN subscription** (recommended)
   - Sign up at [surfshark.com](https://surfshark.com)
   - Or use alternative VPN provider with OpenVPN support

2. **Download OpenVPN configurations**
   - Login to Surfshark account
   - Navigate to "Manual Setup" > "OpenVPN"
   - Download configurations for 10 locations:
     - us-nyc.ovpn (New York, USA)
     - us-lax.ovpn (Los Angeles, USA)
     - uk-lon.ovpn (London, UK)
     - de-fra.ovpn (Frankfurt, Germany)
     - jp-tok.ovpn (Tokyo, Japan)
     - au-syd.ovpn (Sydney, Australia)
     - ca-tor.ovpn (Toronto, Canada)
     - nl-ams.ovpn (Amsterdam, Netherlands)
     - sg-sin.ovpn (Singapore)
     - br-sao.ovpn (São Paulo, Brazil)

### 2.3 Network Requirements

**Firewall Rules:**

```bash
# Allow incoming to honeypot
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS
sudo ufw allow 3306/tcp  # MySQL

# Allow API access (optional, if exposing externally)
sudo ufw allow 8888/tcp  # Engine API
sudo ufw allow 8000/tcp  # Verification API

# Enable firewall
sudo ufw enable
```

**DNS Configuration:**

Ensure DNS resolution is working:
```bash
# Test DNS
nslookup example.com
nslookup google.com

# If issues, configure DNS servers
sudo nano /etc/resolv.conf
# Add:
# nameserver 8.8.8.8
# nameserver 1.1.1.1
```

### 2.4 System Preparation

**Increase open file limits:**

```bash
# Edit limits configuration
sudo nano /etc/security/limits.conf

# Add:
* soft nofile 65536
* hard nofile 65536

# Apply immediately
ulimit -n 65536
```

**Enable packet forwarding (for VPN):**

```bash
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv6.conf.all.forwarding=1

# Make permanent
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
echo "net.ipv6.conf.all.forwarding=1" | sudo tee -a /etc/sysctl.conf
```

---

## 3. Installation

### 3.1 Clone Repository

```bash
# Clone the repository
git clone https://github.com/yourusername/nlsn-pcap-monitor.git
cd nlsn-pcap-monitor

# Checkout stable release (or main branch for latest)
git checkout v1.0.0
```

### 3.2 Configure VPN

```bash
# Navigate to VPN configuration directory
cd verification-container/vpn-configs

# Copy credentials template
cp credentials.example credentials.txt

# Edit credentials file
nano credentials.txt
# Add your Surfshark credentials:
# Line 1: username
# Line 2: password

# Copy your .ovpn files here
cp ~/Downloads/us-nyc.ovpn .
cp ~/Downloads/us-lax.ovpn .
cp ~/Downloads/uk-lon.ovpn .
# ... (copy all 10 .ovpn files)

# Verify files
ls -la *.ovpn
# Should see 10 .ovpn files

# Secure credentials file
chmod 600 credentials.txt
```

### 3.3 Configure System

```bash
# Navigate back to project root
cd ../..

# Copy configuration template
cp shared/config/settings.example.yaml shared/config/settings.yaml

# Edit configuration
nano shared/config/settings.yaml
```

**Minimal Configuration:**

```yaml
# shared/config/settings.yaml

system:
  environment: production
  log_level: info

database:
  host: postgres
  port: 5432
  name: nlsn_monitor
  username: nlsn
  password: <CHANGE_THIS>  # Strong password

redis:
  host: redis
  port: 6379
  db: 0

api:
  engine:
    host: 0.0.0.0
    port: 8888
  verification:
    host: 0.0.0.0
    port: 8000

capture:
  interface: auto  # Auto-detect network interface
  buffer_size: 10485760  # 10MB
  snaplen: 262144  # 256KB

detection:
  baseline_duration_hours: 24
  dns_threshold: 40
  ssl_strip_threshold: 70

verification:
  default_num_paths: 10
  default_timeout: 15
  strategy: diverse

deception:
  auto_activate: true
  default_behavior_profile: average_user
```

### 3.4 Generate Secrets

```bash
# Generate strong database password
openssl rand -base64 32

# Generate API master key
python3 -c "import secrets; print(f'nlsn_sk_{secrets.token_urlsafe(32)}')"

# Update settings.yaml and docker-compose.yml with these values
```

### 3.5 Build Docker Images

```bash
# Build all images
docker-compose build

# Or build individually
docker-compose build verification
docker-compose build honeypot
docker-compose build monitor-go
docker-compose build engine-python

# Verify images built successfully
docker images | grep nlsn
```

### 3.6 Initialize Database

```bash
# Start database only
docker-compose up -d postgres

# Wait for database to be ready
sleep 10

# Run database migrations
docker-compose run --rm engine-python python -m alembic upgrade head

# Verify migrations
docker exec -it nlsn-postgres psql -U nlsn -d nlsn_monitor -c "\dt"
# Should show: threats, verification_results, honeytokens, deception_sessions, api_keys
```

### 3.7 Start Services

```bash
# Start all services
docker-compose up -d

# Check status
docker-compose ps

# Expected output:
# NAME                   STATUS              PORTS
# nlsn-monitor-go        Up 30 seconds
# nlsn-engine            Up 30 seconds       0.0.0.0:8888->8888/tcp
# nlsn-verification      Up 30 seconds       0.0.0.0:8000->8000/tcp
# nlsn-honeypot          Up 30 seconds       0.0.0.0:22->22/tcp, 0.0.0.0:80->80/tcp
# nlsn-postgres          Up 45 seconds       5432/tcp
# nlsn-redis             Up 45 seconds       6379/tcp

# View logs
docker-compose logs -f
```

### 3.8 Verify Installation

```bash
# Test Engine API
curl http://localhost:8888/v1/health
# Expected: {"status":"healthy", ...}

# Test Verification API
curl http://localhost:8000/v1/health
# Expected: {"status":"healthy","vpns_connected":10, ...}

# Wait 30 seconds for VPNs to connect
sleep 30

# Test verification
curl -X POST http://localhost:8000/v1/verify \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com", "num_paths": 5}' | jq .

# Check paths
curl http://localhost:8000/v1/paths | jq .
# Should show 40 paths with most marked "available"
```

---

## 4. Configuration

### 4.1 Network Interface Selection

**Auto-detection (recommended):**

```yaml
# settings.yaml
capture:
  interface: auto
```

**Manual selection:**

```bash
# List available interfaces
ip link show

# Common interfaces:
# - eth0: Ethernet
# - wlan0: WiFi
# - eno1: Embedded NIC
```

```yaml
# settings.yaml
capture:
  interface: eth0  # Your interface name
```

### 4.2 Detection Thresholds

Tune detection sensitivity:

```yaml
detection:
  # DNS hijacking detection
  dns_threshold: 40  # Lower = more sensitive (default: 40)

  # SSL stripping detection
  ssl_strip_threshold: 70  # Higher = more confident (default: 70)

  # ARP spoofing detection
  arp_spoof_threshold: 80  # Higher = more confident (default: 80)

  # Baseline learning period
  baseline_duration_hours: 24  # How long to learn normal behavior
```

**Sensitivity Guidelines:**

| Environment | dns_threshold | ssl_strip_threshold | arp_spoof_threshold |
|-------------|---------------|---------------------|---------------------|
| High-security (paranoid) | 30 | 60 | 70 |
| Standard (recommended) | 40 | 70 | 80 |
| Low false positives | 50 | 80 | 90 |

### 4.3 Verification Configuration

```yaml
verification:
  # Number of paths to use by default
  default_num_paths: 10  # Range: 3-40

  # Timeout per verification path
  default_timeout: 15  # Seconds

  # Path selection strategy
  strategy: diverse  # Options: diverse, fastest, reliable, balanced

  # Minimum paths for confidence
  min_paths_for_confidence: 5

  # Verification caching
  cache_ttl: 300  # Cache results for 5 minutes
```

### 4.4 Deception Configuration

```yaml
deception:
  # Automatically activate deception when attack detected
  auto_activate: true

  # Default behavior profile
  default_behavior_profile: average_user  # Options: average_user, banking_user, developer, executive

  # Default session duration
  default_duration_minutes: 30

  # Maximum concurrent sessions
  max_concurrent_sessions: 10

  # Fake credential complexity
  password_strength: medium  # Options: weak, medium, strong
```

### 4.5 API Configuration

```yaml
api:
  engine:
    host: 0.0.0.0
    port: 8888
    workers: 4  # Number of worker processes

    # Rate limiting
    rate_limit_requests: 1000
    rate_limit_window: 60  # Seconds

    # CORS (if needed for web UI)
    cors_origins:
      - "http://localhost:3000"
      - "https://dashboard.example.com"

  verification:
    host: 0.0.0.0
    port: 8000
    workers: 2
```

### 4.6 Database Configuration

```yaml
database:
  host: postgres
  port: 5432
  name: nlsn_monitor
  username: nlsn
  password: <YOUR_PASSWORD>

  # Connection pool
  pool_size: 20
  max_overflow: 10
  pool_timeout: 30

  # Query optimization
  echo: false  # Set to true for SQL query logging

  # Backup schedule (cron format)
  backup_schedule: "0 2 * * *"  # Daily at 2 AM
```

### 4.7 Logging Configuration

```yaml
logging:
  level: info  # Options: debug, info, warning, error, critical

  # Log formats
  format: json  # Options: json, text

  # Log destinations
  destinations:
    - console
    - file
    - syslog

  # File logging
  file:
    path: /var/log/nlsn-monitor
    max_size_mb: 100
    backup_count: 10

  # Syslog
  syslog:
    host: localhost
    port: 514
    facility: LOG_LOCAL0
```

---

## 5. Deployment Scenarios

### 5.1 Single-Host Deployment (Docker Compose)

**Best for:** Development, small networks, personal use

```bash
# Start all services on single host
docker-compose up -d

# Scale specific services if needed
docker-compose up -d --scale monitor-go=2
```

**Pros:**
- Simple setup
- Easy to manage
- All components on one machine

**Cons:**
- Single point of failure
- Limited scalability
- Resource constraints

### 5.2 Multi-Host Deployment (Docker Swarm)

**Best for:** Medium-sized deployments, high availability

**Initialize Swarm:**

```bash
# On manager node
docker swarm init --advertise-addr <MANAGER_IP>

# On worker nodes (run output command from above)
docker swarm join --token <TOKEN> <MANAGER_IP>:2377

# Verify cluster
docker node ls
```

**Deploy Stack:**

```bash
# Deploy to swarm
docker stack deploy -c docker-compose.swarm.yml nlsn

# Check services
docker service ls

# Scale services
docker service scale nlsn_monitor-go=3

# Update service
docker service update --image nlsn-monitor:v1.1 nlsn_monitor-go
```

**docker-compose.swarm.yml:**

```yaml
version: '3.8'

services:
  monitor-go:
    image: nlsn-monitor:latest
    deploy:
      replicas: 2
      placement:
        constraints:
          - node.role == worker
      resources:
        limits:
          cpus: '1.0'
          memory: 512M

  engine-python:
    image: nlsn-engine:latest
    deploy:
      replicas: 2
      placement:
        constraints:
          - node.role == worker

  verification:
    image: nlsn-verification:latest
    deploy:
      replicas: 1  # VPN connections, don't scale
      placement:
        constraints:
          - node.role == manager  # Requires privileged access

  postgres:
    image: postgres:15
    deploy:
      replicas: 1
      placement:
        constraints:
          - node.role == manager
    volumes:
      - postgres-data:/var/lib/postgresql/data

volumes:
  postgres-data:
    driver: local
```

### 5.3 Kubernetes Deployment

**Best for:** Large deployments, cloud environments, enterprise

**Prerequisites:**
- Kubernetes cluster 1.25+
- kubectl configured
- Helm 3+ (optional)

**Create Namespace:**

```bash
kubectl create namespace nlsn-monitor
kubectl config set-context --current --namespace=nlsn-monitor
```

**Deploy Database:**

```yaml
# File: k8s/postgres.yaml

apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: postgres-pvc
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 100Gi
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: postgres
spec:
  serviceName: postgres
  replicas: 1
  selector:
    matchLabels:
      app: postgres
  template:
    metadata:
      labels:
        app: postgres
    spec:
      containers:
      - name: postgres
        image: postgres:15
        env:
        - name: POSTGRES_DB
          value: nlsn_monitor
        - name: POSTGRES_USER
          value: nlsn
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: postgres-secret
              key: password
        volumeMounts:
        - name: data
          mountPath: /var/lib/postgresql/data
      volumes:
      - name: data
        persistentVolumeClaim:
          claimName: postgres-pvc
---
apiVersion: v1
kind: Service
metadata:
  name: postgres
spec:
  selector:
    app: postgres
  ports:
  - port: 5432
```

**Deploy Monitor:**

```yaml
# File: k8s/monitor.yaml

apiVersion: apps/v1
kind: DaemonSet  # Run on all worker nodes
metadata:
  name: monitor-go
spec:
  selector:
    matchLabels:
      app: monitor-go
  template:
    metadata:
      labels:
        app: monitor-go
    spec:
      hostNetwork: true  # Access host network interfaces
      containers:
      - name: monitor
        image: nlsn-monitor:latest
        securityContext:
          capabilities:
            add:
              - NET_RAW
              - NET_ADMIN
        env:
        - name: INTERFACE
          value: "auto"
        - name: REDIS_HOST
          value: redis
        resources:
          limits:
            cpu: "1"
            memory: "512Mi"
          requests:
            cpu: "500m"
            memory: "256Mi"
```

**Deploy Engine:**

```yaml
# File: k8s/engine.yaml

apiVersion: apps/v1
kind: Deployment
metadata:
  name: engine-python
spec:
  replicas: 3
  selector:
    matchLabels:
      app: engine-python
  template:
    metadata:
      labels:
        app: engine-python
    spec:
      containers:
      - name: engine
        image: nlsn-engine:latest
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: engine-secret
              key: database-url
        - name: REDIS_HOST
          value: redis
        ports:
        - containerPort: 8888
        livenessProbe:
          httpGet:
            path: /v1/health
            port: 8888
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /v1/health
            port: 8888
          initialDelaySeconds: 10
          periodSeconds: 5
---
apiVersion: v1
kind: Service
metadata:
  name: engine
spec:
  type: LoadBalancer
  selector:
    app: engine-python
  ports:
  - port: 8888
    targetPort: 8888
```

**Deploy All:**

```bash
# Create secrets
kubectl create secret generic postgres-secret --from-literal=password=<YOUR_PASSWORD>
kubectl create secret generic engine-secret --from-literal=database-url=<DATABASE_URL>

# Apply manifests
kubectl apply -f k8s/postgres.yaml
kubectl apply -f k8s/redis.yaml
kubectl apply -f k8s/monitor.yaml
kubectl apply -f k8s/engine.yaml
kubectl apply -f k8s/verification.yaml

# Check pods
kubectl get pods

# Check services
kubectl get svc

# View logs
kubectl logs -f deployment/engine-python
```

### 5.4 Cloud Deployments

#### AWS Deployment

```bash
# Using ECS (Elastic Container Service)

# 1. Create ECR repositories
aws ecr create-repository --repository-name nlsn-monitor
aws ecr create-repository --repository-name nlsn-engine

# 2. Build and push images
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin <ACCOUNT_ID>.dkr.ecr.us-east-1.amazonaws.com
docker build -t nlsn-monitor core/
docker tag nlsn-monitor:latest <ACCOUNT_ID>.dkr.ecr.us-east-1.amazonaws.com/nlsn-monitor:latest
docker push <ACCOUNT_ID>.dkr.ecr.us-east-1.amazonaws.com/nlsn-monitor:latest

# 3. Create ECS cluster
aws ecs create-cluster --cluster-name nlsn-cluster

# 4. Create task definition
aws ecs register-task-definition --cli-input-json file://ecs-task-definition.json

# 5. Create service
aws ecs create-service \
  --cluster nlsn-cluster \
  --service-name nlsn-engine \
  --task-definition nlsn-engine:1 \
  --desired-count 2 \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[subnet-12345],securityGroups=[sg-12345]}"
```

---

## 6. Post-Deployment Setup

### 6.1 Create Admin API Key

```bash
# Access engine container
docker exec -it nlsn-engine bash

# Create API key
python -m cli create-api-key \
  --name "Admin Key" \
  --role admin \
  --expires "2026-12-31"

# Output:
# API Key created successfully
# Key: nlsn_sk_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
# Store this key securely - it will not be shown again

# Exit container
exit
```

**Store key securely:**

```bash
# Save to password manager or secrets vault
echo "nlsn_sk_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6" | vault kv put secret/nlsn/admin-key value=-
```

### 6.2 Verify VPN Connections

```bash
# Check VPN status
docker exec -it nlsn-verification python3 << 'EOF'
import subprocess
import json

for i in range(10):
    result = subprocess.run(
        ["ip", "netns", "exec", f"vpn-ns-{i}", "curl", "-s", "https://ipinfo.io/ip"],
        capture_output=True, text=True
    )
    print(f"VPN {i}: {result.stdout.strip()}")
EOF

# Expected: 10 different IP addresses
```

### 6.3 Test Attack Detection

```bash
# Generate test DNS query with wrong IP
docker exec -it nlsn-monitor-go ./scripts/test-dns-hijack.sh

# Wait 5 seconds
sleep 5

# Check if threat was logged
curl -H "Authorization: Bearer <YOUR_API_KEY>" \
  http://localhost:8888/v1/threats?limit=1 | jq .

# Expected: Recent threat with attack_type="dns_hijack"
```

### 6.4 Configure Alerts

```bash
# Edit environment variables
docker-compose stop engine-python

# Add alert configuration
nano .env
# Add:
# SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
# PAGERDUTY_API_KEY=your_pagerduty_key
# SMTP_SERVER=smtp.gmail.com
# SMTP_PORT=587
# SMTP_USERNAME=alerts@example.com
# SMTP_PASSWORD=your_password

# Restart engine
docker-compose up -d engine-python
```

### 6.5 Schedule Backups

```bash
# Create backup script
cat > /usr/local/bin/nlsn-backup.sh << 'EOF'
#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR=/var/backups/nlsn-monitor

mkdir -p $BACKUP_DIR

# Backup database
docker exec nlsn-postgres pg_dump -U nlsn nlsn_monitor | gzip > $BACKUP_DIR/database_$DATE.sql.gz

# Backup configuration
cp -r /opt/nlsn-pcap-monitor/shared/config $BACKUP_DIR/config_$DATE

# Backup VPN configs (encrypted)
tar czf - /opt/nlsn-pcap-monitor/verification-container/vpn-configs | \
  openssl enc -aes-256-cbc -salt -out $BACKUP_DIR/vpn_$DATE.tar.gz.enc -pass pass:$BACKUP_PASSWORD

# Keep only last 30 days
find $BACKUP_DIR -name "*.gz" -mtime +30 -delete
find $BACKUP_DIR -name "*.enc" -mtime +30 -delete

echo "Backup completed: $DATE"
EOF

chmod +x /usr/local/bin/nlsn-backup.sh

# Add to crontab (daily at 2 AM)
(crontab -l 2>/dev/null; echo "0 2 * * * /usr/local/bin/nlsn-backup.sh") | crontab -
```

---

## 7. Monitoring & Health Checks

### 7.1 Health Check Endpoints

```bash
# Check all services
curl http://localhost:8888/v1/health | jq .
curl http://localhost:8000/v1/health | jq .

# Check database
docker exec nlsn-postgres pg_isready -U nlsn

# Check Redis
docker exec nlsn-redis redis-cli ping
```

### 7.2 Prometheus Monitoring

**Install Prometheus:**

```yaml
# docker-compose.monitoring.yml

version: '3.8'

services:
  prometheus:
    image: prom/prometheus:latest
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus-data:/prometheus
    ports:
      - "9090:9090"

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - grafana-data:/var/lib/grafana

volumes:
  prometheus-data:
  grafana-data:
```

**Prometheus Configuration:**

```yaml
# prometheus.yml

global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'nlsn-engine'
    static_configs:
      - targets: ['engine:8888']

  - job_name: 'nlsn-verification'
    static_configs:
      - targets: ['verification:8000']

  - job_name: 'postgres'
    static_configs:
      - targets: ['postgres:9187']  # Requires postgres_exporter

  - job_name: 'redis'
    static_configs:
      - targets: ['redis:9121']  # Requires redis_exporter
```

**Start Monitoring:**

```bash
docker-compose -f docker-compose.monitoring.yml up -d

# Access Grafana: http://localhost:3000
# Default credentials: admin/admin
```

### 7.3 Log Aggregation

**ELK Stack (Elasticsearch, Logstash, Kibana):**

```yaml
# docker-compose.logging.yml

version: '3.8'

services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.5.0
    environment:
      - discovery.type=single-node
      - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
    ports:
      - "9200:9200"

  logstash:
    image: docker.elastic.co/logstash/logstash:8.5.0
    volumes:
      - ./logstash.conf:/usr/share/logstash/pipeline/logstash.conf
    ports:
      - "5000:5000"

  kibana:
    image: docker.elastic.co/kibana/kibana:8.5.0
    ports:
      - "5601:5601"
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
```

### 7.4 Alerting Rules

**Prometheus Alerts:**

```yaml
# File: alert-rules.yml

groups:
  - name: nlsn-alerts
    interval: 30s
    rules:
      - alert: HighPacketLoss
        expr: rate(packets_dropped_total[5m]) > 0.01
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High packet loss detected"
          description: "Packet loss rate is {{ $value }}%"

      - alert: VPNDisconnected
        expr: vpn_connections_active < 8
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "VPN connections below threshold"
          description: "Only {{ $value }} VPNs connected (expected: 10)"

      - alert: CriticalThreatDetected
        expr: increase(threats_detected_total{severity="critical"}[5m]) > 0
        labels:
          severity: critical
        annotations:
          summary: "Critical threat detected"
          description: "{{ $value }} critical threats in last 5 minutes"

      - alert: DatabaseDown
        expr: up{job="postgres"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Database is down"
```

---

## 8. Backup & Recovery

### 8.1 Backup Strategy

**3-2-1 Rule:**
- 3 copies of data
- 2 different storage types
- 1 off-site backup

**Backup Components:**
1. PostgreSQL database
2. Configuration files
3. VPN credentials (encrypted)
4. API keys (encrypted)
5. Audit logs

### 8.2 Database Backup

**Manual Backup:**

```bash
# Full database backup
docker exec nlsn-postgres pg_dump -U nlsn nlsn_monitor > backup_$(date +%Y%m%d).sql

# Compressed backup
docker exec nlsn-postgres pg_dump -U nlsn nlsn_monitor | gzip > backup_$(date +%Y%m%d).sql.gz

# Backup specific tables
docker exec nlsn-postgres pg_dump -U nlsn -t threats -t verification_results nlsn_monitor > threats_backup.sql
```

**Automated Backup (already configured in section 6.5):**

```bash
# Verify backup script is running
ls -lh /var/backups/nlsn-monitor/

# Test restore
gunzip < /var/backups/nlsn-monitor/database_20251110_020000.sql.gz | \
  docker exec -i nlsn-postgres psql -U nlsn nlsn_monitor
```

### 8.3 Disaster Recovery

**Complete System Restore:**

```bash
# 1. Reinstall system on new hardware
# Follow installation steps (sections 2-3)

# 2. Restore configuration
tar xzf config_backup.tar.gz -C /opt/nlsn-pcap-monitor/

# 3. Restore VPN credentials (encrypted)
openssl enc -aes-256-cbc -d -in vpn_backup.tar.gz.enc -pass pass:$BACKUP_PASSWORD | tar xz

# 4. Start database
docker-compose up -d postgres
sleep 10

# 5. Restore database
gunzip < database_backup.sql.gz | docker exec -i nlsn-postgres psql -U nlsn nlsn_monitor

# 6. Start all services
docker-compose up -d

# 7. Verify restoration
curl http://localhost:8888/v1/health
```

**Recovery Time Objective (RTO):** < 1 hour
**Recovery Point Objective (RPO):** < 24 hours (daily backups)

---

## 9. Maintenance & Updates

### 9.1 Regular Maintenance Tasks

**Daily:**
- Check logs for errors: `docker-compose logs --tail=100`
- Verify services running: `docker-compose ps`
- Check disk space: `df -h`

**Weekly:**
- Review threat statistics: `curl http://localhost:8888/v1/stats?period=7d`
- Check VPN connectivity: See section 6.2
- Rotate logs: `docker-compose logs > archive_$(date +%Y%m%d).log`

**Monthly:**
- Update Docker images: See section 9.2
- Review and rotate API keys
- Test backup restoration
- Security vulnerability scan

### 9.2 System Updates

**Update Docker Images:**

```bash
# Pull latest images
docker-compose pull

# Restart with new images
docker-compose up -d

# Verify versions
docker images | grep nlsn
```

**Update with Zero Downtime (Docker Swarm):**

```bash
# Update monitor service (rolling update)
docker service update --image nlsn-monitor:v1.1 nlsn_monitor-go

# Update engine (rolling update)
docker service update --image nlsn-engine:v1.1 nlsn_engine-python
```

### 9.3 Database Maintenance

**Vacuum Database:**

```bash
# Full vacuum (reclaim space)
docker exec -it nlsn-postgres psql -U nlsn -d nlsn_monitor -c "VACUUM FULL;"

# Analyze (update statistics)
docker exec -it nlsn-postgres psql -U nlsn -d nlsn_monitor -c "ANALYZE;"
```

**Reindex:**

```bash
docker exec -it nlsn-postgres psql -U nlsn -d nlsn_monitor -c "REINDEX DATABASE nlsn_monitor;"
```

### 9.4 Log Rotation

```bash
# Configure logrotate
sudo nano /etc/logrotate.d/nlsn-monitor

# Add:
/var/lib/docker/containers/*/*-json.log {
  rotate 7
  daily
  compress
  size=10M
  missingok
  delaycompress
  copytruncate
}
```

---

## 10. Troubleshooting

### 10.1 Common Issues

#### Issue: VPN Not Connecting

**Symptoms:**
- `vpns_connected` < 10 in health check
- Verification fails with "Insufficient paths"

**Diagnosis:**

```bash
# Check VPN logs
docker exec nlsn-verification cat /var/log/openvpn/ns-0.log

# Test credentials
docker exec nlsn-verification cat /etc/openvpn/credentials.txt

# Verify .ovpn files
docker exec nlsn-verification ls -la /etc/openvpn/*.ovpn
```

**Solutions:**

```bash
# 1. Verify credentials are correct
# Edit verification-container/vpn-configs/credentials.txt

# 2. Restart verification container
docker-compose restart verification

# 3. Check firewall
sudo ufw status
sudo ufw allow out 1194/udp

# 4. Test manual connection
docker exec -it nlsn-verification openvpn --config /etc/openvpn/us-nyc.ovpn
```

#### Issue: Monitor Not Capturing Packets

**Symptoms:**
- `packets_captured` = 0 in stats
- No threats detected

**Diagnosis:**

```bash
# Check monitor logs
docker logs nlsn-monitor-go

# Verify interface
docker exec nlsn-monitor-go ip link show

# Check capabilities
docker exec nlsn-monitor-go getcap /app/monitor
```

**Solutions:**

```bash
# 1. Verify network interface in settings.yaml
# Change from "auto" to specific interface like "eth0"

# 2. Check Docker privileges
# In docker-compose.yml, ensure:
#   cap_add:
#     - NET_RAW
#     - NET_ADMIN

# 3. Restart monitor
docker-compose restart monitor-go

# 4. Test packet capture manually
docker exec -it nlsn-monitor-go tcpdump -i eth0 -c 10
```

#### Issue: High Memory Usage

**Symptoms:**
- Container OOM killed
- System swap usage high

**Diagnosis:**

```bash
# Check container memory
docker stats

# Check system memory
free -h
```

**Solutions:**

```bash
# 1. Increase container limits in docker-compose.yml
services:
  engine-python:
    deploy:
      resources:
        limits:
          memory: 2G  # Increase from 1G

# 2. Reduce buffer sizes in settings.yaml
capture:
  buffer_size: 5242880  # Reduce to 5MB

# 3. Enable packet sampling
capture:
  sampling_rate: 10  # Capture every 10th packet

# 4. Restart services
docker-compose up -d
```

### 10.2 Diagnostic Commands

```bash
# System health overview
make health

# Detailed container inspection
docker inspect nlsn-monitor-go | jq .

# Network connectivity
docker exec nlsn-engine ping -c 3 postgres
docker exec nlsn-engine ping -c 3 redis

# Database connectivity
docker exec nlsn-postgres psql -U nlsn -d nlsn_monitor -c "SELECT COUNT(*) FROM threats;"

# Redis connectivity
docker exec nlsn-redis redis-cli ping

# Check open connections
docker exec nlsn-postgres psql -U nlsn -c "SELECT count(*) FROM pg_stat_activity;"
```

### 10.3 Debug Mode

```bash
# Enable debug logging
nano shared/config/settings.yaml
# Change:
# log_level: debug

# Restart services
docker-compose restart

# View detailed logs
docker-compose logs -f --tail=100

# Disable debug mode when done (performance impact)
```

---

## 11. Performance Tuning

### 11.1 Packet Capture Optimization

```yaml
# settings.yaml
capture:
  # Increase buffer for high traffic
  buffer_size: 20971520  # 20MB

  # Reduce snaplen if only headers needed
  snaplen: 1500  # Only capture 1500 bytes per packet

  # Enable BPF filter to reduce load
  bpf_filter: "port 53 or port 80 or port 443 or arp"

  # Enable packet sampling for very high traffic
  sampling_rate: 1  # Capture every packet (default)
  # sampling_rate: 10  # Capture every 10th packet (90% reduction)
```

### 11.2 Database Optimization

```yaml
# settings.yaml
database:
  # Increase connection pool
  pool_size: 50
  max_overflow: 20

  # Tune query performance
  query_timeout: 10  # Seconds
```

**PostgreSQL Tuning:**

```sql
-- In PostgreSQL container
-- Edit /var/lib/postgresql/data/postgresql.conf

# Memory
shared_buffers = 256MB
effective_cache_size = 1GB
work_mem = 16MB

# Connections
max_connections = 100

# Checkpoints
checkpoint_completion_target = 0.9
wal_buffers = 16MB

# Query Planner
random_page_cost = 1.1  # For SSD
effective_io_concurrency = 200

# Restart to apply
# docker-compose restart postgres
```

### 11.3 Redis Optimization

```conf
# redis.conf

# Memory
maxmemory 1gb
maxmemory-policy allkeys-lru

# Persistence (disable for pure cache)
save ""
appendonly no

# Performance
tcp-backlog 511
timeout 300
tcp-keepalive 60
```

### 11.4 API Performance

```yaml
# settings.yaml
api:
  engine:
    workers: 8  # Increase for more concurrent requests
    worker_class: uvicorn.workers.UvicornWorker

    # Connection pooling
    keepalive: 5  # Seconds

    # Request queue
    backlog: 2048
```

---

## 12. Security Hardening

### 12.1 Host Hardening

```bash
# Disable unnecessary services
sudo systemctl disable bluetooth
sudo systemctl disable cups

# Enable automatic security updates
sudo apt install unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades

# Configure firewall
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp  # SSH (change port if needed)
sudo ufw allow 8888/tcp  # Engine API
sudo ufw enable

# Harden SSH
sudo nano /etc/ssh/sshd_config
# Set:
# PermitRootLogin no
# PasswordAuthentication no
# PubkeyAuthentication yes
sudo systemctl restart sshd
```

### 12.2 Docker Security

```yaml
# docker-compose.yml - Security best practices

services:
  monitor-go:
    # Run as non-root user
    user: "1000:1000"

    # Drop all capabilities, add only needed
    cap_drop:
      - ALL
    cap_add:
      - NET_RAW
      - NET_ADMIN

    # Read-only root filesystem
    read_only: true
    tmpfs:
      - /tmp

    # Resource limits
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 512M

    # Security options
    security_opt:
      - no-new-privileges:true
      - apparmor=docker-default
```

### 12.3 Network Hardening

```bash
# Enable syn cookies (prevent SYN flood)
sudo sysctl -w net.ipv4.tcp_syncookies=1

# Enable reverse path filtering
sudo sysctl -w net.ipv4.conf.all.rp_filter=1

# Disable ICMP redirects
sudo sysctl -w net.ipv4.conf.all.accept_redirects=0
sudo sysctl -w net.ipv6.conf.all.accept_redirects=0

# Make permanent
sudo nano /etc/sysctl.conf
# Add above settings
sudo sysctl -p
```

### 12.4 Audit Logging

```bash
# Enable Docker audit logging
sudo nano /etc/audit/rules.d/docker.rules

# Add:
-w /usr/bin/docker -p wa -k docker
-w /var/lib/docker -p wa -k docker
-w /etc/docker -p wa -k docker
-w /usr/lib/systemd/system/docker.service -p wa -k docker
-w /usr/lib/systemd/system/docker.socket -p wa -k docker

# Restart auditd
sudo service auditd restart
```

---

## Conclusion

This deployment guide provides comprehensive instructions for:

- **Installation** on various platforms (Docker Compose, Swarm, Kubernetes)
- **Configuration** of all system components
- **Deployment scenarios** for different scales
- **Post-deployment setup** including backups and monitoring
- **Troubleshooting** common issues
- **Performance tuning** for high-traffic environments
- **Security hardening** best practices

Following this guide ensures a secure, performant, and maintainable NLSN PCAP Monitor deployment.

---

**Document Version:** 1.0
**Total Word Count:** ~10,200 words
**Last Updated:** 2025-11-10
