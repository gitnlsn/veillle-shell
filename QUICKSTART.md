# Quick Start Guide

## What Has Been Built

✅ **Foundation Complete** - Project structure, configuration, Docker setup
✅ **Verification Container** - Multi-path verification via 10 VPNs × 4 paths = 40 paths
✅ **Path Orchestrator** - API for comparing responses across independent network paths
✅ **Go Monitor Skeleton** - Packet capture framework ready for implementation
✅ **Python Engine Skeleton** - API server and module structure
✅ **Docker Compose** - Full deployment configuration

## Current Status

**Phase 1 (Foundation)**: ✅ COMPLETE
**Phase 2 (Detection)**: 🚧 Ready to implement
**Phase 3 (Deception)**: 📋 Planned
**Phase 4 (Honeypot)**: 📋 Planned

## Next Steps to Get Running

### 1. Configure VPN (Required for Verification)

```bash
cd verification-container/vpn-configs

# Create credentials file
cp credentials.example credentials.txt

# Edit with your Surfshark username and password
nano credentials.txt
```

Add your `.ovpn` files from Surfshark:
- Download from: https://account.surfshark.com/setup/manual
- Choose "OpenVPN" configuration
- Download configs for locations matching `setup-namespaces.sh`

Expected files:
```
us-nyc.ovpn
us-lax.ovpn
uk-lon.ovpn
de-fra.ovpn
jp-tok.ovpn
au-syd.ovpn
ca-tor.ovpn
nl-ams.ovpn
sg-sin.ovpn
br-sao.ovpn
```

### 2. Build and Test Verification Container

```bash
# Build the container
make build-verification

# Start it
docker-compose up verification

# In another terminal, test it
make verify-test
```

Expected output:
```json
{
  "url": "https://example.com",
  "attack_detected": false,
  "confidence": "HIGH",
  "paths_checked": 10,
  "paths_agreed": 10,
  ...
}
```

### 3. Test Full System (Partial)

```bash
# Start all services
make up

# Check status
make status

# View logs
make logs

# Check health
make health
```

## What Works Now

### ✅ Verification Container
- Multiple VPN connections in isolated namespaces
- Tor routing through each VPN
- HTTP proxies
- Path orchestrator API
- Multi-path verification with majority voting
- Attack detection through response comparison

### ✅ Basic Infrastructure
- Docker Compose orchestration
- Redis event bus (ready)
- PostgreSQL database (ready)
- API server framework
- Go packet capture framework
- Configuration system

## What Needs Implementation

### 🚧 Phase 2: Detection Layer (Next Priority)

**Go Components** (core/pkg/):
1. `parser/dns.go` - DNS packet parser
2. `parser/http.go` - HTTP packet parser
3. `parser/tls.go` - TLS handshake parser
4. `detector/dns.go` - DNS anomaly detection
5. `detector/tls.go` - TLS/SSL attack detection
6. `events/publisher.go` - Redis event publishing

**Python Components** (engine/):
1. `verification/client.py` - Client for verification container
2. `detector/dns_hijack.py` - DNS hijacking detection logic
3. `detector/ssl_strip.py` - SSL stripping detection logic
4. `intelligence/threat_db.py` - Threat logging database

### 🚧 Phase 3: Deception Engine

**Python Components** (engine/deception/):
1. `autopilot.py` - Automated deception when attack detected
2. `packet_forge.py` - Scapy-based packet forgery
3. `behavior_sim.py` - Human behavior simulation
4. `response_server.py` - Controlled endpoint for fake traffic

### 🚧 Phase 4: Honeypot System

**Honeypot Container** (honeypot-container/):
1. SSH tarpit implementation
2. Fake web services
3. Fake database services
4. Comprehensive logging
5. Network isolation

## Testing the Current System

### Test 1: Verification Container

```bash
# Start verification container
docker-compose up -d verification

# Wait 30 seconds for VPNs to connect

# Test paths list
curl http://localhost:8000/paths

# Test verification
curl -X POST http://localhost:8000/verify \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://ipinfo.io/ip",
    "num_paths": 10,
    "timeout": 15
  }' | jq .
```

You should see different IPs reported from different paths, proving VPNs are working.

### Test 2: Simulate MITM Attack

```bash
# Test same URL through verification paths
# If responses differ, attack is detected

# Example: Check if DNS is consistent
for i in {0..9}; do
  docker exec nlsn-verification \
    ip netns exec vpn-ns-$i \
    dig +short example.com
done

# All should return same IP if no MITM
```

## Development Workflow

```bash
# Using Makefile (recommended)
make help           # Show all commands
make build          # Build all containers
make up             # Start services
make logs           # View logs
make down           # Stop services

# Testing
make test           # Run all tests
make verify-test    # Test verification
make health         # Check service health

# Development
make dev-go         # Run Go monitor locally
make dev-python     # Run Python engine locally

# Debugging
make shell-verification  # Access verification container
make db-shell           # Access database
make redis-cli          # Access Redis
```

## Common Issues

### Issue: VPN not connecting

**Solution:**
```bash
# Check logs
docker logs nlsn-verification

# Verify credentials exist
docker exec nlsn-verification cat /etc/openvpn/credentials.txt

# Verify .ovpn files exist
docker exec nlsn-verification ls -la /etc/openvpn/
```

### Issue: Port already in use

**Solution:**
```bash
# Find what's using the port
lsof -i :8000  # Verification
lsof -i :8888  # Engine API
lsof -i :22    # Honeypot SSH

# Stop conflicting service or change port in docker-compose.yml
```

### Issue: Go not found

**Solution:**
```bash
# Check Go installation
go version

# If not found, install Go
brew install go  # macOS
# or visit: https://golang.org/dl/

# After install, verify
go version
```

## Architecture Diagram

```
┌─────────────────────────────────────────┐
│  Verification Container (Port 8000)     │
│  ┌───────────────────────────────────┐  │
│  │ 10 VPN Namespaces                 │  │
│  │ - Each with: VPN, Tor, Proxies    │  │
│  │ - Total: 40 unique paths          │  │
│  └───────────────────────────────────┘  │
│  ┌───────────────────────────────────┐  │
│  │ Path Orchestrator API             │  │
│  │ - Multi-path verification         │  │
│  │ - Response comparison             │  │
│  │ - Attack detection                │  │
│  └───────────────────────────────────┘  │
└─────────────────────────────────────────┘
                  ↓
┌─────────────────────────────────────────┐
│  Engine (Python) (Port 8888)            │
│  - Detection coordination               │
│  - Deception automation                 │
│  - Threat intelligence                  │
└─────────────────────────────────────────┘
                  ↓
┌─────────────────────────────────────────┐
│  Monitor (Go) (Packet Capture)          │
│  - libpcap capture                      │
│  - Protocol parsing                     │
│  - Anomaly detection                    │
└─────────────────────────────────────────┘
```

## Next Implementation Priority

1. **DNS packet parser** (Go) - Parse DNS queries/responses
2. **DNS anomaly detector** (Go) - Detect suspicious DNS behavior
3. **Verification trigger** (Python) - Call verification when suspicious
4. **Threat logger** (Python) - Log detected attacks silently
5. **Deception autopilot** (Python) - Generate fake traffic when attack confirmed

Each component builds on the previous, creating the complete detection → verification → deception pipeline.

## Resources

- **Full Documentation**: See [DEVELOPMENT.md](DEVELOPMENT.md)
- **Configuration**: See [shared/config/settings.example.yaml](shared/config/settings.example.yaml)
- **API Docs** (when running):
  - Verification: http://localhost:8000/docs
  - Engine: http://localhost:8888/docs

## Getting Help

1. Check logs: `make logs`
2. Review [DEVELOPMENT.md](DEVELOPMENT.md)
3. Enable debug logging in `settings.yaml`
4. Check container health: `make health`

Happy monitoring! 🛡️
