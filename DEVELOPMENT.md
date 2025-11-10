# Development Guide

## Prerequisites

### Required Software

- **Docker** (20.10+) and Docker Compose (2.0+)
- **Go** (1.21+) - for local development
- **Python** (3.11+) - for local development
- **Root/sudo access** - required for packet capture

### Optional

- **Surfshark VPN** subscription (or alternative VPN provider)
- **PostgreSQL client** - for database management
- **Redis client** - for debugging event bus

## Initial Setup

### 1. Clone and Configure

```bash
cd /Users/nelsonkenzotamashiro/dev/nlsn-pcap-monitor

# Copy example configuration
cp shared/config/settings.example.yaml shared/config/settings.yaml

# Edit settings as needed
nano shared/config/settings.yaml
```

### 2. VPN Configuration

```bash
# Navigate to VPN configs
cd verification-container/vpn-configs

# Create credentials file
cp credentials.example credentials.txt

# Edit with your Surfshark username/password
nano credentials.txt

# Download .ovpn files from Surfshark
# Place them in this directory with names matching setup-namespaces.sh:
# us-nyc.ovpn, uk-lon.ovpn, de-fra.ovpn, etc.
```

### 3. Build Containers

```bash
# Build all containers
docker-compose build

# Or build individually
docker-compose build verification
docker-compose build honeypot
docker-compose build monitor-go
docker-compose build engine-python
```

## Development Workflow

### Running the Full System

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Check status
docker-compose ps

# Stop all services
docker-compose down
```

### Running Individual Components

```bash
# Just verification container
docker-compose up -d verification

# Just honeypot
docker-compose up -d honeypot

# Monitor + Engine + Supporting services
docker-compose up -d monitor-go engine-python redis postgres
```

### Local Development (without Docker)

#### Go Monitor

```bash
cd core

# Install dependencies
go mod download

# Run locally (requires root for packet capture)
sudo go run cmd/monitor/main.go -interface en0

# Build binary
go build -o bin/monitor cmd/monitor/main.go
```

#### Python Engine

```bash
cd engine

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r ../requirements.txt

# Run API server
uvicorn api.server:app --reload --port 8888
```

## Testing

### Manual Testing

#### Test Verification Container

```bash
# Access verification container
docker exec -it nlsn-verification bash

# Test VPN connectivity from inside
ip netns exec vpn-ns-0 curl https://ipinfo.io/ip
ip netns exec vpn-ns-1 curl https://ipinfo.io/ip

# Test Tor
ip netns exec vpn-ns-0 curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org

# Test path orchestrator API
curl http://localhost:8000/health
curl http://localhost:8000/paths

# Test verification
curl -X POST http://localhost:8000/verify \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com", "num_paths": 5}'
```

#### Test Honeypot

```bash
# Scan honeypot (from another machine or use localhost)
nmap -p 22,80,443,3306 localhost

# Try SSH connection
ssh -p 22 root@localhost

# Access honeypot logs
docker exec -it nlsn-honeypot tail -f /var/log/honeypot.log
```

#### Test Go Monitor

```bash
# Check if monitor is capturing
docker logs nlsn-monitor-go

# View Redis events
docker exec -it nlsn-redis redis-cli
> SUBSCRIBE packets:dns
> SUBSCRIBE packets:http
> SUBSCRIBE attacks:detected
```

### Automated Testing

```bash
# Run Go tests
cd core
go test ./...

# Run Python tests
cd engine
pytest
```

## Debugging

### Common Issues

**Problem**: VPN not connecting in verification container

```bash
# Check VPN logs
docker exec -it nlsn-verification cat /var/log/openvpn/ns-0.log

# Verify credentials exist
docker exec -it nlsn-verification cat /etc/openvpn/credentials.txt

# Check namespace status
docker exec -it nlsn-verification ip netns list
```

**Problem**: Go monitor not capturing packets

```bash
# Check interface name
docker exec -it nlsn-monitor-go ip link show

# Verify permissions
docker exec -it nlsn-monitor-go getcap /app/monitor

# Check logs for errors
docker logs nlsn-monitor-go --tail 100
```

**Problem**: Python engine can't connect to verification

```bash
# Test connectivity
docker exec -it nlsn-engine curl http://verification:8000/health

# Check network
docker network inspect nlsn-pcap-monitor_monitor-net

# Verify environment variables
docker exec -it nlsn-engine env | grep VERIFICATION
```

### Accessing Databases

```bash
# PostgreSQL
docker exec -it nlsn-postgres psql -U nlsn -d nlsn_monitor

# Redis
docker exec -it nlsn-redis redis-cli
```

### Container Shell Access

```bash
# Verification container
docker exec -it nlsn-verification bash

# Honeypot
docker exec -it nlsn-honeypot sh

# Monitor (Go)
docker exec -it nlsn-monitor-go sh

# Engine (Python)
docker exec -it nlsn-engine bash
```

## Project Structure Details

### Core (Go) Components

```
core/
├── cmd/monitor/          # Main binary
├── pkg/
│   ├── capture/          # Packet capture logic
│   ├── parser/           # Protocol parsers (DNS, HTTP, TLS)
│   ├── detector/         # Anomaly detection
│   └── events/           # Event publishing
```

### Engine (Python) Components

```
engine/
├── api/                  # FastAPI server
├── detector/             # Detection logic
├── deception/            # Fake traffic generation
├── verification/         # Client for verification container
└── intelligence/         # Threat database
```

## Adding New Features

### Adding a New Detection Rule

1. Create detector in `core/pkg/detector/` (Go) or `engine/detector/` (Python)
2. Register detector in main processing loop
3. Define event schema in `shared/proto/`
4. Add tests
5. Update configuration schema

### Adding a New Verification Path

1. Edit `verification-container/setup-namespaces.sh`
2. Add VPN location to `VPN_LOCATIONS` array
3. Place corresponding `.ovpn` file in `vpn-configs/`
4. Restart verification container

### Adding a New Honeypot Service

1. Create service in `honeypot-container/services/`
2. Add to `honeypot-container/Dockerfile`
3. Expose port in `docker-compose.yml`
4. Configure in `shared/config/settings.yaml`

## Performance Tuning

### Packet Capture Optimization

```yaml
# settings.yaml
capture:
  buffer_size: 20971520  # Increase to 20MB for high traffic
  snaplen: 2048          # Reduce if only headers needed
```

### Verification Path Selection

```yaml
# settings.yaml
verification:
  num_paths: 5          # Reduce for faster verification
  timeout: 10           # Reduce for faster response
  selection_strategy: "fastest"  # Use fastest paths
```

## Production Deployment

### Security Checklist

- [ ] Change all default passwords in `settings.yaml`
- [ ] Use strong PostgreSQL password
- [ ] Enable TLS for API endpoints
- [ ] Restrict API access with firewall
- [ ] Enable audit logging
- [ ] Regular security updates

### Monitoring

```bash
# Resource usage
docker stats

# Packet capture rate
docker logs nlsn-monitor-go | grep "Processed"

# Attack detection rate
docker exec -it nlsn-postgres psql -U nlsn -c \
  "SELECT attack_type, COUNT(*) FROM threats GROUP BY attack_type"
```

## Contributing

1. Create feature branch
2. Make changes
3. Add tests
4. Update documentation
5. Submit pull request

## Support

For issues and questions:
- Check logs: `docker-compose logs -f`
- Review this guide
- Check GitHub issues
- Enable debug logging in `settings.yaml`
