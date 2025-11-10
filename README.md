# NLSN PCAP Monitor

Advanced network security monitoring system with MITM detection and active deception capabilities.

## Overview

This system provides multi-layered defense against network attacks through:

1. **Passive Detection** - Real-time packet analysis to identify anomalies (DNS hijacking, SSL stripping, weak crypto)
2. **Active Verification** - Multi-path verification through 40+ independent channels (VPNs, Tor, proxies)
3. **Silent Intelligence Gathering** - Logs attacks without alerting attackers
4. **Active Deception** - Automated fake traffic generation to mislead attackers
5. **Honeypot System** - Exposed decoy services to attract and track network scans

## Architecture

### Components

- **Verification Container** (Docker): Multi-path verification via 10 VPNs × (Tor + Proxies) = 40 paths
- **Honeypot Container** (Docker): Exposed decoy system with intentional vulnerabilities
- **Core Monitor** (Go): High-performance packet capture and parsing
- **Deception Engine** (Python): Orchestration, verification, and fake traffic generation

### Threat Model

**Assume Breach**: The system assumes the network is hostile and all connections are potentially compromised.

**Defense Strategy**:
- Verify all connections through multiple independent paths
- Detect attacks silently without revealing detection
- Generate realistic fake traffic to deceive attackers
- Provide verified safe paths for real traffic

## System Requirements

- **OS**: Linux (Ubuntu 22.04+ recommended) or macOS
- **CPU**: 4+ cores
- **RAM**: 8GB minimum, 16GB recommended
- **Network**: Multiple VPN subscriptions (Surfshark configured in this implementation)
- **Privileges**: Root/sudo access for packet capture

## Quick Start

```bash
# 1. Clone repository
cd /Users/nelsonkenzotamashiro/dev/nlsn-pcap-monitor

# 2. Configure VPN credentials
cp verification-container/vpn-configs/credentials.example verification-container/vpn-configs/credentials.txt
# Edit credentials.txt with your Surfshark username/password

# 3. Build and start containers
docker-compose up -d

# 4. Verify system status
docker-compose ps
docker-compose logs -f
```

## Project Structure

```
nlsn-pcap-monitor/
├── verification-container/   # Multi-path verification system
├── honeypot-container/       # Network decoy services
├── core/                     # Go packet capture engine
├── engine/                   # Python orchestration and deception
├── shared/                   # Common configuration
└── docker-compose.yml        # Deployment configuration
```

## Features

### Detection Capabilities

- ✅ DNS hijacking / cache poisoning
- ✅ SSL stripping / HTTPS downgrade attacks
- ✅ Weak cryptography negotiation
- ✅ ARP spoofing / MITM setup detection
- ✅ Certificate manipulation
- ✅ Protocol downgrade attacks

### Deception Capabilities

- ✅ Automated fake traffic generation (human-like behavior)
- ✅ Fake credential submission with honeytokens
- ✅ Realistic browsing session simulation
- ✅ Domain-specific behavior (banking, shopping, social)
- ✅ Packet forgery and routing to controlled endpoints

### Honeypot Features

- ✅ SSH tarpit (slow, realistic responses)
- ✅ Fake web services with vulnerabilities
- ✅ Fake database services
- ✅ Comprehensive attacker action logging
- ✅ Network isolation from real machine

## Security Considerations

### Legal Notice

This system is designed for **defensive security purposes only**. Users are responsible for:

- Ensuring compliance with local laws regarding network monitoring
- Obtaining proper authorization for all monitored networks
- Understanding privacy implications of packet capture
- Proper handling of captured data

### Honeypot Disclaimer

Deploying honeypots may have legal implications. Ensure you understand your local laws regarding:
- Computer fraud and abuse
- Unauthorized access
- Data retention and privacy

## Development Status

**Current Phase**: Phase 1 - Foundation (Weeks 1-3)

See [DEVELOPMENT.md](DEVELOPMENT.md) for detailed implementation timeline.

## License

MIT License - See LICENSE file for details

## Contributing

This is a personal security research project. Contributions welcome via pull requests.

## Acknowledgments

Built with:
- [gopacket](https://github.com/google/gopacket) - Packet processing
- [Scapy](https://scapy.net/) - Packet manipulation
- [Tor](https://www.torproject.org/) - Anonymous routing
- [Cowrie](https://github.com/cowrie/cowrie) - SSH/Telnet honeypot
