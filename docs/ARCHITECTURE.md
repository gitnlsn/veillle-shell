# System Architecture

## Table of Contents
1. [Overview](#overview)
2. [High-Level Architecture](#high-level-architecture)
3. [Component Architecture](#component-architecture)
4. [Data Flow](#data-flow)
5. [Network Topology](#network-topology)
6. [Security Architecture](#security-architecture)
7. [Scalability](#scalability)

---

## Overview

### System Purpose

NLSN PCAP Monitor is a comprehensive network security system that:
- **Detects** network attacks through passive packet analysis
- **Verifies** suspicions through multi-path independent verification
- **Deceives** attackers with realistic fake traffic
- **Attracts** and tracks attackers through honeypot infrastructure
- **Logs** threats silently without alerting attackers

### Core Philosophy: Assume Breach

The system operates under the assumption that the local network is hostile and potentially compromised. Therefore:
- All data must be verified through independent channels
- Detection must be silent (no visible alerts that attackers can observe)
- Real traffic uses verified safe paths
- Fake traffic deceives attackers into believing attacks succeeded

### Key Innovation: Multi-Path Verification

Unlike traditional IDS systems that trust local network infrastructure, this system verifies all suspicious activity through 40 independent network paths:
- 10 different VPN connections (geographic diversity)
- Each VPN supports 4 paths: Direct, Tor, HTTP Proxy, Tor+Proxy
- Total: 10 × 4 = 40 independent verification channels

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         USER'S MACHINE                              │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │  Browser / Applications                                        │ │
│  │  (Chrome with Enhanced Protection, etc.)                       │ │
│  └───────────────────────────────────────────────────────────────┘ │
│                              ↓                                      │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │  NLSN Monitor System (Container Group)                        │ │
│  │                                                                 │ │
│  │  ┌─────────────┐  ┌──────────────┐  ┌────────────────────┐   │ │
│  │  │   Monitor   │  │   Engine     │  │   Verification     │   │ │
│  │  │   (Go)      │→ │   (Python)   │→ │   Container        │   │ │
│  │  │             │  │              │  │   (40 paths)       │   │ │
│  │  │  Packet     │  │  Detection   │  │                    │   │ │
│  │  │  Capture    │  │  Deception   │  │   10 VPNs          │   │ │
│  │  │  Parsing    │  │  Intelligence│  │   + Tor            │   │ │
│  │  └─────────────┘  └──────────────┘  │   + Proxies        │   │ │
│  │         ↓                ↓           └────────────────────┘   │ │
│  │  ┌─────────────────────────────────────────────────────────┐  │ │
│  │  │  Redis (Event Bus)                                      │  │ │
│  │  └─────────────────────────────────────────────────────────┘  │ │
│  │         ↓                                                      │ │
│  │  ┌─────────────────────────────────────────────────────────┐  │ │
│  │  │  PostgreSQL (Threat Intelligence Database)              │  │ │
│  │  └─────────────────────────────────────────────────────────┘  │ │
│  └───────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘

                              Network Boundary
─────────────────────────────────────────────────────────────────────────

┌─────────────────────────────────────────────────────────────────────┐
│                      HONEYPOT CONTAINER                             │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │  Exposed Services (Decoy for Network Scans)                   │ │
│  │                                                                 │ │
│  │  Port 22:   SSH Tarpit         (slow, realistic)              │ │
│  │  Port 80:   HTTP Honeypot      (fake vulnerabilities)         │ │
│  │  Port 443:  HTTPS Honeypot     (fake services)                │ │
│  │  Port 3306: MySQL Honeypot     (fake database)                │ │
│  │  Port 5432: PostgreSQL Honeypot                               │ │
│  │                                                                 │ │
│  │  ✓ Isolated from real machine                                 │ │
│  │  ✓ All actions logged                                         │ │
│  │  ✓ No access to production data                               │ │
│  └───────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘

                              Internet
─────────────────────────────────────────────────────────────────────────

┌─────────────────────────────────────────────────────────────────────┐
│                         ATTACKER                                    │
│                                                                      │
│  Sees:                                Real Legitimate               │
│  ✗ Honeypot (thinks it's real)        Services (verified)          │
│  ✗ Fake traffic (thinks MITM works)                                │
│  ✗ Fake credentials stolen                                         │
│                                                                      │
│  Doesn't see:                                                       │
│  ✓ Real machine (appears offline)                                  │
│  ✓ Real traffic (via VPN/Tor)                                      │
│  ✓ Detection system                                                │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Component Architecture

### 1. Monitor (Go) - Packet Capture Layer

**Purpose**: High-performance packet capture and real-time analysis

**Technology Stack**:
- Language: Go 1.21+
- Libraries: gopacket, libpcap
- Performance: ~40,000 packets/sec

**Components**:
```
core/
├── cmd/monitor/main.go          # Entry point
├── pkg/
│   ├── capture/
│   │   ├── interface.go         # Interface detection
│   │   ├── capture.go           # Packet capture loop
│   │   └── buffer.go            # Ring buffer management
│   ├── parser/
│   │   ├── dns.go               # DNS parser
│   │   ├── http.go              # HTTP parser
│   │   ├── tls.go               # TLS handshake parser
│   │   └── arp.go               # ARP parser
│   ├── detector/
│   │   ├── dns_anomaly.go       # DNS hijacking detection
│   │   ├── tls_anomaly.go       # SSL stripping detection
│   │   ├── crypto_weak.go       # Weak crypto detection
│   │   └── scorer.go            # Suspicion scoring
│   └── events/
│       ├── publisher.go         # Redis event publisher
│       └── schemas.go           # Event data structures
```

**Responsibilities**:
1. Capture packets on specified interface
2. Parse protocol-specific fields (DNS, HTTP, TLS, ARP)
3. Detect anomalies using heuristics
4. Calculate suspicion scores
5. Publish events to Redis when anomalies detected
6. Maintain high performance (minimal latency)

**Performance Requirements**:
- Packet loss: < 0.1% at 10K pkt/s
- Latency: < 10ms from capture to event publish
- Memory: < 500MB steady state
- CPU: < 30% on 2-core system at normal traffic

### 2. Engine (Python) - Orchestration Layer

**Purpose**: Coordinate detection, verification, and deception

**Technology Stack**:
- Language: Python 3.11+
- Framework: FastAPI, asyncio
- Libraries: httpx, scapy, sqlalchemy

**Components**:
```
engine/
├── api/
│   ├── server.py                # FastAPI server
│   └── routes/
│       ├── verification.py      # Manual verification endpoint
│       ├── threats.py           # Threat query endpoint
│       └── stats.py             # Statistics endpoint
├── detector/
│   ├── dns_hijack.py            # DNS hijacking logic
│   ├── ssl_strip.py             # SSL stripping logic
│   ├── crypto_weak.py           # Crypto weakness logic
│   └── coordinator.py           # Detection coordination
├── verification/
│   ├── client.py                # Verification container client
│   ├── comparison.py            # Response comparison logic
│   └── cache.py                 # Verification result cache
├── deception/
│   ├── autopilot.py             # Automated deception
│   ├── packet_forge.py          # Scapy packet crafting
│   ├── behavior_sim.py          # Human behavior simulation
│   ├── credential_gen.py        # Fake credential generation
│   └── response_server.py       # Controlled response endpoint
├── intelligence/
│   ├── threat_db.py             # Threat database ORM
│   ├── honeytoken.py            # Honeytoken management
│   ├── tracker.py               # Attacker tracking
│   └── reporting.py             # Report generation
└── core/
    ├── config.py                # Configuration loading
    ├── logging.py               # Structured logging
    └── events.py                # Redis event consumer
```

**Responsibilities**:
1. Consume events from Redis (published by Monitor)
2. Coordinate verification when suspicion threshold exceeded
3. Analyze verification results to confirm attacks
4. Log confirmed attacks silently to database
5. Trigger automated deception when attack confirmed
6. Generate and track honeytokens
7. Provide API for manual operations and queries

### 3. Verification Container - Multi-Path Verification

**Purpose**: Verify suspicious activity through independent network paths

**Technology Stack**:
- Base: Ubuntu 22.04
- VPN: OpenVPN (Surfshark configs)
- Anonymization: Tor
- Proxies: Privoxy, Dante
- API: FastAPI (Python)

**Architecture**:
```
Verification Container
├── Network Namespaces (10)
│   ├── vpn-ns-0 (US New York)
│   │   ├── OpenVPN client → Surfshark US-NYC
│   │   ├── Tor daemon (port 9050)
│   │   ├── Privoxy HTTP proxy (port 8080)
│   │   └── Routes: Direct, Tor, Proxy, Tor+Proxy
│   ├── vpn-ns-1 (US Los Angeles)
│   │   └── ... (same structure)
│   ├── vpn-ns-2 (UK London)
│   ├── ... (8 more namespaces)
│   └── vpn-ns-9 (Brazil Sao Paulo)
│
└── Path Orchestrator (API on port 8000)
    ├── /verify  - Multi-path verification endpoint
    ├── /paths   - List available paths
    └── /health  - Health check
```

**40 Verification Paths**:
| Namespace | VPN Location | Paths |
|-----------|--------------|-------|
| vpn-ns-0 | US NYC | Direct, Tor, HTTP Proxy, Tor+Proxy |
| vpn-ns-1 | US LAX | Direct, Tor, HTTP Proxy, Tor+Proxy |
| vpn-ns-2 | UK LON | Direct, Tor, HTTP Proxy, Tor+Proxy |
| vpn-ns-3 | DE FRA | Direct, Tor, HTTP Proxy, Tor+Proxy |
| vpn-ns-4 | JP TOK | Direct, Tor, HTTP Proxy, Tor+Proxy |
| vpn-ns-5 | AU SYD | Direct, Tor, HTTP Proxy, Tor+Proxy |
| vpn-ns-6 | CA TOR | Direct, Tor, HTTP Proxy, Tor+Proxy |
| vpn-ns-7 | NL AMS | Direct, Tor, HTTP Proxy, Tor+Proxy |
| vpn-ns-8 | SG SIN | Direct, Tor, HTTP Proxy, Tor+Proxy |
| vpn-ns-9 | BR SAO | Direct, Tor, HTTP Proxy, Tor+Proxy |

**Verification Algorithm**:
1. Receive verification request (URL, num_paths, timeout)
2. Select N paths randomly or strategically
3. Execute requests concurrently through all paths
4. Collect responses with timing data
5. Hash response content for comparison
6. Group by hash (identical responses)
7. Apply majority voting:
   - If all agree → No attack (HIGH confidence)
   - If majority agrees → Likely no attack (MEDIUM confidence)
   - If significant disagreement → Attack detected (HIGH confidence)
8. Return: attack_detected, compromised_paths, safe_paths, verified_data

**Isolation**:
- Each namespace has independent network stack
- VPN traffic cannot leak to host
- Namespaces cannot communicate with each other
- Tor provides additional anonymization layer

### 4. Honeypot Container - Network Decoy

**Purpose**: Attract and track network attackers

**Technology Stack**:
- Base: Alpine Linux (minimal footprint)
- SSH: Cowrie (SSH/Telnet honeypot)
- Web: Custom Flask/FastAPI fake services
- Database: Fake MySQL/PostgreSQL emulators

**Exposed Services**:
```
Port 22 (SSH):
├── Cowrie SSH honeypot
├── Characteristics:
│   ├── Tarpit mode (slow responses)
│   ├── Accepts weak credentials
│   ├── Fake filesystem with realistic structure
│   ├── Fake command execution
│   └── All actions logged

Port 80/443 (HTTP/HTTPS):
├── Fake web applications
├── Intentional vulnerabilities:
│   ├── SQL injection (returns fake DB dumps)
│   ├── Directory traversal (serves fake files)
│   ├── XXE injection
│   └── Command injection (fake shell)
├── Realistic responses
└── Embedded honeytokens

Port 3306 (MySQL):
├── Fake MySQL protocol
├── Accepts connections
├── Returns fake database schemas
├── Logs all queries
└── Slow responses (tarpit)

Port 5432 (PostgreSQL):
├── Fake PostgreSQL protocol
├── Similar to MySQL honeypot
└── Industry-specific fake data
```

**Network Isolation**:
```
┌─────────────────────────────────────┐
│  Honeypot Container                 │
│  ┌───────────────────────────────┐  │
│  │  Services (exposed)           │  │
│  └───────────────────────────────┘  │
│           ↓                          │
│  ┌───────────────────────────────┐  │
│  │  Logging (write-only)         │  │
│  └───────────────────────────────┘  │
└─────────────────────────────────────┘
         ↑
         │ Monitoring only
         │ (no control path)
         ↓
┌─────────────────────────────────────┐
│  Host Machine (isolated)            │
│  ✗ NO incoming connections          │
│  ✗ NO access from honeypot          │
│  ✓ Monitors honeypot logs           │
└─────────────────────────────────────┘
```

**Security Measures**:
- Container capabilities dropped (CAP_DROP=ALL)
- Read-only filesystem (except /var/log, /tmp)
- No privileged mode
- Network: separate bridge from host
- Resource limits (CPU, memory)
- AppArmor/SELinux profiles

### 5. Data Layer

#### Redis (Event Bus)

**Purpose**: Real-time event streaming between components

**Channels**:
```
packets:dns          # DNS packets and anomalies
packets:http         # HTTP packets and anomalies
packets:tls          # TLS handshakes and anomalies
packets:arp          # ARP packets
attacks:detected     # Confirmed attacks
attacks:suspected    # Suspicious activity
deception:active     # Active deception sessions
verification:requested  # Verification requests
verification:complete   # Verification results
honeypot:interaction    # Honeypot activity
```

**Event Schema Example** (DNS Anomaly):
```json
{
  "event_type": "dns_anomaly",
  "timestamp": "2025-01-10T12:34:56Z",
  "source_ip": "192.168.1.100",
  "dest_ip": "8.8.8.8",
  "domain": "bank.com",
  "query_type": "A",
  "response_ip": "1.2.3.4",
  "suspicion_score": 85,
  "reasons": [
    "unexpected_dns_server",
    "response_ip_mismatch"
  ],
  "metadata": {
    "expected_ip": "5.6.7.8",
    "ttl": 60
  }
}
```

#### PostgreSQL (Threat Intelligence)

**Purpose**: Persistent storage for threat data

**Schema**:
```sql
-- Threat logs
CREATE TABLE threats (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    attack_type VARCHAR(50) NOT NULL,
    confidence VARCHAR(20) NOT NULL,
    source_event_id VARCHAR(100),
    attacker_ips TEXT[],
    target VARCHAR(255),
    verified BOOLEAN DEFAULT FALSE,
    verification_details JSONB,
    deception_activated BOOLEAN DEFAULT FALSE,
    status VARCHAR(20) DEFAULT 'active'
);

-- Honeytokens
CREATE TABLE honeytokens (
    id SERIAL PRIMARY KEY,
    token_type VARCHAR(50) NOT NULL,
    token_value VARCHAR(255) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    embedded_in VARCHAR(255),
    trigger_count INTEGER DEFAULT 0,
    last_triggered TIMESTAMPTZ,
    attacker_context JSONB
);

-- Honeypot sessions
CREATE TABLE honeypot_sessions (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(100) UNIQUE,
    service VARCHAR(50),
    attacker_ip VARCHAR(45),
    start_time TIMESTAMPTZ DEFAULT NOW(),
    end_time TIMESTAMPTZ,
    commands_executed TEXT[],
    files_accessed TEXT[],
    data_exfiltrated TEXT,
    attacker_fingerprint JSONB
);

-- Verification results
CREATE TABLE verification_results (
    id SERIAL PRIMARY KEY,
    url VARCHAR(1000),
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    paths_checked INTEGER,
    paths_agreed INTEGER,
    attack_detected BOOLEAN,
    compromised_paths TEXT[],
    verified_data_hash VARCHAR(64)
);

-- System statistics
CREATE TABLE statistics (
    timestamp TIMESTAMPTZ PRIMARY KEY,
    packets_captured BIGINT,
    attacks_detected INTEGER,
    verifications_performed INTEGER,
    honeypot_interactions INTEGER,
    active_deceptions INTEGER
);
```

---

## Data Flow

### Scenario 1: Normal Traffic (No Attack)

```
1. User browses to https://example.com
   ↓
2. Monitor captures DNS query packet
   ↓
3. Parser extracts: domain=example.com, response_ip=93.184.216.34
   ↓
4. Detector checks anomaly patterns
   ↓
5. Suspicion score: 10 (LOW - normal behavior)
   ↓
6. No event published (below threshold)
   ↓
7. Traffic proceeds normally
```

### Scenario 2: DNS Hijacking Detected

```
1. User browses to https://bank.com
   ↓
2. Monitor captures DNS response
   ↓
3. Parser extracts: domain=bank.com, response_ip=1.2.3.4
   ↓
4. Detector notices:
   - Unusual DNS server (not user's configured DNS)
   - IP differs from historical data
   ↓
5. Suspicion score: 85 (HIGH)
   ↓
6. Event published to Redis: "packets:dns" + "attacks:suspected"
   ↓
7. Engine consumes event
   ↓
8. Engine triggers verification:
   POST http://verification:8000/verify
   {
     "url": "https://bank.com",
     "num_paths": 10,
     "timeout": 15
   }
   ↓
9. Verification Container:
   - Queries bank.com through 10 different VPN paths
   - Results:
     * 9 paths return: 5.6.7.8 (legitimate)
     * 1 path returns: 1.2.3.4 (local network - compromised)
   ↓
10. Verification response:
    {
      "attack_detected": true,
      "confidence": "HIGH",
      "attack_type": "DNS_HIJACKING",
      "compromised_paths": ["vpn-ns-0-direct"],
      "verified_ip": "5.6.7.8"
    }
   ↓
11. Engine logs to database:
    INSERT INTO threats (
      attack_type='DNS_HIJACKING',
      attacker_ips=['1.2.3.4'],
      target='bank.com',
      verified=true
    )
   ↓
12. User's browser (Chrome Enhanced Protection) blocks HTTP connection
    - Shows: "This site is insecure"
   ↓
13. User closes tab/blocks connection
   ↓
14. Engine activates deception autopilot:
    - Generates fake DNS queries for bank.com subdomains
    - Fake TCP handshake to 1.2.3.4:443
    - Fake TLS ClientHello
    - Fake HTTP requests (if SSL stripped)
    - Fake credential submission:
      username: fake_user_9871
      password: P@ssw0rd123!_FAKE
      (embedded with honeytoken tracking ID)
   ↓
15. Attacker sees:
    - User "ignored" security warning
    - User submitted credentials
    - User browsed account dashboard
    ↓
16. Engine provides user with safe verified connection:
    - Routes through: VPN-UK → Tor → bank.com (5.6.7.8)
   ↓
17. User completes banking safely
   ↓
18. System monitors if honeytoken used elsewhere
    - If attacker tries fake credentials on real bank.com
    - Alert triggered, attacker infrastructure mapped
```

### Scenario 3: Honeypot Interaction

```
1. Attacker scans network: nmap 192.168.1.0/24
   ↓
2. Discovers honeypot: 192.168.1.100
   - Ports: 22, 80, 443, 3306 open
   ↓
3. Real machine: 192.168.1.50
   - Appears offline (firewall blocks scans)
   ↓
4. Attacker attempts SSH: ssh root@192.168.1.100
   ↓
5. Honeypot accepts connection
   ↓
6. Tarpit delay: 5 seconds before password prompt
   ↓
7. Attacker tries: password=admin
   ↓
8. Tarpit delay: 8 seconds processing
   ↓
9. "Login successful" (fake)
   ↓
10. Attacker: ls /
   ↓
11. Tarpit delay: 3 seconds
   ↓
12. Returns fake filesystem
   ↓
13. Attacker: cat /etc/shadow
   ↓
14. Returns fake shadow file with crackable hashes
   ↓
15. All actions logged:
    INSERT INTO honeypot_sessions (
      attacker_ip='203.0.113.45',
      service='ssh',
      commands_executed=['ls /', 'cat /etc/shadow'],
      ...
    )
   ↓
16. Attacker wastes hours in tarpit
   ↓
17. System fingerprints attacker:
    - Tools used
    - Techniques
    - Objectives
    - Skill level
```

---

## Network Topology

### Physical/Logical Network Layout

```
Internet
   │
   │ (Router/Firewall)
   │
   ├────────────────┬────────────────────┐
   │                │                    │
   │                │                    │
Honeypot      Real Machine         Verification
(192.168.1.100)  (192.168.1.50)    (Cloud or Local)
   │                │
   │                │
Exposed          Isolated
All ports        Firewalled
```

### Docker Network Architecture

```
┌──────────────────────────────────────────────────┐
│  Docker Host                                     │
│                                                   │
│  ┌────────────────────────────────────────────┐  │
│  │  honeypot-net (bridge, external=true)     │  │
│  │  ├─ honeypot container (exposed)          │  │
│  │  └─ Accessible from internet              │  │
│  └────────────────────────────────────────────┘  │
│                                                   │
│  ┌────────────────────────────────────────────┐  │
│  │  monitor-net (bridge, internal=true)      │  │
│  │  ├─ monitor-go                            │  │
│  │  ├─ engine-python                         │  │
│  │  ├─ verification                          │  │
│  │  ├─ redis                                 │  │
│  │  ├─ postgres                              │  │
│  │  └─ Isolated from internet                │  │
│  └────────────────────────────────────────────┘  │
│                                                   │
│  Monitor uses host network for packet capture    │
└──────────────────────────────────────────────────┘
```

### Verification Container Internal Network

```
Inside Verification Container:

┌─────────────────────────────────────────┐
│  Default Namespace                      │
│  ├─ Path Orchestrator API (port 8000)  │
│  └─ Controls all namespaces             │
└─────────────────────────────────────────┘
        │
        ├─ vpn-ns-0 (isolated)
        │  ├─ OpenVPN → Surfshark US-NYC
        │  ├─ Tor (port 9050)
        │  ├─ Privoxy (port 8080)
        │  └─ External IP: 198.51.100.1
        │
        ├─ vpn-ns-1 (isolated)
        │  └─ External IP: 198.51.100.2
        │
        ├─ ... (8 more namespaces)
        │
        └─ vpn-ns-9 (isolated)
           └─ External IP: 198.51.100.10

Each namespace completely isolated:
- Separate routing tables
- Separate network interfaces
- Cannot communicate with other namespaces
- Traffic exits through different VPN servers
```

---

## Security Architecture

### Trust Boundaries

```
┌─────────────────────────────────────────────────┐
│  Trust Zone 1: Host Machine                    │
│  Highest trust - User's actual system           │
│  ✓ Real user data                              │
│  ✓ Production credentials                      │
│  ✓ Monitoring system                           │
└─────────────────────────────────────────────────┘
         │
         │ Firewall (one-way monitoring)
         ↓
┌─────────────────────────────────────────────────┐
│  Trust Zone 2: Monitoring Containers           │
│  Medium trust - Internal processing             │
│  ✓ Monitor (packet capture)                    │
│  ✓ Engine (detection/deception)                │
│  ✓ Verification (multi-path checks)            │
│  ✓ Database (threat logs)                      │
│  ✗ NO production credentials                   │
│  ✗ NO real user data stored                    │
└─────────────────────────────────────────────────┘
         │
         │ Network isolation
         ↓
┌─────────────────────────────────────────────────┐
│  Trust Zone 3: Honeypot                        │
│  Zero trust - Exposed to attackers             │
│  ✗ NO real data                                │
│  ✗ NO real credentials                         │
│  ✗ NO access to other zones                    │
│  ✓ All fake data                               │
│  ✓ Fully isolated                              │
│  ✓ Disposable                                  │
└─────────────────────────────────────────────────┘
         │
         │ Internet
         ↓
    [Attackers]
```

### Defense in Depth

**Layer 1: Network**
- Firewall rules blocking honeypot → host
- Separate Docker networks
- Network namespace isolation for VPNs

**Layer 2: Container**
- AppArmor/SELinux profiles
- Capability dropping (CAP_DROP=ALL)
- Read-only filesystems
- Resource limits (CPU, memory, disk I/O)

**Layer 3: Application**
- Input validation on all APIs
- SQL injection prevention (parameterized queries)
- XSS prevention (output encoding)
- CSRF protection
- Rate limiting

**Layer 4: Data**
- Encryption at rest (database)
- Encryption in transit (TLS for APIs)
- Credential separation (no production creds in containers)
- Audit logging (tamper-evident)

**Layer 5: Operational**
- Regular security updates
- Vulnerability scanning
- Penetration testing
- Incident response procedures

### Credential Management

```
Production Credentials (Real):
├─ VPN username/password
│  Location: Host machine only
│  Access: Mounted read-only into verification container
│  Security: Never logged, never exposed
│
├─ Database password
│  Location: Docker secrets or environment
│  Access: Engine and postgres containers only
│  Security: Rotated regularly
│
└─ API keys (if any)
   Location: Configuration file (host)
   Access: Mounted read-only

Fake Credentials (Honeypot):
├─ SSH passwords (intentionally weak)
├─ Database credentials (fake)
└─ Honeytokens (tracked)
   - Embedded in fake data
   - Unique identifiers
   - Alert if used elsewhere
```

### Audit Trail

All security events logged:
```
1. Packet capture events (Redis stream - 24h retention)
2. Attack detections (PostgreSQL - permanent)
3. Verification requests (PostgreSQL - permanent)
4. Deception activations (PostgreSQL - permanent)
5. Honeypot interactions (PostgreSQL - permanent)
6. API calls (Application logs - 30d retention)
7. Container events (Docker logs - 7d retention)
```

Logs are:
- Structured (JSON format)
- Timestamped (UTC)
- Source-identified (component, container)
- Tamper-evident (PostgreSQL transaction log)

---

## Scalability

### Vertical Scaling

**Single-host deployment** (current design):
- Monitor: 1 CPU core, 512MB RAM → 10K pkt/s
- Engine: 2 CPU cores, 2GB RAM → 100 req/s
- Verification: 4 CPU cores, 4GB RAM → 10 VPNs
- Database: 2 CPU cores, 2GB RAM → 10K queries/s

**Scaling up**:
- Monitor: Can handle 100K pkt/s with 4 cores, 2GB RAM
- Verification: Add more VPN namespaces (20, 30, etc.)

### Horizontal Scaling

**Multi-host deployment** (future):
```
┌─────────────────────────────────────────┐
│  Host 1: Capture & Detection            │
│  ├─ Monitor (packet capture)            │
│  └─ Engine (detection)                  │
└─────────────────────────────────────────┘
         ↓ (Redis)
┌─────────────────────────────────────────┐
│  Host 2: Verification Cluster           │
│  ├─ Verification instance 1 (10 VPNs)   │
│  ├─ Verification instance 2 (10 VPNs)   │
│  └─ Verification instance 3 (10 VPNs)   │
│  Total: 30 VPNs × 4 = 120 paths         │
└─────────────────────────────────────────┘
         ↓ (PostgreSQL)
┌─────────────────────────────────────────┐
│  Host 3: Data & Deception               │
│  ├─ PostgreSQL (threat database)        │
│  ├─ Deception engine                    │
│  └─ Honeypot farm (multiple instances)  │
└─────────────────────────────────────────┘
```

**Load Balancing**:
- Multiple verification containers behind load balancer
- Round-robin or least-connections strategy
- Each verification instance independent

**Distributed Honeypots**:
- Deploy honeypots on different IPs/subnets
- Central logging to shared database
- Coordinated deception strategies

### Performance Optimization

**Packet Capture**:
- Use AF_PACKET instead of pcap for zero-copy
- Ring buffers to prevent packet loss
- BPF filters to reduce irrelevant traffic
- Multi-threaded parsing

**Verification**:
- Cache verification results (5 min TTL)
- Concurrent path execution (asyncio)
- Connection pooling
- Fastest-path selection strategy

**Database**:
- Indexes on frequently queried fields
- Partitioning by timestamp (time-series data)
- Connection pooling
- Read replicas for queries

**Deception**:
- Pre-generated fake data templates
- Reusable behavior patterns
- Asynchronous packet sending

---

## Technology Choices & Rationale

### Why Go for Packet Capture?
- **Performance**: 60K pkt/s vs Python's 1K pkt/s
- **Low latency**: GC pauses < 1ms
- **Concurrency**: Goroutines for parallel processing
- **Memory safety**: No segfaults

### Why Python for Orchestration?
- **Rich ecosystem**: Scapy, ML libraries, web frameworks
- **Fast development**: Complex logic easier to implement
- **Integration**: Easy to integrate external tools
- **Flexibility**: Dynamic typing for rapid iteration

### Why Docker?
- **Isolation**: Strong container boundaries
- **Reproducibility**: Same environment everywhere
- **Resource limits**: Prevent resource exhaustion
- **Deployment**: Easy to deploy and scale

### Why Redis?
- **Speed**: In-memory, microsecond latency
- **Pub/Sub**: Built-in event streaming
- **Simple**: Easy to integrate
- **Lightweight**: Minimal overhead

### Why PostgreSQL?
- **JSONB**: Flexible schema for varied threat data
- **ACID**: Strong consistency for audit logs
- **Performance**: Good for time-series data
- **Extensions**: PostGIS, pg_cron, etc.

---

## Future Enhancements

### Machine Learning Integration
- Anomaly detection using behavioral analysis
- Traffic pattern learning
- Attacker fingerprinting
- False positive reduction

### Distributed Deployment
- Kubernetes orchestration
- Multi-region verification
- Cloud-native architecture
- Auto-scaling

### Advanced Deception
- AI-generated fake content
- Realistic chatbot honeypots
- Dynamic honeypot morphing
- Attacker-adaptive responses

### Threat Intelligence
- Integration with threat feeds (STIX/TAXII)
- Automated IOC generation
- Collaborative defense (share anonymized data)
- Attribution analysis

---

## Conclusion

This architecture provides:
✅ **Defense in depth** through multiple layers
✅ **High confidence detection** via 40 independent verification paths
✅ **Stealth operation** that doesn't alert attackers
✅ **Active defense** through realistic deception
✅ **Comprehensive intelligence** gathering
✅ **Scalable design** from single host to distributed
✅ **Strong isolation** between trust zones
✅ **Performance** sufficient for home and SMB networks

The system is designed to be:
- **Secure by default**
- **Observable** (comprehensive logging)
- **Maintainable** (clear separation of concerns)
- **Extensible** (modular architecture)
- **Testable** (component isolation)
