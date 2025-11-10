# NLSN PCAP Monitor - CLI-First Architecture

**Document Version:** 2025-11-10
**Architecture Version:** 2.0 (CLI-First)
**Status:** Active Development

---

## Overview

This document describes the revised CLI-first architecture for NLSN PCAP Monitor. This represents a shift from the original microservices design to a simpler, more Unix-like tool that prioritizes user control, composability, and ease of deployment.

## Design Philosophy

### Core Principles

1. **Unix Philosophy**
   - Do one thing well: network security monitoring
   - Composable with other tools via pipes and files
   - Text-based configuration and output
   - Fail gracefully with clear error messages

2. **User Control**
   - User decides when to start/stop monitoring
   - Explicit rather than implicit behavior
   - Transparent operation (no hidden background services)
   - Configurable via flags and config files

3. **Simplicity First**
   - Single binary deployment (Go)
   - Minimal dependencies (libpcap only)
   - SQLite for storage (no external database server)
   - Progressive complexity (start simple, add features incrementally)

4. **File-Based Integration**
   - Standard config location: `~/.config/nlsn-pcap/`
   - Standard data location: `~/.local/share/nlsn-pcap/`
   - Export formats: JSON, CSV, PCAP
   - Log files for debugging

---

## Architecture Layers

The system is built in distinct layers, each with clear responsibilities:

```
┌─────────────────────────────────────────────────────────────┐
│  Layer 5: CLI Interface                                     │
│  - Flag parsing (--interface, --config, --verbose)          │
│  - Configuration loading                                     │
│  - Output formatting (stdout, logs, files)                  │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│  Layer 4: Detection Engine                                  │
│  - Pattern matching (DNS hijack, SSL strip, etc.)           │
│  - Scoring (suspicion levels 0-100)                         │
│  - Multi-path verification trigger                          │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│  Layer 3: Protocol Parsers                                  │
│  - DNS parser (queries, responses, NXDOMAIN)                │
│  - HTTP parser (requests, responses, headers)               │
│  - TLS parser (handshakes, certs, ciphers)                  │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│  Layer 2: Packet Capture                                    │
│  - libpcap interface                                        │
│  - BPF filtering                                            │
│  - Packet buffering                                         │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│  Layer 1: Network Interface                                 │
│  - Raw packet access (requires root/CAP_NET_RAW)            │
│  - Interface detection                                      │
└─────────────────────────────────────────────────────────────┘
```

### Layer Dependencies

Each layer depends only on the layer below it:
- **Layer 1 → Layer 2**: Packet capture reads from network interface
- **Layer 2 → Layer 3**: Parsers receive raw packet bytes
- **Layer 3 → Layer 4**: Detection works on parsed protocol data
- **Layer 4 → Layer 5**: CLI formats and outputs detection results

This separation allows for:
- Independent testing of each layer
- Easy addition of new protocols (add to Layer 3)
- New detection patterns (add to Layer 4)
- Different output formats (modify Layer 5)

---

## Component Architecture

### 1. CLI Binary (`nlsn-monitor`)

**Language:** Go 1.21+
**Purpose:** Main executable for all operations
**Location:** Single binary, installed system-wide or in `~/bin/`

#### Command Structure

```bash
nlsn-monitor [command] [flags]

Commands:
  start       Start monitoring (default command)
  capture     Capture packets to file
  analyze     Analyze existing PCAP file
  verify      Verify URL through multiple paths
  threats     Query threat database
  config      Manage configuration
  version     Show version info
  help        Show help

Global Flags:
  --config, -c      Config file path (default: ~/.config/nlsn-pcap/config.yaml)
  --interface, -i   Network interface (default: auto-detect)
  --verbose, -v     Verbose output
  --quiet, -q       Quiet mode (errors only)
  --output, -o      Output format (json|text|csv)
```

#### Configuration Hierarchy

Configuration is loaded in this order (later overrides earlier):

1. Default values (hardcoded in binary)
2. System config: `/etc/nlsn-pcap/config.yaml`
3. User config: `~/.config/nlsn-pcap/config.yaml`
4. Environment variables: `NLSN_*`
5. Command-line flags

### 2. Configuration System

**Format:** YAML
**Location:** `~/.config/nlsn-pcap/`

#### Directory Structure

```
~/.config/nlsn-pcap/
├── config.yaml              # Main configuration
├── patterns.yaml            # Detection patterns
├── vpn/                     # VPN configurations (optional)
│   ├── credentials.env
│   └── configs/
│       ├── nordvpn-us.ovpn
│       ├── protonvpn-ch.ovpn
│       └── ...
└── .internal/               # Internal state (ignored by git)
    └── cache/
```

#### Main Configuration (`config.yaml`)

```yaml
# NLSN PCAP Monitor Configuration
version: "2.0"

# Capture settings
capture:
  interface: "auto"              # Auto-detect or specify (e.g., "en0")
  snaplen: 65535                 # Bytes to capture per packet
  promisc: true                  # Promiscuous mode
  buffer_size: 10485760          # 10MB buffer

# Detection settings
detection:
  enabled: true
  patterns_file: "patterns.yaml" # External pattern definitions
  min_confidence: 50             # Minimum score to trigger alert (0-100)

# Verification settings (optional)
verification:
  enabled: false                 # Multi-path verification
  mode: "sequential"             # sequential|parallel
  paths: 5                       # Number of paths to use
  timeout: 30                    # Seconds per verification

# Storage settings
storage:
  type: "sqlite"                 # sqlite|postgres|none
  path: "~/.local/share/nlsn-pcap/nlsn.db"
  retention_days: 30             # Auto-delete old data

# Logging settings
logging:
  level: "info"                  # debug|info|warn|error
  file: "~/.local/share/nlsn-pcap/logs/nlsn.log"
  max_size_mb: 100
  max_backups: 5

# Output settings
output:
  format: "text"                 # text|json|csv
  realtime: true                 # Print detections as they occur
  export_dir: "~/.local/share/nlsn-pcap/exports/"
```

### 3. Data Storage

**Primary:** SQLite database
**Location:** `~/.local/share/nlsn-pcap/`

#### Directory Structure

```
~/.local/share/nlsn-pcap/
├── nlsn.db                  # Main SQLite database
├── logs/
│   ├── nlsn.log             # Application logs
│   └── nlsn.log.1           # Rotated logs
├── exports/                 # Exported data
│   ├── threats-2025-11-10.json
│   └── capture-2025-11-10.pcap
└── cache/                   # Temporary data
    └── verification-cache.db
```

#### Database Schema

```sql
-- Captured packets (summary)
CREATE TABLE packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME NOT NULL,
    protocol TEXT NOT NULL,           -- dns|http|tls|arp
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    src_port INTEGER,
    dst_port INTEGER,
    size INTEGER,
    metadata JSON,                     -- Protocol-specific data
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Detected threats
CREATE TABLE threats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME NOT NULL,
    type TEXT NOT NULL,                -- dns_hijack|ssl_strip|mitm|arp_spoof
    severity TEXT NOT NULL,            -- low|medium|high|critical
    confidence INTEGER NOT NULL,       -- 0-100
    source_ip TEXT,
    target TEXT,                       -- Domain, URL, or IP being attacked
    details JSON,                      -- Attack-specific details
    verified BOOLEAN DEFAULT FALSE,    -- Multi-path verification result
    verification_data JSON,            -- Verification details
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Verification results (if multi-path enabled)
CREATE TABLE verifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_id INTEGER,
    url TEXT NOT NULL,
    paths_total INTEGER,
    paths_succeeded INTEGER,
    consensus_hash TEXT,               -- Hash of majority response
    divergent_hashes TEXT,             -- JSON array of different hashes
    confidence TEXT,                   -- HIGH|MEDIUM|LOW
    attack_detected BOOLEAN,
    details JSON,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (threat_id) REFERENCES threats(id)
);

-- System statistics
CREATE TABLE stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME NOT NULL,
    packets_captured INTEGER,
    packets_analyzed INTEGER,
    threats_detected INTEGER,
    verifications_run INTEGER,
    uptime_seconds INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX idx_packets_timestamp ON packets(timestamp);
CREATE INDEX idx_packets_protocol ON packets(protocol);
CREATE INDEX idx_threats_timestamp ON threats(timestamp);
CREATE INDEX idx_threats_type ON threats(type);
CREATE INDEX idx_threats_severity ON threats(severity);
```

### 4. Protocol Parsers

Each parser is a Go package that:
- Receives raw packet bytes
- Extracts protocol-specific fields
- Returns structured data
- Handles errors gracefully

#### DNS Parser (`pkg/parser/dns`)

```go
type DNSPacket struct {
    TransactionID uint16
    IsQuery       bool
    IsResponse    bool
    Opcode        uint8
    QueryDomain   string
    ResponseIPs   []net.IP
    ResponseCode  uint8
    TTL           uint32
    AuthServer    net.IP
    Timestamp     time.Time
}

func ParseDNS(data []byte) (*DNSPacket, error)
```

#### HTTP Parser (`pkg/parser/http`)

```go
type HTTPRequest struct {
    Method      string
    URI         string
    Host        string
    Headers     map[string]string
    IsHTTPS     bool
    Timestamp   time.Time
}

type HTTPResponse struct {
    StatusCode  int
    Headers     map[string]string
    Redirects   []string
    Timestamp   time.Time
}

func ParseHTTPRequest(data []byte) (*HTTPRequest, error)
func ParseHTTPResponse(data []byte) (*HTTPResponse, error)
```

#### TLS Parser (`pkg/parser/tls`)

```go
type TLSHandshake struct {
    Version         uint16
    SNI             string
    CipherSuites    []uint16
    Certificate     *x509.Certificate
    IsClientHello   bool
    IsServerHello   bool
    Timestamp       time.Time
}

func ParseTLS(data []byte) (*TLSHandshake, error)
```

### 5. Detection Engine

**Purpose:** Identify network attacks based on parsed packet data
**Location:** `pkg/detector/`

#### Detection Pattern Structure

Patterns are defined in `~/.config/nlsn-pcap/patterns.yaml`:

```yaml
patterns:
  - name: "DNS Hijacking"
    type: "dns_hijack"
    severity: "high"
    description: "Unexpected DNS server or response manipulation"
    conditions:
      - field: "dns.response_ip"
        operator: "not_in"
        value: "known_servers.txt"
      - field: "dns.ttl"
        operator: "less_than"
        value: 60
    actions:
      - alert
      - verify_multi_path

  - name: "SSL Stripping"
    type: "ssl_strip"
    severity: "critical"
    description: "HTTPS downgraded to HTTP"
    conditions:
      - field: "http.protocol"
        operator: "equals"
        value: "http"
      - field: "http.host"
        operator: "in"
        value: "https_expected_domains.txt"
    actions:
      - alert
      - verify_multi_path
```

#### Detector Interface

```go
type Detector interface {
    Name() string
    Detect(packet ParsedPacket) (*Threat, error)
}

type Threat struct {
    Type       string
    Severity   string
    Confidence int      // 0-100
    Source     net.IP
    Target     string
    Details    map[string]interface{}
    Timestamp  time.Time
}
```

#### Built-in Detectors

1. **DNS Hijack Detector** (`pkg/detector/dns_hijack.go`)
   - Unexpected DNS server responses
   - IP address mismatches
   - Low TTL values (<60s)
   - Response timing anomalies

2. **SSL Strip Detector** (`pkg/detector/ssl_strip.go`)
   - HTTP used for known HTTPS sites
   - Missing HSTS headers
   - Protocol downgrades

3. **Weak Crypto Detector** (`pkg/detector/weak_crypto.go`)
   - TLS 1.0/1.1 usage
   - Weak cipher suites (RC4, DES, 3DES)
   - Self-signed certificates

4. **ARP Spoof Detector** (`pkg/detector/arp_spoof.go`)
   - Duplicate MAC addresses
   - IP/MAC binding changes
   - Gratuitous ARP anomalies

### 6. Multi-Path Verification (Optional)

**Purpose:** Verify suspicious activity through independent network paths
**Mode:** Sequential (simple) or Parallel (complex)

#### Sequential Mode (Default)

When a threat is detected with high confidence:

1. Extract target URL/domain
2. Make requests through 3-5 VPN connections sequentially
3. Compare responses (hash comparison)
4. Determine if MITM is present

**Implementation:** Simple, no network namespaces needed

```go
func VerifySequential(url string, vpnConfigs []string) (*VerificationResult, error) {
    results := []Response{}

    for _, vpn := range vpnConfigs {
        // Connect to VPN
        // Make request
        // Store response
        results = append(results, resp)
    }

    // Compare responses
    return CompareResponses(results)
}
```

#### Parallel Mode (Advanced - Future)

Use the existing verification-container (Docker) for 40-path parallel verification:

```bash
# User starts verification service separately
docker run -d nlsn-verification-container

# CLI calls the API when needed
nlsn-monitor verify --url https://bank.com --api http://localhost:8000
```

This keeps the CLI simple while allowing advanced users to enable powerful verification.

---

## Data Flow

### Normal Operation

```
Network Interface
       ↓
   [Packet Capture]
       ↓
   BPF Filter (DNS/HTTP/TLS)
       ↓
   [Protocol Parser]
       ↓
   Parsed Packet
       ↓
   [Detection Engine]
       ↓
  Threat? (yes/no)
       ↓
    [SQLite DB] ← Store all packets + threats
       ↓
  [CLI Output] → stdout/logs/files
```

### With Verification

```
   [Detection Engine]
       ↓
  High-confidence threat detected
       ↓
   [Verification Trigger]
       ↓
  [Multi-Path Verifier]
    ↓         ↓         ↓
  VPN-1    VPN-2    VPN-3
    ↓         ↓         ↓
  [Response Comparison]
       ↓
  MITM Confirmed? (yes/no)
       ↓
  [Update Threat Record]
       ↓
  [Alert User]
```

---

## Performance Characteristics

### Target Metrics

| Metric | Target | Notes |
|--------|--------|-------|
| Packet capture rate | 10,000 pkt/s | Sufficient for home/small office |
| Detection latency | <100ms | Per packet analysis time |
| Memory usage | <500MB | Without PCAP storage |
| CPU usage | <20% | Single core, idle network |
| Storage growth | ~100MB/day | Depends on network activity |

### Optimization Strategies

1. **BPF Filtering** - Only capture relevant packets (DNS, HTTP, TLS)
2. **Bounded Buffers** - Prevent memory exhaustion on high traffic
3. **SQLite WAL Mode** - Write-ahead logging for better performance
4. **Batch Inserts** - Group database writes
5. **Indexing** - Fast queries on timestamps and threat types

---

## Security Model

### Privilege Requirements

- **Root/CAP_NET_RAW** - Required for packet capture
- **User permissions** - Everything else runs as normal user

### Privilege Separation

```bash
# Option 1: Run entire tool as root (simple but not ideal)
sudo nlsn-monitor start

# Option 2: Grant capabilities (better)
sudo setcap cap_net_raw=eip /usr/local/bin/nlsn-monitor
nlsn-monitor start

# Option 3: Dedicated capture binary (best)
sudo nlsn-capture | nlsn-analyze  # Only capture needs root
```

### Data Protection

- **Config files**: 0600 permissions (user read/write only)
- **Database**: 0600 permissions
- **VPN credentials**: Encrypted or referenced via secrets manager
- **Logs**: Sanitized (no passwords, tokens)

---

## Comparison with Original Architecture

### What Changed

| Aspect | Original (Microservices) | New (CLI) |
|--------|-------------------------|-----------|
| Deployment | Docker Compose (6 containers) | Single binary |
| Dependencies | Redis, PostgreSQL, Docker | libpcap only |
| Operation | Always-on background service | On-demand (user-controlled) |
| Configuration | `./shared/config/` | `~/.config/nlsn-pcap/` |
| Storage | PostgreSQL | SQLite |
| Verification | 40 parallel paths (namespaces) | Sequential or optional API |
| Honeypot | Integrated | Not included (could be separate) |
| Deception | Automated | Not yet implemented |

### What Stays

- Go for performance-critical packet capture/parsing
- Python for verification (optional container)
- Multi-path verification concept (simplified)
- Detection patterns and algorithms
- Database schema (adapted for SQLite)

### Trade-offs

**Gained:**
- ✅ Simpler deployment (single binary)
- ✅ Better user control
- ✅ Easier integration with other tools
- ✅ Standard config locations
- ✅ Portable

**Lost:**
- ❌ Real-time 24/7 monitoring (user must start it)
- ❌ Automated deception (not yet implemented)
- ❌ Honeypot integration (separate component if needed)
- ❌ 40-path parallel verification (optional via API)

**Acceptable for:**
- On-demand network analysis
- Incident investigation
- Security testing
- Development/learning

**Not suitable for:**
- Enterprise SOC operations (needs always-on monitoring)
- High-scale networks (needs distributed architecture)

---

## Future Enhancements

### Phase 2+ Features

1. **TUI (Terminal UI)** - Interactive dashboard (using tview/bubbletea)
2. **HTTP API** - Optional API server for remote queries
3. **Plugins** - Extensible detector system
4. **ML Detection** - Anomaly detection using machine learning
5. **Cloud Verification** - Verify through cloud VPN providers' APIs
6. **Deception** - Automated fake traffic generation
7. **Distributed Mode** - Multiple monitors reporting to central DB

---

## Conclusion

This CLI-first architecture represents a pragmatic approach to network security monitoring:

- **Simple to deploy** - Single binary, no complex setup
- **Unix-friendly** - Composable, scriptable, understandable
- **Progressive complexity** - Start simple, add features incrementally
- **User-controlled** - Explicit operation, no surprises

The system grows with user needs: start with basic capture/detection, add verification when needed, integrate with other tools naturally.

**Next Steps:** See `IMPLEMENTATION-PLAN.md` for detailed development roadmap.
