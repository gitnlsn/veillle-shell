# NLSN PCAP Monitor - Implementation Plan

**Document Version:** 2025-11-10
**Architecture:** CLI-First (v2.0)
**Total Duration:** 20 weeks (~480 hours)

---

## Overview

This implementation plan follows a **bottom-up, incremental approach**:

1. Start with basics (packet capture)
2. Add parsing layer
3. Implement detection
4. Add verification
5. Polish and extend

Each phase delivers a **working, usable tool** - no "big bang" release.

---

## Phase 1: Foundation - Packet Capture & Basic DNS Detection

**Duration:** 4 weeks (96 hours)
**Goal:** Working CLI that captures packets and detects DNS hijacking
**Deliverable:** `nlsn-monitor` binary that can detect basic attacks

### Week 1: CLI Framework & Packet Capture (24 hours)

#### Tasks

**1.1 Project Setup (4 hours)**
- Initialize new Go module structure
- Set up development environment
- Add dependencies (gopacket, cobra, viper)
- Create basic directory structure

```
nlsn-monitor/
├── cmd/
│   └── nlsn-monitor/
│       └── main.go
├── internal/
│   ├── capture/
│   ├── parser/
│   ├── detector/
│   ├── storage/
│   └── config/
├── pkg/
│   └── types/
├── configs/
│   └── config.example.yaml
├── go.mod
├── go.sum
├── Makefile
└── README.md
```

**1.2 CLI Framework (8 hours)**
- Implement command structure using Cobra
- Add global flags (--config, --interface, --verbose)
- Configuration loading (YAML → env → flags)
- Logging setup (structured logging with zerolog)
- Version command

```go
// cmd/nlsn-monitor/main.go
package main

import (
    "github.com/spf13/cobra"
    "nlsn-monitor/internal/config"
)

var rootCmd = &cobra.Command{
    Use:   "nlsn-monitor",
    Short: "Network security monitoring tool",
}

var startCmd = &cobra.Command{
    Use:   "start",
    Short: "Start monitoring network traffic",
    Run:   runStart,
}

func main() {
    rootCmd.Execute()
}
```

**1.3 Packet Capture Engine (12 hours)**
- Interface detection and selection
- libpcap wrapper using gopacket
- BPF filter implementation
- Packet buffering
- Signal handling (graceful shutdown)
- Basic packet statistics

```go
// internal/capture/capture.go
type Capturer struct {
    handle      *pcap.Handle
    packetChan  chan gopacket.Packet
    stats       *Statistics
}

func New(iface string, snaplen int, promisc bool) (*Capturer, error)
func (c *Capturer) Start() error
func (c *Capturer) Stop() error
func (c *Capturer) Packets() <-chan gopacket.Packet
```

**Deliverables:**
- Working CLI that captures packets
- Counts packets by protocol
- Prints basic statistics
- Handles Ctrl+C gracefully

**Test:**
```bash
sudo nlsn-monitor start --interface en0
# Should see: "Capturing on interface en0..."
# Ctrl+C: "Captured 1234 packets (567 DNS, 345 HTTP, 322 TLS)"
```

---

### Week 2: DNS Parser & Storage (24 hours)

#### Tasks

**2.1 DNS Protocol Parser (12 hours)**
- DNS packet structure parsing
- Query extraction (domain, type, class)
- Response parsing (IPs, CNAME, TTL)
- NXDOMAIN handling
- Compression pointer resolution
- Error handling for malformed packets

```go
// internal/parser/dns.go
type DNSPacket struct {
    TransactionID uint16
    IsQuery       bool
    IsResponse    bool
    QueryDomain   string
    QueryType     uint16
    ResponseIPs   []net.IP
    ResponseCode  uint8
    TTL           uint32
    ServerIP      net.IP
    Timestamp     time.Time
}

func ParseDNS(packet gopacket.Packet) (*DNSPacket, error)
```

**2.2 Unit Tests (4 hours)**
- Test cases for DNS parsing
- Malformed packet handling
- Edge cases (empty responses, long domains)

**2.3 SQLite Storage (8 hours)**
- Database schema creation
- Connection pooling
- Insert/query operations
- Migrations system (simple version tracking)

```go
// internal/storage/sqlite.go
type Store struct {
    db *sql.DB
}

func New(path string) (*Store, error)
func (s *Store) SavePacket(pkt *parser.DNSPacket) error
func (s *Store) GetThreatsByTime(start, end time.Time) ([]Threat, error)
```

**Deliverables:**
- DNS packets parsed and displayed
- Data stored in SQLite
- Query command to view stored data

**Test:**
```bash
sudo nlsn-monitor start --interface en0
# Let it run for a minute
# In another terminal:
nlsn-monitor threats list
# Should show DNS packets captured
```

---

### Week 3: DNS Hijacking Detection (24 hours)

#### Tasks

**3.1 Detection Engine Framework (8 hours)**
- Detector interface definition
- Detection pipeline (parser → detector → storage)
- Threat scoring system (0-100)
- Alert thresholds

```go
// internal/detector/detector.go
type Detector interface {
    Name() string
    Type() string
    Detect(packet interface{}) (*Threat, error)
}

type Threat struct {
    ID          string
    Type        string
    Severity    string
    Confidence  int
    Source      net.IP
    Target      string
    Details     map[string]interface{}
    Timestamp   time.Time
}
```

**3.2 DNS Hijack Detector (12 hours)**
- Baseline DNS server tracking
- Unexpected DNS server detection
- Response IP validation (GeoIP check)
- Low TTL detection (<60s)
- Multiple A record responses (suspicious)
- Cache poisoning indicators

```go
// internal/detector/dns_hijack.go
type DNSHijackDetector struct {
    knownServers   map[string]bool
    domainBaseline map[string][]net.IP
}

func (d *DNSHijackDetector) Detect(pkt *parser.DNSPacket) (*Threat, error)
```

**3.3 Real-time Alerting (4 hours)**
- Console output formatting
- Colored output for severity levels
- JSON output option
- Alert suppression (don't spam same threat)

**Deliverables:**
- Working DNS hijacking detection
- Real-time alerts on console
- Threats stored in database

**Test:**
```bash
# Simulate DNS hijacking using /etc/hosts or local DNS server
echo "93.184.216.34 google.com" | sudo tee -a /etc/hosts

sudo nlsn-monitor start --interface en0 --verbose
# Try to access google.com
# Should see: "⚠️  DNS HIJACK DETECTED: google.com → 93.184.216.34 (unexpected IP)"
```

---

### Week 4: Testing, Documentation, & Polish (24 hours)

#### Tasks

**4.1 Integration Testing (8 hours)**
- End-to-end test scenarios
- Attack simulation scripts
- Performance benchmarking
- Memory/CPU profiling

**4.2 Configuration System (6 hours)**
- Sample config file with comments
- Config validation
- Environment variable support
- XDG Base Directory compliance

```yaml
# ~/.config/nlsn-pcap/config.yaml
version: "2.0"

capture:
  interface: "auto"
  snaplen: 65535
  promisc: true
  buffer_size: 10485760

detection:
  enabled: true
  min_confidence: 50

storage:
  type: "sqlite"
  path: "~/.local/share/nlsn-pcap/nlsn.db"
  retention_days: 30

logging:
  level: "info"
  file: "~/.local/share/nlsn-pcap/logs/nlsn.log"
```

**4.3 Documentation (6 hours)**
- README with installation instructions
- Usage examples
- Configuration reference
- Troubleshooting guide

**4.4 Build & Release (4 hours)**
- Makefile for common tasks
- Cross-compilation (Linux, macOS)
- Release packaging
- Installation script

**Deliverables:**
- Stable v0.1.0 release
- Complete documentation
- Installation instructions

**Acceptance Criteria:**
```bash
# Install
curl -sSL https://example.com/install.sh | bash

# Configure
nlsn-monitor config init  # Creates default config

# Run
sudo nlsn-monitor start

# Query
nlsn-monitor threats list --severity high

# Export
nlsn-monitor threats export --format json > threats.json
```

---

## Phase 2: HTTP/TLS Parsing & SSL Stripping Detection

**Duration:** 4 weeks (96 hours)
**Goal:** Detect HTTPS downgrade attacks
**Deliverable:** Detection of SSL stripping and weak crypto

### Week 5: HTTP Protocol Parser (24 hours)

#### Tasks

**5.1 HTTP Request Parser (12 hours)**
- HTTP method, URI, version parsing
- Header extraction
- Host detection
- Cookie handling
- Content-Length/Transfer-Encoding

**5.2 HTTP Response Parser (8 hours)**
- Status code extraction
- Header parsing
- Redirect detection (Location header)
- Set-Cookie handling

**5.3 Integration (4 hours)**
- Add HTTP to capture BPF filter
- HTTP packet detection
- Storage schema updates
- Display HTTP traffic

**Deliverables:**
- HTTP requests/responses parsed
- Displayed in console with detail level
- Stored in database

**Test:**
```bash
sudo nlsn-monitor start --filter http
curl http://example.com
# Should see HTTP request/response logged
```

---

### Week 6: TLS Protocol Parser (24 hours)

#### Tasks

**6.1 TLS Handshake Parser (16 hours)**
- ClientHello parsing
- ServerHello parsing
- SNI (Server Name Indication) extraction
- Cipher suite identification
- TLS version detection
- Certificate parsing (basic)

**6.2 Certificate Validation (8 hours)**
- Certificate chain extraction
- Expiry date checking
- Self-signed detection
- CA verification (optional)

**Deliverables:**
- TLS handshakes parsed
- Cipher suites identified
- Certificates extracted

**Test:**
```bash
sudo nlsn-monitor start --filter tls
curl https://example.com
# Should see: "TLS 1.3 handshake, SNI: example.com, Cipher: TLS_AES_128_GCM_SHA256"
```

---

### Week 7: SSL Stripping Detection (24 hours)

#### Tasks

**7.1 HTTPS Domain Database (4 hours)**
- List of HTTPS-only domains (HSTS preload list)
- Domain classification
- Periodic updates

**7.2 SSL Strip Detector (12 hours)**
- HTTP on HTTPS-expected domain
- Missing HSTS header
- Protocol downgrade (TLS 1.3 → 1.0)
- Redirect to HTTP

```go
// internal/detector/ssl_strip.go
type SSLStripDetector struct {
    httpsOnlyDomains map[string]bool
    hstsCache        map[string]time.Time
}

func (d *SSLStripDetector) Detect(pkt interface{}) (*Threat, error)
```

**7.3 Weak Crypto Detector (8 hours)**
- TLS 1.0/1.1 usage
- Weak cipher suites (RC4, DES, 3DES, NULL)
- Export-grade crypto
- Self-signed certificates

**Deliverables:**
- SSL stripping detected
- Weak crypto alerts
- High-confidence scoring

**Test:**
```bash
# Set up local proxy that strips SSL
sudo nlsn-monitor start
# Visit bank website through proxy
# Should see: "🚨 CRITICAL: SSL STRIP detected for bank.com"
```

---

### Week 8: Multi-Protocol Integration (24 hours)

#### Tasks

**8.1 Unified Threat View (8 hours)**
- Combine DNS, HTTP, TLS threats
- Correlation between protocols
- Timeline view

**8.2 Pattern Configuration (8 hours)**
- External pattern definitions (YAML)
- User-defined detection rules
- Pattern hot-reload

```yaml
# ~/.config/nlsn-pcap/patterns.yaml
patterns:
  - name: "Custom DNS Block"
    type: "dns_hijack"
    severity: "high"
    conditions:
      - field: "dns.server"
        operator: "equals"
        value: "192.168.1.1"
    actions:
      - alert
```

**8.3 Performance Optimization (8 hours)**
- Packet processing pipeline optimization
- Database batch writes
- Memory pooling
- CPU profiling

**Deliverables:**
- Multi-protocol detection working
- Custom patterns supported
- Performance improvements (>5000 pkt/s)

---

## Phase 3: Multi-Path Verification

**Duration:** 4 weeks (96 hours)
**Goal:** Verify threats through independent network paths
**Deliverable:** Sequential VPN-based verification

### Week 9: VPN Management (24 hours)

#### Tasks

**9.1 OpenVPN Integration (12 hours)**
- VPN config parsing (.ovpn files)
- VPN connection management
- Connection health checking
- Auto-reconnect logic

```go
// internal/vpn/openvpn.go
type VPNConnection struct {
    Name   string
    Config string
    Status ConnectionStatus
}

func Connect(configPath string) (*VPNConnection, error)
func (v *VPNConnection) IsConnected() bool
func (v *VPNConnection) Disconnect() error
```

**9.2 VPN Pool Manager (8 hours)**
- Multiple VPN configuration loading
- Connection pooling
- Round-robin selection
- Failure handling

**9.3 Network Route Management (4 hours)**
- Route-specific traffic through VPN
- DNS over VPN
- Cleanup on disconnect

**Deliverables:**
- VPN connections managed programmatically
- Pool of 3-5 VPNs ready for verification

---

### Week 10: Sequential Verification (24 hours)

#### Tasks

**10.1 HTTP Client with VPN Routing (12 hours)**
- HTTP client that uses specific VPN
- DNS resolution through VPN
- Request execution
- Response capture (headers + body)

```go
// internal/verification/verifier.go
type Verifier struct {
    vpnPool *vpn.Pool
}

func (v *Verifier) VerifyURL(url string, pathCount int) (*VerificationResult, error)
```

**10.2 Response Comparison (8 hours)**
- SHA256 hashing of responses
- Header normalization (ignore timestamps, etc.)
- Content comparison
- Majority voting

**10.3 Verification Trigger (4 hours)**
- Auto-trigger on high-confidence threat
- Manual verification command
- Result storage

**Deliverables:**
- Sequential verification through multiple VPNs
- Attack confirmation/denial
- Updated threat records

**Test:**
```bash
# Detect threat
sudo nlsn-monitor start

# Manual verification
nlsn-monitor verify --url https://bank.com --paths 5
# Should see: "Verifying through 5 paths... Path 1/5 (NordVPN-US)... MATCH"
```

---

### Week 11: Verification Caching & Optimization (24 hours)

#### Tasks

**11.1 Verification Cache (8 hours)**
- Cache results (5-minute TTL)
- Avoid redundant verifications
- Cache invalidation

**11.2 Parallel Verification (Optional) (12 hours)**
- Goroutine-based parallel requests
- Timeout handling
- Result aggregation

**11.3 Verification API Client (4 hours)**
- Optional: Call external verification container
- API client for docker verification service
- Fallback to sequential if unavailable

**Deliverables:**
- Fast verification (<30s for 5 paths)
- Cached results
- Optional parallel mode

---

### Week 12: Testing & Documentation (24 hours)

#### Tasks

**12.1 Integration Testing (12 hours)**
- Test verification accuracy
- False positive rate measurement
- MITM simulation

**12.2 Documentation (8 hours)**
- Verification usage guide
- VPN setup instructions
- Troubleshooting

**12.3 Performance Tuning (4 hours)**
- Optimize VPN connection setup
- Reduce verification latency

---

## Phase 4: Deception & Automation

**Duration:** 4 weeks (96 hours)
**Goal:** Automated fake traffic generation
**Deliverable:** Deception engine that misleads attackers

### Week 13-14: Behavior Simulation (48 hours)

#### Tasks

- Realistic browser behavior simulation
- Fake credential generation
- Session management
- Traffic patterns (timing, size)

*(Detailed breakdown available upon request)*

---

### Week 15-16: Automated Response (48 hours)

#### Tasks

- Auto-activate deception on confirmed threat
- Parallel real/fake traffic
- Attack surface expansion
- Intelligence gathering

*(Detailed breakdown available upon request)*

---

## Phase 5: Polish & Advanced Features

**Duration:** 4 weeks (96 hours)
**Goal:** Production-ready tool
**Deliverable:** v1.0 release

### Week 17: Terminal UI (24 hours)

#### Tasks

**17.1 Interactive Dashboard (16 hours)**
- Real-time packet stats
- Threat timeline
- Live threat list
- Keyboard navigation

Using `tview` or `bubbletea`:

```
┌─ NLSN Monitor ──────────────────────────────────────────────────────┐
│ Status: Running  Interface: en0  Uptime: 2h 34m                     │
├─────────────────────────────────────────────────────────────────────┤
│ Packets Captured: 45,234  DNS: 12,456  HTTP: 8,901  TLS: 23,877    │
├─ Recent Threats ────────────────────────────────────────────────────┤
│ [CRITICAL] 14:23:45  SSL Strip    bank.com                          │
│ [HIGH]     14:22:10  DNS Hijack   google.com → 1.2.3.4              │
│ [MEDIUM]   14:20:33  Weak Crypto  TLS 1.0 to api.example.com        │
├─ Commands ──────────────────────────────────────────────────────────┤
│ [q] Quit  [v] Verify  [d] Details  [e] Export  [h] Help             │
└─────────────────────────────────────────────────────────────────────┘
```

**17.2 Detail Views (8 hours)**
- Threat detail popup
- Packet inspector
- Verification results display

**Deliverables:**
- TUI mode: `nlsn-monitor start --tui`

---

### Week 18: Export & Integration (24 hours)

#### Tasks

**18.1 Export Formats (12 hours)**
- JSON export (full schema)
- CSV export (simplified)
- PCAP export (filtered packets)
- HTML report generation

**18.2 Integration Features (12 hours)**
- Webhook support (send alerts to external systems)
- Syslog output
- SIEM integration (Splunk, ELK)
- API server mode (optional HTTP API)

**Deliverables:**
```bash
nlsn-monitor threats export --format json --output threats.json
nlsn-monitor capture export --filter "threat_id=123" --output attack.pcap
nlsn-monitor serve --port 8080  # Start API server
```

---

### Week 19: Testing & Benchmarking (24 hours)

#### Tasks

**19.1 Comprehensive Testing (16 hours)**
- Unit test coverage >80%
- Integration test suite
- Attack simulation toolkit
- Fuzzing (packet parser)

**19.2 Performance Benchmarking (8 hours)**
- Packet processing throughput
- Memory usage profiling
- CPU usage optimization
- Latency measurements

**Deliverables:**
- Test coverage report
- Performance benchmarks documented

---

### Week 20: Documentation & Release (24 hours)

#### Tasks

**20.1 Documentation (16 hours)**
- Complete user manual
- Architecture documentation
- API reference (if API mode enabled)
- Video tutorials (optional)

**20.2 Release Preparation (8 hours)**
- Semantic versioning
- Changelog
- Release notes
- Homebrew formula / DEB package / RPM package

**Deliverables:**
- v1.0.0 release
- Published on GitHub
- Installation via package managers

---

## Milestones & Checkpoints

| Milestone | Week | Deliverable | Success Criteria |
|-----------|------|-------------|------------------|
| **M1: MVP** | 4 | DNS detection working | Detects DNS hijacking with 90% accuracy |
| **M2: Protocol Coverage** | 8 | HTTP/TLS detection | Detects SSL stripping and weak crypto |
| **M3: Verification** | 12 | Multi-path verification | Confirms MITM with <5% false positives |
| **M4: Automation** | 16 | Deception engine | Generates realistic fake traffic |
| **M5: Production** | 20 | v1.0 release | Stable, documented, packaged |

---

## Risk Management

### Technical Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| VPN integration complexity | High | Medium | Start with sequential, defer parallel |
| Packet parsing errors | Medium | High | Extensive testing, fuzzing |
| Performance bottlenecks | Medium | Medium | Profile early, optimize iteratively |
| False positives | High | High | Adjustable thresholds, verification |

### Schedule Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Scope creep | Medium | High | Stick to phased approach |
| Testing time underestimated | High | Medium | Allocate buffer time |
| VPN delays | Medium | Medium | Use stub VPN for development |

---

## Development Practices

### Version Control

- Feature branches: `feature/dns-parser`, `feature/ssl-strip-detection`
- Main branch always buildable
- Semantic versioning: `v0.1.0` → `v0.2.0` → ... → `v1.0.0`

### Testing Strategy

- **Unit tests**: Each parser, detector, storage function
- **Integration tests**: End-to-end detection scenarios
- **Performance tests**: Benchmark critical paths
- **Regression tests**: Previous bugs don't return

### Code Quality

- `golangci-lint` for linting
- `gofmt` for formatting
- Code reviews (self or peer)
- Documentation for public APIs

### Continuous Integration

```yaml
# .github/workflows/ci.yml
name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-go@v2
      - run: make test
      - run: make lint
```

---

## Success Metrics

### Phase 1 Success Criteria
- ✅ Captures 10,000+ packets/sec
- ✅ Detects DNS hijacking with >90% accuracy
- ✅ <5% false positive rate
- ✅ Clean installation process
- ✅ Documentation complete

### Overall Project Success
- ✅ All 5 phases completed
- ✅ v1.0 released
- ✅ 100+ GitHub stars
- ✅ Used by security community
- ✅ Positive feedback

---

## Next Steps

1. **Review this plan** - Ensure alignment with goals
2. **Start Phase 1** - Begin with Week 1 tasks
3. **Setup dev environment** - Go, libpcap, editors
4. **Create repository** - Initialize Git repo
5. **Write first code** - CLI framework (Week 1.2)

**Ready to begin?** See `PHASE1-BASICS.md` for detailed Week 1 tasks.
