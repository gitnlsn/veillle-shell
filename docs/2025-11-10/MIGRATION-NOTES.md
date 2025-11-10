# Migration Notes - From Microservices to CLI

**Document Version:** 2025-11-10
**Status:** Planning
**Migration Strategy:** Fresh Start (New Implementation)

---

## Overview

This document explains how the project transitions from the original microservices architecture to the new CLI-first design. It details what code can be reused, what needs to be rewritten, and how to handle the transition.

---

## Current State Analysis

### What Exists Today

Based on the gap analysis (see context from earlier research):

#### ✅ Fully Implemented (Can Reuse)

1. **Verification Container** - `verification-container/path-orchestrator.py`
   - **Status:** 100% complete, production-ready
   - **Functionality:** 40-path VPN verification with majority voting
   - **Reuse Strategy:** Keep as optional component (see below)

2. **Documentation** - `docs/` folder
   - **Status:** Complete and extensive
   - **Content:** ARCHITECTURE.md, PHASES.md, TECHNICAL_SPECS.md, etc.
   - **Reuse Strategy:** Archive, reference for algorithms/concepts

3. **Docker Infrastructure** - `docker-compose.yml`
   - **Status:** Complete orchestration
   - **Reuse Strategy:** Keep for "pro mode" (future)

#### ⚠️ Partial Implementation (Inspiration Only)

4. **Go Monitor** - `core/cmd/monitor/main.go`
   - **Status:** Basic packet capture only (~40% complete)
   - **What Works:** Interface detection, packet counting, signal handling
   - **What's Missing:** Parsing, detection, Redis publishing
   - **Reuse Strategy:** Reference implementation, rewrite for CLI

5. **Python Engine** - `engine/api/server.py`
   - **Status:** Skeleton only (~5% complete)
   - **What Works:** FastAPI structure
   - **What's Missing:** All detection, verification, deception logic
   - **Reuse Strategy:** Concepts only, not porting to CLI

#### ❌ Empty Skeletons (Start Fresh)

6. **Go Packages** - `core/pkg/*`
   - **Status:** Empty directories, no code
   - **Reuse Strategy:** Directory structure inspiration

7. **Python Modules** - `engine/detector/`, `engine/deception/`, etc.
   - **Status:** Empty `__init__.py` files only
   - **Reuse Strategy:** None (CLI won't use Python)

---

## Migration Strategy: Fresh Start

### Decision: Build New CLI from Scratch

**Rationale:**
- Current implementation is ~15% complete
- Architecture is fundamentally different
- Easier to start fresh than refactor
- Go-only implementation (no Python in CLI)

**Approach:**
```
Old Code (archive) ← Reference for algorithms
      ↓
New CLI Project ← Clean implementation
      ↓
Reuse: Concepts, patterns, documentation
Not reuse: Actual code (different architecture)
```

---

## What to Reuse

### 1. Verification Container (Keep as Optional Component)

**Decision:** Keep verification-container/ intact as separate microservice

**Rationale:**
- Already fully functional
- Multi-path verification is complex
- Network namespaces require containers
- CLI can call it via API

**Integration Options:**

#### Option A: CLI with External Verification Service
```bash
# User starts verification container separately
docker run -d -p 8000:8000 nlsn-verification-container

# CLI calls the API when needed
nlsn-monitor verify --url https://bank.com --api http://localhost:8000
```

**Pros:**
- Keep sophisticated 40-path verification
- No reimplementation needed
- Advanced users can use it

**Cons:**
- Still requires Docker for this feature
- Two-component deployment

#### Option B: CLI with Built-in Sequential Verification
```bash
# CLI does verification internally (simpler)
nlsn-monitor verify --url https://bank.com --paths 5
# Uses 5 VPNs sequentially, no namespaces
```

**Pros:**
- No Docker required
- Self-contained tool
- Simpler for users

**Cons:**
- Slower (sequential)
- Need to reimplement VPN logic

#### Option C: Hybrid (Recommended)
```bash
# CLI has built-in sequential verification
nlsn-monitor verify --url https://bank.com

# But can use external verification service if available
nlsn-monitor verify --url https://bank.com --use-verification-service
# Auto-detects if http://localhost:8000 is running
```

**Pros:**
- Works out of the box (built-in)
- Upgradeable (use service if available)
- Best of both worlds

**Recommendation:** Implement Option C

### 2. Detection Algorithms (Reuse Concepts)

**From Documentation:**
- DNS hijacking indicators (unexpected IPs, low TTL, etc.)
- SSL stripping patterns (HTTP on HTTPS sites)
- Weak crypto detection (TLS versions, cipher suites)
- ARP spoofing heuristics

**Reuse Strategy:**
- Port algorithm logic from TECHNICAL_SPECS.md
- Reimplement in Go (don't copy Python)
- Use same detection patterns and thresholds

**Example:**

Original Spec (TECHNICAL_SPECS.md):
```
DNS Hijacking Detection:
- TTL < 60 seconds → Suspicious (score: 30)
- IP not in expected range → Suspicious (score: 50)
- Multiple A records → Suspicious (score: 20)
- Combine scores → If total > 70, trigger alert
```

Go Implementation:
```go
// internal/detector/dns_hijack.go
func (d *DNSHijackDetector) scoreTTL(ttl uint32) int {
    if ttl < 60 {
        return 30 // Suspicious
    }
    return 0
}

func (d *DNSHijackDetector) scoreIP(ip net.IP) int {
    if !d.isExpectedIP(ip) {
        return 50 // Suspicious
    }
    return 0
}

func (d *DNSHijackDetector) Detect(pkt *DNSPacket) (*Threat, error) {
    score := 0
    score += d.scoreTTL(pkt.TTL)
    score += d.scoreIP(pkt.ResponseIPs[0])
    // ... more checks

    if score > 70 {
        return &Threat{Type: "dns_hijack", Confidence: score}, nil
    }
    return nil, nil
}
```

### 3. Database Schema (Adapt for SQLite)

**Original Schema:** PostgreSQL with JSONB

**Adaptation for SQLite:**

```sql
-- Original (PostgreSQL)
CREATE TABLE threats (
    id SERIAL PRIMARY KEY,
    metadata JSONB,
    ...
);

-- Adapted (SQLite)
CREATE TABLE threats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    metadata TEXT,  -- JSON as TEXT
    ...
);
```

**Reuse Strategy:**
- Keep table structure
- Change SERIAL → AUTOINCREMENT
- Change JSONB → TEXT (still store JSON)
- Remove PostgreSQL-specific features (GIS, etc.)

### 4. Configuration Schema (Simplify)

**Original:** `shared/config/settings.example.yaml`

**New:** `~/.config/nlsn-pcap/config.yaml`

**Changes:**
- Remove Docker-specific settings
- Remove Redis/PostgreSQL connection strings
- Add CLI-specific options
- Simplify structure

**Example:**

```yaml
# OLD (Microservices)
services:
  monitor:
    interface: "en0"
    redis_url: "redis://redis:6379"
  engine:
    api_port: 8888
    postgres_url: "postgresql://user:pass@postgres/nlsn"

# NEW (CLI)
capture:
  interface: "en0"
  snaplen: 65535
storage:
  type: "sqlite"
  path: "~/.local/share/nlsn-pcap/nlsn.db"
```

### 5. Documentation Concepts (Reuse)

**From Original Docs:**
- Threat taxonomy (attack types)
- Detection patterns
- Verification methodology
- Security model

**Reuse Strategy:**
- Reference original docs for concepts
- Rewrite for CLI context
- Update examples for CLI usage

---

## What NOT to Reuse

### 1. Docker Compose Configuration

**File:** `docker-compose.yml`

**Reason:** CLI doesn't use containers (except optional verification)

**Action:** Archive, don't delete (useful for future pro mode)

### 2. Python Code

**Files:** All `engine/*.py` files

**Reason:**
- CLI is Go-only
- Python was for orchestration (not needed)
- Only ~5% implemented anyway

**Action:** Archive, reference for algorithms only

### 3. Redis Event Bus

**Files:** Redis configuration, event schemas

**Reason:**
- CLI is single-process (no pub/sub needed)
- Direct function calls instead

**Action:** Remove from CLI design

### 4. Honeypot Container

**Files:** `honeypot-container/*`

**Reason:**
- CLI focused on detection, not deception initially
- Honeypot requires always-on service
- Could be separate tool later

**Action:** Out of scope for CLI Phase 1-3

### 5. Deception Engine

**Files:** `engine/deception/*`

**Reason:**
- Complex feature (Phase 4+)
- Requires background processes
- Not priority for CLI MVP

**Action:** Defer to Phase 4 (if implemented at all)

---

## Directory Structure Comparison

### Original (Microservices)

```
nlsn-pcap-monitor/
├── core/                    # Go monitor
│   ├── cmd/monitor/
│   └── pkg/                 # Empty
├── engine/                  # Python orchestrator
│   ├── api/
│   ├── detector/            # Empty
│   ├── deception/           # Empty
│   └── verification/        # Empty
├── verification-container/  # Complete
├── honeypot-container/      # Empty
├── shared/config/
├── docker-compose.yml
└── docs/
```

### New (CLI)

```
nlsn-monitor/                # New repository
├── cmd/
│   └── nlsn-monitor/        # Main CLI
│       └── main.go
├── internal/                # Private packages
│   ├── capture/
│   ├── parser/
│   ├── detector/
│   ├── storage/
│   ├── config/
│   └── verification/        # Optional: VPN client
├── pkg/                     # Public packages
│   └── types/
├── configs/
│   └── config.example.yaml
├── test/
├── docs/
│   └── 2025-11-10/          # New architecture docs
├── Makefile
├── go.mod
└── README.md
```

**Key Differences:**
- Single root (no separate core/engine)
- `internal/` for private packages
- No Docker files (except optional verification)
- No Python code
- Simpler structure

---

## Code Migration Examples

### Example 1: Packet Capture

#### Original (core/cmd/monitor/main.go)
```go
// Old: Basic capture, counts packets
func main() {
    handle, _ := pcap.OpenLive(iface, 65535, true, pcap.BlockForever)
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

    count := 0
    for packet := range packetSource.Packets() {
        count++
        // TODO: Parse packet
    }
    log.Printf("Captured %d packets", count)
}
```

#### New (internal/capture/capture.go)
```go
// New: Full capturer with stats, channels, graceful shutdown
type Capturer struct {
    handle     *pcap.Handle
    packetChan chan gopacket.Packet
    doneChan   chan struct{}
    stats      *Statistics
}

func (c *Capturer) Start() error {
    go c.captureLoop()
    return nil
}

func (c *Capturer) captureLoop() {
    for packet := range packetSource.Packets() {
        c.stats.PacketsCaptured++
        select {
        case c.packetChan <- packet:
        case <-c.doneChan:
            return
        }
    }
}
```

**Changes:**
- Structured as package with types
- Goroutine-based architecture
- Channel communication
- Statistics tracking
- Graceful shutdown

### Example 2: DNS Detection

#### Original Specification (TECHNICAL_SPECS.md)
```
DNS Hijacking Indicators:
1. Response from unexpected DNS server
2. IP address not matching known good IPs
3. TTL suspiciously low (<60s)
4. Response time anomaly

Scoring:
- Single indicator: 30-50 points
- Multiple indicators: Sum scores
- Threshold: >70 = high confidence threat
```

#### New Implementation (internal/detector/dns_hijack.go)
```go
type DNSHijackDetector struct {
    knownServers   map[string]bool
    domainBaseline map[string][]net.IP
}

func (d *DNSHijackDetector) Detect(pkt *parser.DNSPacket) (*Threat, error) {
    score := 0
    details := make(map[string]interface{})

    // Check 1: Unexpected DNS server
    if !d.knownServers[pkt.ServerIP.String()] {
        score += 50
        details["unexpected_server"] = pkt.ServerIP.String()
    }

    // Check 2: IP mismatch
    if baseline, exists := d.domainBaseline[pkt.QueryDomain]; exists {
        if !containsIP(baseline, pkt.ResponseIPs[0]) {
            score += 50
            details["unexpected_ip"] = pkt.ResponseIPs[0].String()
        }
    }

    // Check 3: Low TTL
    if pkt.TTL < 60 {
        score += 30
        details["low_ttl"] = pkt.TTL
    }

    // Evaluate
    if score >= 70 {
        return &Threat{
            Type:       "dns_hijack",
            Severity:   severityFromScore(score),
            Confidence: score,
            Source:     pkt.ServerIP,
            Target:     pkt.QueryDomain,
            Details:    details,
            Timestamp:  pkt.Timestamp,
        }, nil
    }

    return nil, nil
}
```

**Migration Process:**
1. Read algorithm from original docs
2. Identify key logic (scoring, thresholds)
3. Reimplement in Go with proper types
4. Add error handling
5. Write tests

---

## File-by-File Migration Plan

### Phase 1: Archive Old Code

```bash
# Create archive
mkdir -p archive/microservices-2025-11-10
mv core/ engine/ shared/ archive/microservices-2025-11-10/
mv docker-compose.yml archive/microservices-2025-11-10/

# Keep these
# - verification-container/ (optional component)
# - docs/ (reference material)
# - README.md (update for CLI)
```

### Phase 2: Create New Structure

```bash
# New repository (could be same repo, new directory)
mkdir nlsn-monitor/
cd nlsn-monitor/

# Initialize
go mod init github.com/YOUR_USERNAME/nlsn-monitor

# Create structure (see PHASE1-BASICS.md)
mkdir -p cmd/nlsn-monitor
mkdir -p internal/{capture,parser,detector,storage,config}
# ... etc
```

### Phase 3: Incremental Implementation

Follow IMPLEMENTATION-PLAN.md:
- Week 1: CLI framework (new code)
- Week 2: Packet capture (reference old, write new)
- Week 3: DNS parser (new code, use specs from docs)
- Week 4: DNS detector (port algorithm from docs)
- ... and so on

---

## Migration Checklist

### Pre-Migration

- [ ] Archive original microservices code
- [ ] Document what works and what doesn't
- [ ] Extract reusable algorithms from docs
- [ ] Identify VPN configs to migrate
- [ ] Backup any existing test data

### During Migration

- [ ] Set up new Go project structure
- [ ] Implement Week 1 (CLI framework)
- [ ] Implement Week 2 (Packet capture)
- [ ] Port detection algorithms (weeks 3-4)
- [ ] Implement storage layer (SQLite)
- [ ] Add configuration system

### Post-Migration

- [ ] Test all features work
- [ ] Verify detection accuracy
- [ ] Document new CLI usage
- [ ] Create installation guide
- [ ] Write migration guide for users (if any)

### Optional

- [ ] Keep verification-container working
- [ ] Add API client to call verification service
- [ ] Test hybrid verification mode

---

## Handling the Verification Container

### Option 1: Keep Separate (Recommended)

**Structure:**
```
nlsn-pcap-monitor/
├── nlsn-monitor/             # New CLI tool
│   ├── cmd/
│   ├── internal/
│   └── ...
├── verification-container/    # Keep as-is
│   ├── path-orchestrator.py
│   ├── Dockerfile
│   └── ...
└── docs/
    ├── 2025-11-10/           # New docs
    └── original/             # Archive old docs
```

**Usage:**
```bash
# Use CLI alone (built-in verification)
nlsn-monitor start

# Or use with verification service
docker run -d nlsn-verification-container
nlsn-monitor verify --url https://bank.com --use-service
```

### Option 2: Embed in CLI (Complex)

**Approach:** Bundle verification container, launch automatically

**Pros:**
- Seamless user experience
- Full features available

**Cons:**
- Requires Docker anyway
- Complex implementation
- Hidden dependencies

**Decision:** Not recommended (defeats purpose of CLI simplicity)

### Option 3: Port to Go (Future)

**Approach:** Rewrite verification logic in Go

**Pros:**
- Pure Go implementation
- No Docker needed
- Integrated into CLI

**Cons:**
- Network namespaces complex in Go
- VPN management tricky
- Significant effort (~4 weeks)

**Decision:** Defer to Phase 3+ if needed

---

## Testing Strategy During Migration

### 1. Archive Old Tests

```bash
mv core/pkg/parser/*_test.go archive/
# Keep as reference
```

### 2. Write New Tests

```go
// internal/parser/dns_test.go
func TestDNSParser(t *testing.T) {
    // Fresh test cases
    testCases := []struct{
        name string
        input []byte
        want *DNSPacket
    }{
        {
            name: "simple A record query",
            input: []byte{...},
            want: &DNSPacket{...},
        },
    }
    // ...
}
```

### 3. Compare Outputs

Use old implementation (if working) to generate test data:

```bash
# Run old monitor, capture DNS packets
sudo ./old-monitor > test/testdata/dns-packets.pcap

# Use in new tests
func TestDNSParserWithRealData(t *testing.T) {
    pcap := readPCAP("test/testdata/dns-packets.pcap")
    // Parse with new parser
    // Compare with expected results
}
```

---

## Timeline

### Immediate (Week 0)

- [x] Document new architecture
- [x] Write implementation plan
- [ ] Archive old code
- [ ] Set up new repository structure

### Short Term (Weeks 1-4)

- [ ] Implement CLI framework
- [ ] Port packet capture logic
- [ ] Implement DNS parser
- [ ] Port DNS detection algorithm

### Medium Term (Weeks 5-12)

- [ ] Implement HTTP/TLS parsing
- [ ] Port SSL stripping detection
- [ ] Implement verification (sequential)
- [ ] Add SQLite storage

### Long Term (Weeks 13-20)

- [ ] Add TUI
- [ ] Implement deception (optional)
- [ ] Performance tuning
- [ ] Release v1.0

### Future (Post-v1.0)

- [ ] Consider "pro mode" with containers
- [ ] Evaluate porting verification to Go
- [ ] Add advanced features

---

## Risks & Mitigation

### Risk 1: Loss of Verification Capability

**Risk:** Sequential verification slower than parallel

**Mitigation:**
- Accept trade-off (still usable at ~50s)
- Keep verification-container as option
- Document that advanced users can use container

### Risk 2: Algorithm Differences

**Risk:** New implementation detects different threats

**Mitigation:**
- Use same algorithms from original specs
- Test against known attacks
- Measure false positive/negative rates
- Adjust thresholds if needed

### Risk 3: Missing Features

**Risk:** Users expect microservices features

**Mitigation:**
- Clear documentation of differences
- Explain trade-offs (simplicity vs features)
- Offer verification-container for advanced use
- Plan "pro mode" for future

---

## Communication Plan

### For Users (If Any)

**Message:**
```
NLSN Monitor has been redesigned as a CLI-first tool for simplicity and ease of use.

What's changing:
- Single binary installation (no Docker required)
- User-controlled operation (start/stop when you want)
- Standard Unix integration (pipes, files, scripts)
- Simplified configuration (~/.config/nlsn-pcap/)

What's staying:
- Same detection algorithms
- Multi-path verification (simplified)
- Threat intelligence database
- Core security features

Migration:
- No migration needed (starting fresh)
- Old verification container still works (optional)
```

### For Contributors

**Message:**
```
We're refocusing on a CLI-first architecture. If you were working on the microservices version, here's what you need to know:

1. All Go code is being rewritten (cleaner structure)
2. Python engine is being removed (Go-only)
3. Detection algorithms stay the same (porting to new structure)
4. Verification container remains available (optional component)

New contribution areas:
- Protocol parsers (DNS, HTTP, TLS)
- Detection patterns
- CLI features (TUI, exports, etc.)
- Documentation

See IMPLEMENTATION-PLAN.md for roadmap.
```

---

## Conclusion

This migration is actually a **fresh start with lessons learned**:

**Keeping:**
- ✅ Detection algorithms (port to Go)
- ✅ Verification container (optional)
- ✅ Database schema (adapt for SQLite)
- ✅ Documentation concepts

**Discarding:**
- ❌ Microservices architecture
- ❌ Python engine code
- ❌ Docker orchestration (for main tool)
- ❌ Redis event bus

**Approach:** Reference old docs, write new code, test thoroughly

**Goal:** Simpler, more Unix-like tool that matches user needs

---

## Next Steps

1. Review this migration plan
2. Archive old code (if approved)
3. Begin Phase 1 Week 1 (see PHASE1-BASICS.md)
4. Build incrementally, test continuously
5. Deliver working CLI tool

**Ready to start building!** 🚀
