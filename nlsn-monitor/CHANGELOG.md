# Changelog

All notable changes to nlsn-monitor will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-11-10

### Added

#### CLI & Core
- **CLI Framework** - Full-featured command-line interface using Cobra
- **`start` command** - Begin real-time network monitoring
- **`threats` command** - Query and filter detected threats from database
- **`version` command** - Display version information
- **Configuration system** - YAML-based config with XDG directory compliance
- **Graceful shutdown** - Proper signal handling (SIGINT, SIGTERM)
- **Colored output** - Severity-based ANSI colors (critical/high/medium/low)

#### Packet Capture
- **libpcap integration** - High-performance packet capture using gopacket
- **Auto interface detection** - Automatic network interface selection
- **BPF filtering** - Optimized packet filtering (default: port 53)
- **Promiscuous mode** - Capture all network traffic on interface
- **Statistics tracking** - Packets captured, bytes, rate, duration
- **Channel-based processing** - 1000-packet buffer for high throughput

#### DNS Parsing
- **DNS protocol parser** - Full query and response parsing
- **Compression handling** - RFC 1035 DNS compression pointer support
- **Record types** - A, AAAA, CNAME, MX, NS records
- **Response codes** - NOERROR, NXDOMAIN, SERVFAIL, etc.
- **Multiple answers** - Support for multiple A/AAAA records
- **Performance** - 5.3M packets/second @ 186ns/op (Apple M1)

#### Threat Detection
- **DNS Hijacking Detector** - 5 detection methods with weighted scoring:
  1. Unknown DNS server (50 points)
  2. IP address mismatch with baseline (50 points)
  3. Suspiciously low TTL <60s (30 points)
  4. Multiple A records >3 (20 points)
  5. Private IP for public domain (40 points)
- **Baseline learning** - Automatic IP address learning per domain (up to 5 IPs)
- **Configurable threshold** - Adjustable min_confidence (default: 50)
- **Severity calculation** - Auto-determined from confidence score
- **Thread-safe operation** - Mutex-protected baseline and statistics

#### Storage
- **SQLite database** - Persistent storage with WAL mode
- **Automatic schema** - Self-initializing tables and indexes
- **DNS packets table** - All captured DNS queries and responses
- **Threats table** - Detected security threats with full details
- **JSON serialization** - Complex data stored as JSON
- **Query functions** - Recent packets, by domain, by type, statistics

#### Testing
- **Unit tests** - Comprehensive test coverage:
  - DNS parser tests (domain parsing, packet parsing, errors)
  - Detector tests (all 5 detection methods, scoring)
  - 14 test functions total
- **Attack simulation** - Bash script with 6 attack scenarios
- **Traffic generator** - Python script using Scapy for test traffic
- **Benchmarks** - Performance profiling with CPU and memory profiles
- **Test documentation** - Complete testing guide in test/README.md

#### Documentation
- **README.md** - Comprehensive user guide with examples
- **STATUS.md** - Detailed project status and progress tracking
- **WEEK1-COMPLETE.md** - Week 1 completion summary
- **WEEK2-COMPLETE.md** - Week 2 completion summary
- **WEEK3-COMPLETE.md** - Week 3 completion summary
- **test/README.md** - Testing documentation
- **Installation script** - Automated install.sh with dependency checking

### Performance

- **Parser throughput**: 5,376,344 packets/second
- **Memory usage**: 208 bytes per packet
- **Binary size**: 12MB
- **Theoretical bandwidth**: 22 Gbps @ 512-byte packets
- **Allocations**: 6 per operation

### Known Limitations

- DNS detection only (no HTTP/TLS yet)
- No multi-path verification (Phase 3)
- Possible false positives on first queries (until baseline learned)
- Requires sudo/root on most systems (or CAP_NET_RAW capability)
- macOS cannot set capabilities (always requires sudo)
- CLI-only (no web interface)

### Breaking Changes

None (initial release)

### Fixed

N/A (initial release)

### Deprecated

N/A (initial release)

---

## [Unreleased]

### Planned for v0.2.0 (Phase 2)

- HTTP/HTTPS packet parsing
- SSL stripping detection
- Weak cipher detection
- Certificate validation
- Custom detection patterns (YAML)
- Server whitelist configuration
- Alert suppression/deduplication

---

## Development Timeline

### Week 1 (Nov 3-9): CLI Framework & Packet Capture ✅
- Created project structure
- Implemented CLI with Cobra
- Built packet capture engine
- Added configuration system
- Interface auto-detection
- Statistics tracking

### Week 2 (Nov 3-9): DNS Parser & Storage ✅
- DNS packet types
- Full DNS protocol parser
- DNS compression handling
- SQLite storage layer
- Database schema and migrations
- Query functions

### Week 3 (Nov 9-10): DNS Hijacking Detection ✅
- Threat types and severity levels
- DNS hijack detector with 5 methods
- Baseline learning system
- Colored real-time alerts
- Threat persistence
- Integration with main.go

### Week 4 (Nov 10): Testing & Release ✅
- Unit tests for parser and detector
- Attack simulation scripts
- Performance benchmarking
- Threats query command
- Installation script
- Comprehensive documentation
- v0.1.0 release

---

## Contributors

- Nelson Kenzo Tamashiro (@yourusername)

---

## Release Notes

### v0.1.0 - Initial Alpha Release

This is the first public release of nlsn-monitor, completing Phase 1 of the development roadmap. The tool is now fully functional for DNS hijacking detection but should be considered alpha quality.

**What works:**
- Real-time DNS monitoring
- Threat detection with colored alerts
- Persistent database storage
- CLI interface for monitoring and querying

**What's next:**
- Integration testing with real network traffic
- False positive rate measurement
- HTTP/TLS detection (Phase 2)
- Multi-path verification (Phase 3)

**Getting Started:**
```bash
./install.sh
sudo nlsn-monitor start
nlsn-monitor threats
```

See README.md for full documentation.

---

**Note**: All dates reflect development timeline. Project started 2025-11-03.
