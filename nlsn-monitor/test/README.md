# nlsn-monitor Test Suite

This directory contains testing tools for nlsn-monitor.

## Test Organization

```
test/
├── README.md                    # This file
├── simulate_dns_hijack.sh       # Bash script for attack simulation
└── generate_test_traffic.py     # Python traffic generator
```

## Unit Tests

Unit tests are located in the source tree alongside the code:

- `internal/parser/dns_test.go` - DNS parser tests
- `internal/detector/dns_hijack_test.go` - Detection engine tests

### Running Unit Tests

```bash
# Run all tests
go test ./...

# Run with verbose output
go test ./... -v

# Run specific package
go test ./internal/parser/...
go test ./internal/detector/...

# Run benchmarks
go test ./internal/parser/... -bench=. -benchmem

# With coverage
go test ./... -cover
go test ./... -coverprofile=coverage.out
go tool cover -html=coverage.out
```

### Current Test Coverage

**Parser Tests** (`internal/parser/dns_test.go`):
- ✅ Domain name parsing (simple, subdomains, compression)
- ✅ DNS packet parsing (queries, responses)
- ✅ Error handling (short packets, malformed data)
- ✅ Response codes (NOERROR, NXDOMAIN, etc.)
- ✅ Multiple answer records
- ✅ Performance benchmarks

**Detector Tests** (`internal/detector/dns_hijack_test.go`):
- ✅ Known server detection
- ✅ Baseline learning and matching
- ✅ Private IP detection
- ✅ Public domain detection
- ✅ Low TTL detection
- ✅ Unknown server alerts
- ✅ IP mismatch alerts
- ✅ Multiple indicator combinations
- ✅ Query/error response filtering

**Performance Results** (Apple M1):
```
BenchmarkParseRaw-8   	 5,883,034 iterations
                          190.6 ns/op
                          208 B/op
                          6 allocs/op
```

This means the parser can handle **~5 million packets/second** on M1.

## Attack Simulation

### Bash Simulation Script

The `simulate_dns_hijack.sh` script creates realistic attack scenarios by manipulating system DNS settings and hosts file.

**Available Scenarios:**

1. **Unknown DNS Server** - Changes system DNS to local router
2. **IP Mismatch** - Modifies `/etc/hosts` to return wrong IPs
3. **Low TTL Response** - Requires dnsmasq setup (manual)
4. **Private IP for Public Domain** - Points banking domains to private IPs
5. **Multiple Indicators** - Combines several attack indicators
6. **All Scenarios** - Runs all tests sequentially

**Usage:**

```bash
cd nlsn-monitor
sudo ./test/simulate_dns_hijack.sh

# In another terminal
sudo ./nlsn-monitor start --interface en0 -v
```

**Safety:**
- ⚠️ **Only use on your own test network**
- The script backs up and restores all changes
- Press Ctrl+C to abort if needed
- All modifications are temporary

### Python Traffic Generator

The `generate_test_traffic.py` script generates realistic DNS traffic patterns using Scapy.

**Requirements:**
```bash
pip3 install scapy
```

**Available Tests:**

1. **Normal Traffic** - Legitimate DNS queries to popular domains
2. **Baseline Learning** - Repeated queries to test learning system
3. **Multiple A Records** - Queries to domains with many IPs
4. **Stress Test** - High-volume traffic for performance testing
5. **Mixed Traffic** - Combination of all scenarios

**Usage:**

```bash
# Install dependencies
pip3 install scapy

# Run generator (may need sudo for packet injection)
sudo python3 test/generate_test_traffic.py

# In another terminal, run nlsn-monitor
sudo ./nlsn-monitor start --interface en0 -v
```

**Features:**
- Interactive menu
- Configurable DNS server target
- Real-time logging
- Performance metrics

## Integration Testing

### End-to-End Test Flow

1. **Start nlsn-monitor:**
   ```bash
   sudo ./nlsn-monitor start --interface en0 --verbose
   ```

2. **Run attack simulation:**
   ```bash
   # Terminal 2
   sudo ./test/simulate_dns_hijack.sh
   # Select scenario 5 (Multiple Indicators)
   ```

3. **Generate DNS queries:**
   ```bash
   # Terminal 3
   dig google.com
   dig amazon.com
   dig facebook.com
   ```

4. **Verify detection:**
   - Check terminal 1 for colored threat alerts
   - Expected: 🚨 CRITICAL alerts with 90+ confidence

5. **Check database:**
   ```bash
   sqlite3 ~/.local/share/nlsn-pcap/nlsn.db

   sqlite> SELECT timestamp, type, severity, confidence, target FROM threats;
   sqlite> SELECT COUNT(*) FROM dns_packets;
   ```

### Expected Results

**Scenario 1: Unknown DNS Server**
- Trigger: Using 192.168.1.1 as DNS
- Expected: Medium severity (50 points)
- Alert: "Unexpected DNS Server: 192.168.1.1"

**Scenario 2: IP Mismatch**
- Trigger: google.com -> 10.0.0.53 (after baseline)
- Expected: Medium severity (50 points)
- Alert: "Unexpected IP: 10.0.0.53"

**Scenario 4: Private IP for Public Domain**
- Trigger: paypal.com -> 192.168.1.53
- Expected: Medium severity (40 points)
- Alert: "Private IP for Public Domain!"

**Scenario 5: Multiple Indicators**
- Triggers: Unknown server + Private IP + Low TTL
- Expected: Critical severity (120+ points)
- Alert: 🚨 with multiple reasons listed

## Performance Testing

### Stress Test with Traffic Generator

```bash
# Start nlsn-monitor
sudo ./nlsn-monitor start --interface en0

# Generate high-volume traffic
sudo python3 test/generate_test_traffic.py
# Select option 4 (Stress Test)
```

**Target Performance:**
- Packet capture: 10,000+ pkt/s
- DNS parsing: 5,000+ pkt/s
- Memory: < 100MB for 1M packets
- Zero packet drops

### Manual Performance Testing

```bash
# Generate many DNS queries
for i in {1..1000}; do
    dig "test${i}.example.com" @8.8.8.8 &
done

# Monitor nlsn-monitor statistics
# Check for packet drops, errors
```

## Troubleshooting Tests

### Tests Fail to Compile

```bash
# Ensure dependencies are installed
go mod download
go mod tidy
```

### Permission Errors

```bash
# Tests need root for packet capture
sudo go test ./...

# Or set capabilities
sudo setcap cap_net_raw,cap_net_admin=eip $(which go)
```

### No Packets Captured

```bash
# Check interface exists
ip link show
ifconfig

# Check BPF filter
sudo tcpdump -i en0 port 53

# Verify permissions
sudo ./nlsn-monitor start --interface en0 -v
```

### Simulation Script Errors

```bash
# Ensure running as root
sudo ./test/simulate_dns_hijack.sh

# If hosts file locked on macOS
sudo chflags nouchg /etc/hosts
sudo ./test/simulate_dns_hijack.sh
sudo chflags uchg /etc/hosts  # Re-lock after
```

### Python Generator Errors

```bash
# Install scapy
pip3 install scapy

# On macOS, may need to disable SIP for packet injection
# Or run in VM/container

# Permission errors
sudo python3 test/generate_test_traffic.py
```

## Test Coverage Goals

### Current Coverage
- ✅ Parser: Domain parsing, packet parsing
- ✅ Detector: All 5 detection methods
- ✅ Integration: Attack simulation
- ❌ Storage: No dedicated tests yet
- ❌ Capture: No unit tests (integration only)

### Future Testing
- Storage layer unit tests
- Capture layer tests with mock data
- Multi-threaded stress tests
- False positive rate measurement
- Baseline learning accuracy tests
- Long-running stability tests (24+ hours)

## Continuous Integration

Future CI/CD pipeline:

```yaml
# .github/workflows/test.yml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-go@v2
        with:
          go-version: '1.21'
      - name: Install libpcap
        run: sudo apt-get install libpcap-dev
      - name: Run tests
        run: go test ./... -v -race -coverprofile=coverage.out
      - name: Upload coverage
        uses: codecov/codecov-action@v2
```

## Contributing Tests

When adding new features:

1. Write unit tests first (TDD)
2. Ensure >80% coverage
3. Add integration test scenario if applicable
4. Update this README
5. Run full test suite before commit

**Test Guidelines:**
- Use table-driven tests
- Test edge cases and errors
- Include benchmarks for critical paths
- Mock external dependencies
- Keep tests fast (<100ms per test)
