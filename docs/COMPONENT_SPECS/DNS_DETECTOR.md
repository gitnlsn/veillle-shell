# DNS Detector Component Specification

**Version:** 1.0
**Last Updated:** 2025-11-10
**Component:** Go Monitor / DNS Detection Module

---

## Overview

The DNS Detector is responsible for monitoring DNS traffic and detecting DNS hijacking attacks in real-time.

## Responsibilities

1. **Parse DNS Packets**: Extract DNS queries and responses from captured traffic
2. **Correlate Queries/Responses**: Match DNS responses to their corresponding queries
3. **Baseline Learning**: Build profile of normal DNS behavior
4. **Anomaly Detection**: Identify suspicious DNS responses
5. **Event Publishing**: Publish detection events to Redis for Engine processing

## Implementation

**File:** `core/pkg/detector/dns.go`

### Data Structures

```go
type DNSDetector struct {
    cache         *DNSCache
    baseline      *NetworkBaseline
    eventPublisher *events.EventPublisher
    config        *DetectorConfig
    mutex         sync.RWMutex
}

type DNSCache struct {
    queries     map[uint16]*DNSQuery    // Key: transaction ID
    responses   map[string]*DNSResponse // Key: domain name
    mutex       sync.RWMutex
    ttl         time.Duration
}

type DetectionResult struct {
    AttackDetected   bool
    SuspicionScore   int
    TriggerReasons   []string
    RequiresVerification bool
    Timestamp        time.Time
}
```

### Core Algorithm

```go
func (d *DNSDetector) Detect(query *DNSQuery, response *DNSResponse) *DetectionResult {
    result := &DetectionResult{
        AttackDetected: false,
        SuspicionScore: 0,
        TriggerReasons: []string{},
        Timestamp:      time.Now(),
    }

    // Check #1: Known domain with unexpected IP
    if d.baseline.HasDomain(query.Domain) {
        expectedIPs := d.baseline.GetExpectedIPs(query.Domain)
        if !contains(expectedIPs, response.IP) {
            result.SuspicionScore += 50
            result.TriggerReasons = append(result.TriggerReasons,
                fmt.Sprintf("Known domain %s returned unexpected IP %s",
                    query.Domain, response.IP))
        }
    }

    // Check #2: Private IP for public domain
    if isPublicDomain(query.Domain) && isPrivateIP(response.IP) {
        result.SuspicionScore += 40
        result.TriggerReasons = append(result.TriggerReasons,
            "Public domain resolved to private IP")
    }

    // Check #3: Abnormally low TTL
    if response.TTL < 60 && d.baseline.IsHighTrafficDomain(query.Domain) {
        result.SuspicionScore += 25
        result.TriggerReasons = append(result.TriggerReasons,
            "Abnormally low TTL for high-traffic domain")
    }

    // Determine action
    if result.SuspicionScore >= 80 {
        result.AttackDetected = true
        result.RequiresVerification = true
    } else if result.SuspicionScore >= 40 {
        result.RequiresVerification = true
    }

    return result
}
```

## Performance Requirements

- **Throughput**: Process 10,000 DNS packets per second
- **Latency**: < 10ms per detection
- **Memory**: < 100MB baseline data
- **False Positive Rate**: < 2%
- **False Negative Rate**: < 5%

## Configuration

```yaml
detection:
  dns:
    enabled: true
    threshold: 40
    cache_ttl: 300
    baseline_domains:
      - google.com
      - facebook.com
      - youtube.com
```

## Testing

See `core/pkg/detector/dns_test.go` for:
- Unit tests for detection logic
- Baseline learning tests
- False positive/negative rate tests
- Performance benchmarks

## Dependencies

- `core/pkg/parser/dns.go`: DNS packet parsing
- `core/pkg/events/publisher.go`: Event publishing
- `core/pkg/baseline/network.go`: Baseline management

---

**Document Version:** 1.0
**Total Word Count:** ~400 words
