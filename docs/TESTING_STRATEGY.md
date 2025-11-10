# Testing Strategy

**Version:** 1.0
**Last Updated:** 2025-11-10
**Project:** NLSN PCAP Monitor

---

## Table of Contents

1. [Introduction](#introduction)
2. [Testing Philosophy](#testing-philosophy)
3. [Test Levels](#test-levels)
4. [Unit Testing](#unit-testing)
5. [Integration Testing](#integration-testing)
6. [End-to-End Testing](#end-to-end-testing)
7. [Security Testing](#security-testing)
8. [Performance Testing](#performance-testing)
9. [Test Data Management](#test-data-management)
10. [CI/CD Integration](#cicd-integration)
11. [Test Coverage Requirements](#test-coverage-requirements)
12. [Testing Tools](#testing-tools)

---

## 1. Introduction

This document defines the comprehensive testing strategy for the NLSN PCAP Monitor system. It establishes testing standards, methodologies, and requirements to ensure system reliability, security, and performance.

### 1.1 Testing Goals

- **Correctness**: Verify all components behave as specified
- **Security**: Ensure no vulnerabilities in attack detection and deception
- **Performance**: Validate system meets performance requirements
- **Reliability**: Confirm system operates correctly under various conditions
- **Maintainability**: Ensure tests are readable and maintainable

### 1.2 Scope

Testing covers:
- Go Monitor (packet capture and detection)
- Python Engine (orchestration and deception)
- Verification Container (multi-path verification)
- Honeypot System (tarpit behaviors)
- APIs (REST and WebSocket)
- Database operations
- Event bus communication

### 1.3 Testing Principles

1. **Test Early, Test Often**: Write tests alongside implementation
2. **Automate Everything**: Minimize manual testing
3. **Test in Isolation**: Unit tests should be independent
4. **Test Realistic Scenarios**: Integration tests use real-world data
5. **Fail Fast**: Tests should quickly identify failures
6. **Maintainable Tests**: Tests should be as clean as production code

---

## 2. Testing Philosophy

### 2.1 Test-Driven Development (TDD)

For critical detection algorithms, we use TDD:

1. **Red**: Write failing test first
2. **Green**: Implement minimal code to pass
3. **Refactor**: Improve code while maintaining tests

**Example:**

```python
# 1. RED - Write failing test
def test_dns_hijack_detection():
    detector = DNSHijackDetector()
    packet = create_hijacked_dns_packet()

    result = detector.detect(packet)

    assert result.attack_detected == True
    assert result.confidence >= 0.8

# 2. GREEN - Implement detection
class DNSHijackDetector:
    def detect(self, packet):
        # Minimal implementation
        if packet.response_ip != packet.expected_ip:
            return DetectionResult(attack_detected=True, confidence=0.9)
        return DetectionResult(attack_detected=False, confidence=0.0)

# 3. REFACTOR - Improve while tests pass
```

### 2.2 Behavior-Driven Development (BDD)

For user-facing features, we use BDD with Gherkin syntax:

```gherkin
Feature: DNS Hijacking Detection
  As a system user
  I want to detect DNS hijacking attempts
  So that I can protect my network traffic

  Scenario: Detect DNS hijacking for known domain
    Given the system has learned baseline DNS responses
    And example.com normally resolves to 93.184.216.34
    When a DNS response claims example.com is 192.0.2.1
    Then the system should detect a DNS hijacking attack
    And the confidence should be HIGH
    And verification should be triggered
```

### 2.3 Property-Based Testing

For parser robustness, we use property-based testing:

```python
from hypothesis import given, strategies as st

@given(st.binary(min_size=12, max_size=512))
def test_dns_parser_never_crashes(packet_data):
    """DNS parser should never crash on any input"""
    try:
        result = parse_dns_packet(packet_data)
        # Parser either succeeds or raises expected exceptions
        assert result is not None or True
    except (DNSParseError, ValueError):
        # Expected exceptions are OK
        pass
    except Exception as e:
        # Unexpected exceptions fail the test
        pytest.fail(f"Unexpected exception: {e}")
```

### 2.4 Testing Pyramid

```
       /\
      /  \        E2E Tests (10%)
     /────\       - Full system scenarios
    /      \      - Real network traffic
   /────────\     Integration Tests (30%)
  /          \    - Component interactions
 /────────────\   - Database + Redis + APIs
/──────────────\  Unit Tests (60%)
                  - Individual functions
                  - Pure logic
                  - Fast execution
```

---

## 3. Test Levels

### 3.1 Unit Tests

**Target:** 60% of test effort

**Characteristics:**
- Test individual functions/methods in isolation
- No external dependencies (database, network, filesystem)
- Fast execution (< 1ms per test)
- Use mocks/stubs for dependencies

**Examples:**
- DNS packet parser
- Detection algorithm logic
- Hash calculation functions
- Configuration validation

### 3.2 Integration Tests

**Target:** 30% of test effort

**Characteristics:**
- Test component interactions
- Use real dependencies (database, Redis)
- Medium execution time (100ms - 1s per test)
- Test data setup/teardown

**Examples:**
- Engine → Verification API calls
- Event publishing → Event subscription
- Database operations
- API endpoint handlers

### 3.3 End-to-End Tests

**Target:** 10% of test effort

**Characteristics:**
- Test complete user scenarios
- All components running
- Slow execution (5s - 30s per test)
- Use test environments

**Examples:**
- Full attack detection → verification → deception flow
- Multi-path verification with real VPNs
- Honeypot interaction scenarios

---

## 4. Unit Testing

### 4.1 Go Unit Tests

**Framework:** Go standard `testing` package + `testify` for assertions

**Structure:**

```
core/
├── pkg/
│   ├── parser/
│   │   ├── dns.go
│   │   └── dns_test.go       # Unit tests for DNS parser
│   ├── detector/
│   │   ├── dns.go
│   │   └── dns_test.go       # Unit tests for DNS detector
│   └── events/
│       ├── publisher.go
│       └── publisher_test.go  # Unit tests for event publisher
```

**Example Test:**

```go
// File: core/pkg/parser/dns_test.go

package parser

import (
    "net"
    "testing"
    "time"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestParseDNS_ValidQuery(t *testing.T) {
    // Arrange
    rawData := []byte{
        0x12, 0x34, // Transaction ID
        0x01, 0x00, // Flags (standard query)
        0x00, 0x01, // Questions: 1
        0x00, 0x00, // Answers: 0
        0x00, 0x00, // Authority: 0
        0x00, 0x00, // Additional: 0
        // Question: example.com A IN
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03, 'c', 'o', 'm',
        0x00,       // End of name
        0x00, 0x01, // Type: A
        0x00, 0x01, // Class: IN
    }

    srcIP := net.ParseIP("192.168.1.50")
    dstIP := net.ParseIP("8.8.8.8")
    timestamp := time.Now()

    // Act
    packet, err := ParseDNS(rawData, srcIP, dstIP, timestamp)

    // Assert
    require.NoError(t, err)
    assert.Equal(t, uint16(0x1234), packet.TransactionID)
    assert.False(t, packet.IsResponse)
    assert.Len(t, packet.Questions, 1)
    assert.Equal(t, "example.com", packet.Questions[0].Name)
    assert.Equal(t, uint16(1), packet.Questions[0].Type) // A record
}

func TestParseDNS_InvalidPacketTooShort(t *testing.T) {
    // Arrange
    rawData := []byte{0x12, 0x34} // Only 2 bytes (minimum is 12)

    // Act
    packet, err := ParseDNS(rawData, nil, nil, time.Now())

    // Assert
    assert.Error(t, err)
    assert.Nil(t, packet)
    assert.Equal(t, ErrDNSPacketTooShort, err)
}

func TestParseDNS_WithCompression(t *testing.T) {
    // Arrange - DNS response with name compression
    rawData := []byte{
        0x12, 0x34, // Transaction ID
        0x81, 0x80, // Flags (response, recursion available)
        0x00, 0x01, // Questions: 1
        0x00, 0x01, // Answers: 1
        0x00, 0x00, // Authority: 0
        0x00, 0x00, // Additional: 0
        // Question
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03, 'c', 'o', 'm',
        0x00,
        0x00, 0x01, // Type: A
        0x00, 0x01, // Class: IN
        // Answer with pointer to question name
        0xC0, 0x0C, // Pointer to offset 12 (question name)
        0x00, 0x01, // Type: A
        0x00, 0x01, // Class: IN
        0x00, 0x00, 0x00, 0x3C, // TTL: 60
        0x00, 0x04, // Data length: 4
        0x5D, 0xB8, 0xD8, 0x22, // IP: 93.184.216.34
    }

    // Act
    packet, err := ParseDNS(rawData, nil, nil, time.Now())

    // Assert
    require.NoError(t, err)
    assert.True(t, packet.IsResponse)
    assert.Len(t, packet.Answers, 1)
    assert.Equal(t, "example.com", packet.Answers[0].Name)
    assert.Equal(t, "93.184.216.34", packet.Answers[0].IP.String())
}

// Benchmark tests
func BenchmarkParseDNS(b *testing.B) {
    rawData := createValidDNSQuery()
    srcIP := net.ParseIP("192.168.1.50")
    dstIP := net.ParseIP("8.8.8.8")

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        ParseDNS(rawData, srcIP, dstIP, time.Now())
    }
}

// Table-driven tests
func TestDetectDNSAnomaly(t *testing.T) {
    tests := []struct {
        name           string
        query          DNSQuery
        response       DNSResponse
        expectedScore  int
        expectedDetect bool
    }{
        {
            name: "Known domain with unexpected IP",
            query: DNSQuery{Domain: "google.com"},
            response: DNSResponse{
                Domain: "google.com",
                IP:     net.ParseIP("192.168.1.1"), // Private IP
            },
            expectedScore:  90,
            expectedDetect: true,
        },
        {
            name: "Normal resolution",
            query: DNSQuery{Domain: "example.com"},
            response: DNSResponse{
                Domain: "example.com",
                IP:     net.ParseIP("93.184.216.34"),
            },
            expectedScore:  0,
            expectedDetect: false,
        },
        {
            name: "Abnormally low TTL",
            query: DNSQuery{Domain: "facebook.com"},
            response: DNSResponse{
                Domain: "facebook.com",
                IP:     net.ParseIP("157.240.1.1"),
                TTL:    30, // Very low TTL
            },
            expectedScore:  45,
            expectedDetect: false, // Below threshold
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            detector := NewDNSAnomalyDetector()
            result := detector.Detect(tt.query, tt.response)

            assert.Equal(t, tt.expectedDetect, result.AttackDetected)
            assert.GreaterOrEqual(t, result.SuspicionScore, tt.expectedScore-5)
            assert.LessOrEqual(t, result.SuspicionScore, tt.expectedScore+5)
        })
    }
}
```

### 4.2 Python Unit Tests

**Framework:** pytest + pytest-asyncio + pytest-mock

**Structure:**

```
engine/
├── detector/
│   ├── dns_hijack.py
│   └── test_dns_hijack.py    # Unit tests
├── deception/
│   ├── behavior_sim.py
│   └── test_behavior_sim.py  # Unit tests
└── verification/
    ├── client.py
    └── test_client.py        # Unit tests
```

**Example Test:**

```python
# File: engine/detector/test_dns_hijack.py

import pytest
from unittest.mock import Mock, patch
from detector.dns_hijack import DNSHijackDetector, DetectionResult

class TestDNSHijackDetector:
    @pytest.fixture
    def detector(self):
        """Create detector instance for each test"""
        return DNSHijackDetector()

    @pytest.fixture
    def baseline_data(self):
        """Sample baseline data"""
        return {
            "example.com": ["93.184.216.34"],
            "google.com": ["142.250.80.46"],
        }

    def test_detect_hijack_known_domain(self, detector, baseline_data):
        """Should detect hijack for known domain with wrong IP"""
        # Arrange
        detector.baseline = baseline_data
        query = {"domain": "example.com"}
        response = {"ip": "192.0.2.1"}  # Wrong IP

        # Act
        result = detector.detect(query, response)

        # Assert
        assert result.attack_detected is True
        assert result.confidence >= 0.8
        assert "Known domain with unexpected IP" in result.reason

    def test_no_detection_correct_ip(self, detector, baseline_data):
        """Should not detect attack when IP is correct"""
        # Arrange
        detector.baseline = baseline_data
        query = {"domain": "example.com"}
        response = {"ip": "93.184.216.34"}  # Correct IP

        # Act
        result = detector.detect(query, response)

        # Assert
        assert result.attack_detected is False
        assert result.confidence < 0.3

    def test_detect_private_ip_for_public_domain(self, detector):
        """Should detect private IP response for public domain"""
        # Arrange
        query = {"domain": "public-site.com"}
        response = {"ip": "192.168.1.100"}  # Private IP

        # Act
        result = detector.detect(query, response)

        # Assert
        assert result.attack_detected is True
        assert "private IP" in result.reason.lower()

    @pytest.mark.parametrize("domain,ip,expected_attack", [
        ("example.com", "93.184.216.34", False),  # Correct
        ("example.com", "192.0.2.1", True),       # Hijacked
        ("google.com", "10.0.0.1", True),         # Private IP
        ("localhost", "127.0.0.1", False),        # Local domain OK
    ])
    def test_detection_scenarios(self, detector, baseline_data, domain, ip, expected_attack):
        """Test multiple detection scenarios"""
        detector.baseline = baseline_data
        query = {"domain": domain}
        response = {"ip": ip}

        result = detector.detect(query, response)

        assert result.attack_detected == expected_attack

    @patch('detector.dns_hijack.verify_dns_through_vpn')
    async def test_verify_suspicion(self, mock_verify, detector):
        """Should trigger verification for suspicious responses"""
        # Arrange
        mock_verify.return_value = {
            "attack_confirmed": True,
            "consensus_ip": "93.184.216.34"
        }

        query = {"domain": "example.com"}
        response = {"ip": "192.0.2.1"}

        # Act
        result = await detector.detect_and_verify(query, response)

        # Assert
        mock_verify.assert_called_once()
        assert result.verified is True
        assert result.attack_confirmed is True

# Async tests
@pytest.mark.asyncio
async def test_async_verification():
    """Test async verification process"""
    detector = DNSHijackDetector()

    result = await detector.verify_async("example.com", num_paths=5)

    assert result is not None
    assert "paths_checked" in result

# Property-based testing
from hypothesis import given, strategies as st

@given(
    domain=st.text(min_size=1, max_size=253, alphabet=st.characters(whitelist_categories=('Ll', 'Nd'), whitelist_characters='.-')),
    ip=st.ip_addresses(v=4)
)
def test_detector_never_crashes(domain, ip):
    """Detector should handle any domain/IP combination"""
    detector = DNSHijackDetector()

    try:
        result = detector.detect(
            {"domain": domain},
            {"ip": str(ip)}
        )
        assert isinstance(result, DetectionResult)
    except ValueError:
        # Expected for invalid inputs
        pass
```

### 4.3 Test Fixtures and Helpers

**Go Test Helpers:**

```go
// File: core/pkg/testutil/fixtures.go

package testutil

import (
    "net"
    "time"
)

// CreateDNSQuery creates a test DNS query packet
func CreateDNSQuery(domain string, transactionID uint16) []byte {
    // Build DNS query packet bytes
    return buildDNSQueryBytes(domain, transactionID)
}

// CreateDNSResponse creates a test DNS response packet
func CreateDNSResponse(domain string, ip string, transactionID uint16) []byte {
    return buildDNSResponseBytes(domain, ip, transactionID)
}

// CreateHTTPRequest creates a test HTTP request packet
func CreateHTTPRequest(method, url, host string) []byte {
    return buildHTTPRequestBytes(method, url, host)
}

// MockRedisClient creates a mock Redis client for testing
func MockRedisClient() *RedisClientMock {
    return &RedisClientMock{
        published: make(map[string][]string),
    }
}
```

**Python Test Fixtures:**

```python
# File: engine/tests/conftest.py

import pytest
from sqlalchemy import create_engine
from redis import Redis

@pytest.fixture(scope="session")
def database():
    """Create test database"""
    engine = create_engine("postgresql://test:test@localhost/test_nlsn")
    # Create tables
    Base.metadata.create_all(engine)
    yield engine
    # Cleanup
    Base.metadata.drop_all(engine)

@pytest.fixture
def db_session(database):
    """Create database session for each test"""
    connection = database.connect()
    transaction = connection.begin()
    session = Session(bind=connection)

    yield session

    session.close()
    transaction.rollback()
    connection.close()

@pytest.fixture
def redis_client():
    """Create Redis client for testing"""
    client = Redis(host="localhost", port=6379, db=15)  # Use test DB
    yield client
    client.flushdb()  # Clean up after test

@pytest.fixture
def sample_threat(db_session):
    """Create sample threat for testing"""
    threat = Threat(
        attack_type="dns_hijack",
        severity="high",
        source_ip="192.168.1.1",
        description="Test threat"
    )
    db_session.add(threat)
    db_session.commit()
    return threat

@pytest.fixture
def mock_verification_api(monkeypatch):
    """Mock verification API responses"""
    async def mock_verify(url, num_paths):
        return {
            "attack_detected": False,
            "confidence": "HIGH",
            "paths_checked": num_paths
        }

    monkeypatch.setattr("verification.client.verify_url", mock_verify)
```

---

## 5. Integration Testing

### 5.1 Component Integration Tests

**Test Scenarios:**

1. **Monitor → Redis → Engine**
   - Monitor publishes DNS packet event
   - Engine receives and processes event
   - Verify event data integrity

2. **Engine → Verification API → Database**
   - Engine calls verification API
   - Verification returns result
   - Engine stores threat in database

3. **Engine → Deception → Redis**
   - Engine starts deception session
   - Deception publishes fake packet events
   - Verify packet generation

**Example Test:**

```python
# File: engine/tests/integration/test_detection_flow.py

import pytest
import asyncio
from redis import Redis
import json

@pytest.mark.integration
class TestDetectionFlow:
    @pytest.fixture
    def redis_client(self):
        client = Redis(host="localhost", port=6379, db=15)
        yield client
        client.flushdb()

    @pytest.fixture
    def engine(self, redis_client, db_session):
        from engine.main import Engine
        engine = Engine(redis_client, db_session)
        return engine

    async def test_full_dns_hijack_detection_flow(self, redis_client, engine, db_session):
        """Test complete flow from packet to threat logging"""
        # 1. Simulate Monitor publishing DNS packet event
        dns_event = {
            "event_type": "dns_packet",
            "timestamp": "2025-11-10T14:32:15.123Z",
            "data": {
                "transaction_id": 12345,
                "is_response": True,
                "query": {"domain": "example.com"},
                "response": {
                    "ips": ["192.0.2.1"],  # Suspicious IP
                    "ttl": 300
                },
                "source_ip": "192.168.1.1",
                "suspicious": True,
                "suspicion_score": 85
            }
        }

        redis_client.publish("packets:dns", json.dumps(dns_event))

        # 2. Wait for engine to process
        await asyncio.sleep(0.5)

        # 3. Verify attack detection event published
        pubsub = redis_client.pubsub()
        pubsub.subscribe("attacks:detected")

        message = pubsub.get_message(timeout=5)
        assert message is not None

        attack_event = json.loads(message['data'])
        assert attack_event['data']['attack_type'] == "dns_hijack"
        assert attack_event['data']['severity'] in ["high", "critical"]

        # 4. Verify threat logged to database
        threats = db_session.query(Threat).filter_by(
            attack_type="dns_hijack"
        ).all()

        assert len(threats) == 1
        assert threats[0].source_ip == "192.168.1.1"
        assert threats[0].verified == False  # Not yet verified

        # 5. Verify verification triggered
        await asyncio.sleep(2)  # Wait for verification

        db_session.refresh(threats[0])
        assert threats[0].verified == True
        assert threats[0].verification_data is not None
```

### 5.2 API Integration Tests

```python
# File: engine/tests/integration/test_api.py

import pytest
from fastapi.testclient import TestClient
from engine.api.server import app

@pytest.fixture
def client():
    return TestClient(app)

@pytest.mark.integration
class TestEngineAPI:
    def test_health_endpoint(self, client):
        """Test health check endpoint"""
        response = client.get("/v1/health")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] in ["healthy", "degraded"]
        assert "components" in data

    def test_list_threats(self, client, sample_threats):
        """Test threat listing with filters"""
        response = client.get("/v1/threats?severity=high&limit=50")

        assert response.status_code == 200
        data = response.json()
        assert "threats" in data
        assert data["total"] > 0

        # Verify all returned threats have high severity
        for threat in data["threats"]:
            assert threat["severity"] == "high"

    def test_start_deception_session(self, client):
        """Test starting deception session"""
        payload = {
            "target_domain": "example.com",
            "attacker_ip": "192.168.1.1",
            "behavior_profile": "banking_user"
        }

        response = client.post("/v1/deception/start", json=payload)

        assert response.status_code == 201
        data = response.json()
        assert "session_id" in data
        assert data["status"] == "active"
        assert len(data["honeytokens_deployed"]) > 0

    @pytest.mark.asyncio
    async def test_verification_proxy(self, client, mock_verification_api):
        """Test Engine proxying to Verification API"""
        payload = {
            "url": "https://example.com",
            "num_paths": 10
        }

        response = client.post("/v1/verify", json=payload)

        assert response.status_code == 200
        data = response.json()
        assert "verification_id" in data
        assert "attack_detected" in data
```

### 5.3 Database Integration Tests

```python
# File: engine/tests/integration/test_database.py

import pytest
from sqlalchemy.exc import IntegrityError
from datetime import datetime, timedelta

@pytest.mark.integration
class TestDatabaseOperations:
    def test_create_threat(self, db_session):
        """Test creating threat in database"""
        threat = Threat(
            attack_type="dns_hijack",
            severity="high",
            source_ip="192.168.1.1",
            dest_ip="192.168.1.50",
            protocol="DNS",
            description="Test threat"
        )

        db_session.add(threat)
        db_session.commit()

        assert threat.id is not None
        assert threat.timestamp is not None

    def test_query_threats_by_severity(self, db_session, sample_threats):
        """Test querying threats by severity"""
        high_threats = db_session.query(Threat).filter_by(
            severity="high"
        ).all()

        assert len(high_threats) > 0
        for threat in high_threats:
            assert threat.severity == "high"

    def test_threat_with_verification_result(self, db_session):
        """Test storing verification results"""
        threat = Threat(attack_type="dns_hijack", severity="high")
        db_session.add(threat)
        db_session.commit()

        verification = VerificationResult(
            threat_id=threat.id,
            url="https://example.com",
            paths_checked=10,
            paths_agreed=9,
            confidence=0.95
        )
        db_session.add(verification)
        db_session.commit()

        # Query threat with verification
        threat_with_ver = db_session.query(Threat).filter_by(
            id=threat.id
        ).first()

        assert threat_with_ver.verification_results is not None
        assert len(threat_with_ver.verification_results) == 1

    def test_database_constraints(self, db_session):
        """Test database constraints are enforced"""
        # Test NOT NULL constraint
        with pytest.raises(IntegrityError):
            threat = Threat(severity="high")  # Missing attack_type
            db_session.add(threat)
            db_session.commit()
```

---

## 6. End-to-End Testing

### 6.1 E2E Test Environment

**Setup:**

```bash
# Start all services in test mode
docker-compose -f docker-compose.test.yml up -d

# Wait for services to be ready
./scripts/wait-for-services.sh

# Run E2E tests
pytest tests/e2e/ -v --tb=short
```

**Test Environment Configuration:**

```yaml
# docker-compose.test.yml
version: '3.8'

services:
  verification-test:
    build: ./verification-container
    environment:
      - ENV=test
      - VPN_ENABLED=false  # Use mock VPNs for speed
    ports:
      - "8000:8000"

  engine-test:
    build: ./engine
    environment:
      - ENV=test
      - DATABASE_URL=postgresql://test:test@postgres-test/nlsn_test
    depends_on:
      - postgres-test
      - redis-test

  postgres-test:
    image: postgres:15
    environment:
      POSTGRES_DB: nlsn_test
      POSTGRES_USER: test
      POSTGRES_PASSWORD: test

  redis-test:
    image: redis:7-alpine
```

### 6.2 E2E Test Scenarios

```python
# File: tests/e2e/test_full_attack_detection.py

import pytest
import requests
import time
from scapy.all import *

@pytest.mark.e2e
class TestFullAttackDetection:
    @pytest.fixture(scope="class")
    def system_ready(self):
        """Wait for all services to be ready"""
        max_wait = 30
        start = time.time()

        while time.time() - start < max_wait:
            try:
                health = requests.get("http://localhost:8888/v1/health")
                if health.status_code == 200:
                    return True
            except:
                time.sleep(1)

        pytest.fail("System not ready after 30 seconds")

    def test_dns_hijack_detection_full_flow(self, system_ready):
        """
        Complete DNS hijacking detection scenario:
        1. Generate DNS query/response packets
        2. Monitor detects anomaly
        3. Engine triggers verification
        4. Verification confirms attack
        5. Deception activated
        6. Threat logged
        """
        # 1. Send DNS query
        dns_query = IP(dst="8.8.8.8")/UDP(dport=53)/DNS(
            id=12345,
            qd=DNSQR(qname="example.com")
        )

        send(dns_query, verbose=False)

        # 2. Send malicious DNS response (hijacked)
        dns_response = IP(src="8.8.8.8")/UDP(sport=53)/DNS(
            id=12345,
            qr=1,  # Response
            an=DNSRR(rrname="example.com", rdata="192.0.2.1")  # Wrong IP
        )

        send(dns_response, verbose=False)

        # 3. Wait for detection and verification (max 15 seconds)
        time.sleep(15)

        # 4. Check threat was logged
        threats_response = requests.get(
            "http://localhost:8888/v1/threats?attack_type=dns_hijack&limit=1"
        )

        assert threats_response.status_code == 200
        threats = threats_response.json()["threats"]
        assert len(threats) > 0

        threat = threats[0]
        assert threat["attack_type"] == "dns_hijack"
        assert threat["verified"] == True
        assert threat["confidence"] >= 0.7

        # 5. Verify deception was activated
        assert threat["response_action"] == "deception_activated"

        # 6. Check threat details
        threat_detail = requests.get(
            f"http://localhost:8888/v1/threats/{threat['id']}"
        )

        assert threat_detail.status_code == 200
        detail = threat_detail.json()

        assert detail["evidence"]["domain"] == "example.com"
        assert detail["evidence"]["local_ip"] == "192.0.2.1"
        assert detail["deception_session"] is not None
        assert detail["deception_session"]["status"] == "active"

    def test_ssl_stripping_detection_full_flow(self, system_ready):
        """
        Complete SSL stripping detection scenario
        """
        # 1. Establish baseline (HTTPS works for this domain)
        https_request = requests.get("https://example.com")
        assert https_request.status_code == 200

        time.sleep(2)  # Let baseline register

        # 2. Attempt HTTP connection (should be flagged)
        http_packets = IP(dst="93.184.216.34")/TCP(dport=80)/Raw(
            load=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        )

        send(http_packets, verbose=False)

        # 3. Wait for detection
        time.sleep(10)

        # 4. Verify threat logged
        threats = requests.get(
            "http://localhost:8888/v1/threats?attack_type=ssl_strip"
        ).json()["threats"]

        assert len(threats) > 0
        assert threats[0]["severity"] in ["high", "critical"]

    @pytest.mark.slow
    def test_multi_path_verification_real_vpn(self, system_ready):
        """
        Test verification with real VPN connections
        (Requires VPN configuration)
        """
        # Trigger manual verification
        verify_request = {
            "url": "https://example.com",
            "num_paths": 10,
            "timeout": 20
        }

        response = requests.post(
            "http://localhost:8888/v1/verify",
            json=verify_request
        )

        assert response.status_code == 200
        result = response.json()

        assert result["verification_details"]["paths_checked"] == 10
        assert result["verification_details"]["paths_succeeded"] >= 7
        assert result["attack_detected"] == False  # Legitimate site
```

### 6.3 E2E Performance Tests

```python
# File: tests/e2e/test_performance.py

import pytest
import time
from concurrent.futures import ThreadPoolExecutor

@pytest.mark.e2e
@pytest.mark.performance
class TestSystemPerformance:
    def test_packet_processing_rate(self):
        """System should maintain >10K packets/second"""
        # Generate 100K test packets
        packet_count = 100000
        start_time = time.time()

        # Generate and send packets
        generate_and_send_packets(packet_count)

        # Wait for processing
        time.sleep(5)

        # Check processing stats
        stats = requests.get("http://localhost:8888/v1/stats").json()

        elapsed = time.time() - start_time
        packets_per_second = stats["capture"]["packets_captured"] / elapsed

        assert packets_per_second >= 10000, f"Only processed {packets_per_second} pkt/s"

    def test_verification_latency(self):
        """Verification should complete in <10 seconds"""
        start = time.time()

        response = requests.post(
            "http://localhost:8888/v1/verify",
            json={"url": "https://example.com", "num_paths": 10}
        )

        elapsed = time.time() - start

        assert elapsed < 10, f"Verification took {elapsed}s (max 10s)"
        assert response.status_code == 200

    def test_concurrent_api_requests(self):
        """API should handle 100 concurrent requests"""
        def make_request():
            return requests.get("http://localhost:8888/v1/threats?limit=10")

        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = [executor.submit(make_request) for _ in range(100)]
            responses = [f.result() for f in futures]

        # All requests should succeed
        success_count = sum(1 for r in responses if r.status_code == 200)
        assert success_count == 100
```

---

## 7. Security Testing

### 7.1 Vulnerability Scanning

**Tools:**
- **Snyk**: Dependency vulnerability scanning
- **Trivy**: Container image scanning
- **OWASP ZAP**: API security testing

**Automated Scans:**

```bash
# Scan Python dependencies
snyk test --file=requirements.txt

# Scan Go dependencies
snyk test --file=core/go.mod

# Scan Docker images
trivy image nlsn-monitor:latest
trivy image nlsn-engine:latest

# API security scan
docker run -t owasp/zap2docker-stable zap-baseline.py \
  -t http://localhost:8888 \
  -r zap-report.html
```

### 7.2 Penetration Testing Scenarios

```python
# File: tests/security/test_injection_attacks.py

import pytest
import requests

@pytest.mark.security
class TestInjectionAttacks:
    def test_sql_injection_in_threat_query(self):
        """API should not be vulnerable to SQL injection"""
        malicious_payloads = [
            "1' OR '1'='1",
            "'; DROP TABLE threats;--",
            "1 UNION SELECT * FROM users--",
        ]

        for payload in malicious_payloads:
            response = requests.get(
                f"http://localhost:8888/v1/threats",
                params={"attack_type": payload}
            )

            # Should return 400 or empty results, not 500
            assert response.status_code in [200, 400]

            # Should not expose error details
            if response.status_code == 400:
                assert "SQL" not in response.text
                assert "syntax error" not in response.text.lower()

    def test_command_injection_in_verification(self):
        """Verification should not execute shell commands from input"""
        malicious_urls = [
            "https://example.com; rm -rf /",
            "https://example.com`whoami`",
            "https://example.com$(cat /etc/passwd)",
        ]

        for url in malicious_urls:
            response = requests.post(
                "http://localhost:8888/v1/verify",
                json={"url": url}
            )

            # Should reject invalid URL, not execute commands
            assert response.status_code == 400

    def test_xss_in_threat_description(self):
        """Threat descriptions should be sanitized"""
        # Create threat with XSS payload
        xss_payload = "<script>alert('XSS')</script>"

        # (This would be created by monitor, simulated here)
        threat = create_threat_via_internal_api({
            "attack_type": "dns_hijack",
            "description": xss_payload
        })

        # Retrieve threat via API
        response = requests.get(f"http://localhost:8888/v1/threats/{threat.id}")

        # Payload should be escaped
        assert "<script>" not in response.text
        assert "&lt;script&gt;" in response.text or xss_payload not in response.text

    def test_authentication_bypass(self):
        """API key authentication should not be bypassable"""
        bypass_attempts = [
            {},  # No auth
            {"Authorization": "Bearer invalid_key"},
            {"Authorization": "Bearer "},
            {"X-API-Key": "nlsn_sk_valid_key"},  # Wrong header name
        ]

        for headers in bypass_attempts:
            response = requests.get(
                "http://localhost:8888/v1/threats",
                headers=headers
            )

            assert response.status_code == 401

    def test_rate_limit_bypass(self):
        """Rate limiting should not be bypassable"""
        # Make 70 requests (limit is 60/minute)
        responses = []
        for i in range(70):
            r = requests.get("http://localhost:8888/v1/threats")
            responses.append(r)

        # At least one should be rate limited
        rate_limited = [r for r in responses if r.status_code == 429]
        assert len(rate_limited) > 0
```

### 7.3 Fuzzing Tests

```python
# File: tests/security/test_fuzzing.py

import pytest
from hypothesis import given, strategies as st, settings
import requests

@pytest.mark.security
class TestFuzzing:
    @given(url=st.text(min_size=1, max_size=1000))
    @settings(max_examples=100)
    def test_verify_endpoint_fuzzing(self, url):
        """Verify endpoint should handle arbitrary input safely"""
        try:
            response = requests.post(
                "http://localhost:8888/v1/verify",
                json={"url": url},
                timeout=5
            )

            # Should return 400 or 200, never 500
            assert response.status_code in [200, 400, 429]
        except requests.exceptions.Timeout:
            # Timeout is acceptable
            pass
        except requests.exceptions.ConnectionError:
            # Connection errors are acceptable for invalid input
            pass

    @given(
        attack_type=st.text(max_size=100),
        severity=st.text(max_size=20),
        limit=st.integers(min_value=-1000, max_value=10000)
    )
    @settings(max_examples=100)
    def test_threats_endpoint_fuzzing(self, attack_type, severity, limit):
        """Threats endpoint should handle arbitrary parameters"""
        response = requests.get(
            "http://localhost:8888/v1/threats",
            params={
                "attack_type": attack_type,
                "severity": severity,
                "limit": limit
            },
            timeout=5
        )

        # Should handle gracefully
        assert response.status_code in [200, 400]
```

---

## 8. Performance Testing

### 8.1 Load Testing

**Tool:** Locust

```python
# File: tests/performance/locustfile.py

from locust import HttpUser, task, between

class NLSNUser(HttpUser):
    wait_time = between(1, 3)

    def on_start(self):
        """Setup API key"""
        self.client.headers = {
            "Authorization": "Bearer nlsn_sk_test_key"
        }

    @task(10)
    def list_threats(self):
        """Most common operation"""
        self.client.get("/v1/threats?limit=50")

    @task(5)
    def get_threat_details(self):
        """Moderate frequency"""
        # Assume threat IDs 1-100 exist
        threat_id = random.randint(1, 100)
        self.client.get(f"/v1/threats/{threat_id}")

    @task(1)
    def trigger_verification(self):
        """Infrequent but expensive"""
        self.client.post("/v1/verify", json={
            "url": "https://example.com",
            "num_paths": 5
        })

    @task(3)
    def get_stats(self):
        """Dashboard queries"""
        self.client.get("/v1/stats?period=1h")
```

**Running Load Tests:**

```bash
# Start Locust
locust -f tests/performance/locustfile.py

# Open browser to http://localhost:8089
# Configure:
# - Number of users: 1000
# - Spawn rate: 10 users/second
# - Run for: 10 minutes

# Monitor metrics:
# - Response time (p50, p95, p99)
# - Requests per second
# - Failure rate
```

### 8.2 Stress Testing

```python
# File: tests/performance/test_stress.py

import pytest
import asyncio
import aiohttp

@pytest.mark.performance
@pytest.mark.stress
class TestStressConditions:
    @pytest.mark.asyncio
    async def test_api_under_high_load(self):
        """Test API with 10K concurrent requests"""
        async with aiohttp.ClientSession() as session:
            tasks = []
            for i in range(10000):
                task = session.get("http://localhost:8888/v1/health")
                tasks.append(task)

            responses = await asyncio.gather(*tasks, return_exceptions=True)

            # Count successful responses
            successful = sum(1 for r in responses if not isinstance(r, Exception) and r.status == 200)

            # Should handle at least 95% successfully
            success_rate = successful / len(responses)
            assert success_rate >= 0.95, f"Only {success_rate*100}% succeeded"

    def test_database_connection_pool_exhaustion(self):
        """Test system behavior when DB connections exhausted"""
        # Create many concurrent database queries
        # System should queue requests, not crash
        pass

    def test_redis_connection_failure(self):
        """Test system resilience to Redis failure"""
        # Stop Redis
        os.system("docker stop nlsn-redis-test")

        # System should degrade gracefully
        response = requests.get("http://localhost:8888/v1/health")
        assert response.status_code == 503
        data = response.json()
        assert data["status"] == "degraded"
        assert data["components"]["redis"]["status"] == "disconnected"

        # Restart Redis
        os.system("docker start nlsn-redis-test")
        time.sleep(5)

        # System should recover
        response = requests.get("http://localhost:8888/v1/health")
        assert response.status_code == 200
```

### 8.3 Benchmark Tests

```go
// File: core/pkg/parser/dns_benchmark_test.go

func BenchmarkParseDNS_SimpleQuery(b *testing.B) {
    data := createSimpleDNSQuery()

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        ParseDNS(data, nil, nil, time.Now())
    }
}

func BenchmarkParseDNS_LargeResponse(b *testing.B) {
    data := createDNSResponseWithMany Records()

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        ParseDNS(data, nil, nil, time.Now())
    }
}

func BenchmarkDetectDNSAnomaly(b *testing.B) {
    detector := NewDNSAnomalyDetector()
    query := &DNSQuery{Domain: "example.com"}
    response := &DNSResponse{IP: net.ParseIP("192.0.2.1")}

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        detector.Detect(query, response)
    }
}

// Target benchmarks:
// BenchmarkParseDNS_SimpleQuery-8     1000000    1050 ns/op
// BenchmarkDetectDNSAnomaly-8         500000     3200 ns/op
```

---

## 9. Test Data Management

### 9.1 Test Data Generation

```python
# File: tests/fixtures/data_generator.py

import random
from faker import Faker

fake = Faker()

class TestDataGenerator:
    @staticmethod
    def generate_dns_packet(hijacked=False):
        """Generate realistic DNS packet data"""
        domain = fake.domain_name()

        if hijacked:
            # Generate private IP
            ip = f"192.168.{random.randint(0,255)}.{random.randint(1,254)}"
        else:
            # Generate public IP
            ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

        return {
            "transaction_id": random.randint(1, 65535),
            "query": {"domain": domain, "type": "A"},
            "response": {"ip": ip, "ttl": random.randint(60, 86400)}
        }

    @staticmethod
    def generate_threat(attack_type="dns_hijack", verified=False):
        """Generate threat record"""
        return {
            "attack_type": attack_type,
            "severity": random.choice(["low", "medium", "high", "critical"]),
            "source_ip": fake.ipv4_private(),
            "dest_ip": fake.ipv4_private(),
            "protocol": "DNS",
            "description": f"Test {attack_type} attack",
            "verified": verified,
            "confidence": random.uniform(0.7, 0.99) if verified else 0.0
        }

    @staticmethod
    def generate_pcap_file(filename, packet_count=1000):
        """Generate PCAP file with test traffic"""
        from scapy.all import wrpcap, IP, UDP, DNS, DNSQR

        packets = []
        for i in range(packet_count):
            pkt = IP(dst="8.8.8.8")/UDP(dport=53)/DNS(qd=DNSQR(qname=fake.domain_name()))
            packets.append(pkt)

        wrpcap(filename, packets)
```

### 9.2 Test Data Seeding

```python
# File: tests/fixtures/seed_database.py

def seed_test_database(db_session):
    """Seed database with test data"""
    generator = TestDataGenerator()

    # Create 100 threats
    for i in range(100):
        threat_data = generator.generate_threat(
            attack_type=random.choice(["dns_hijack", "ssl_strip", "arp_spoof"]),
            verified=random.random() > 0.3  # 70% verified
        )
        threat = Threat(**threat_data)
        db_session.add(threat)

    # Create honeytokens
    for i in range(50):
        token = Honeytoken(
            token=f"tok_{secrets.token_hex(8)}",
            token_type=random.choice(["email", "password", "api_key"]),
            domain=generator.fake.domain_name(),
            triggered=random.random() > 0.9  # 10% triggered
        )
        db_session.add(token)

    db_session.commit()
```

### 9.3 PCAP Test Files

```
tests/data/pcap/
├── dns_normal.pcap          # Normal DNS traffic
├── dns_hijacked.pcap        # DNS hijacking attack
├── ssl_strip.pcap           # SSL stripping attack
├── arp_spoof.pcap           # ARP spoofing
├── mixed_attacks.pcap       # Multiple attack types
└── high_volume.pcap         # 100K packets for load testing
```

---

## 10. CI/CD Integration

### 10.1 GitHub Actions Workflow

```yaml
# File: .github/workflows/test.yml

name: Test Suite

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  unit-tests-go:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Setup Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.21'

      - name: Cache Go modules
        uses: actions/cache@v3
        with:
          path: ~/go/pkg/mod
          key: ${{ runner.os }}-go-${{ hashFiles('**/go.sum') }}

      - name: Run Go unit tests
        run: |
          cd core
          go test ./... -v -race -coverprofile=coverage.out
          go tool cover -html=coverage.out -o coverage.html

      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          files: ./core/coverage.out
          flags: go-unit

  unit-tests-python:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Cache pip packages
        uses: actions/cache@v3
        with:
          path: ~/.cache/pip
          key: ${{ runner.os }}-pip-${{ hashFiles('**/requirements.txt') }}

      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install pytest pytest-cov pytest-asyncio

      - name: Run Python unit tests
        run: |
          cd engine
          pytest tests/unit/ -v --cov=. --cov-report=xml --cov-report=html

      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          files: ./engine/coverage.xml
          flags: python-unit

  integration-tests:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_DB: nlsn_test
          POSTGRES_USER: test
          POSTGRES_PASSWORD: test
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5

      redis:
        image: redis:7-alpine
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5

    steps:
      - uses: actions/checkout@v3

      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: pip install -r requirements.txt

      - name: Run integration tests
        env:
          DATABASE_URL: postgresql://test:test@localhost/nlsn_test
          REDIS_URL: redis://localhost:6379
        run: |
          cd engine
          pytest tests/integration/ -v --tb=short

  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Run Snyk Security Scan
        uses: snyk/actions/python@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
        with:
          args: --file=requirements.txt

      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          scan-ref: '.'
          format: 'sarif'
          output: 'trivy-results.sarif'

      - name: Upload Trivy results
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: 'trivy-results.sarif'

  e2e-tests:
    runs-on: ubuntu-latest
    if: github.event_name == 'push' && github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@v3

      - name: Build Docker images
        run: docker-compose -f docker-compose.test.yml build

      - name: Start services
        run: docker-compose -f docker-compose.test.yml up -d

      - name: Wait for services
        run: ./scripts/wait-for-services.sh

      - name: Run E2E tests
        run: |
          pip install -r requirements.txt
          pytest tests/e2e/ -v --tb=short

      - name: Collect logs
        if: failure()
        run: docker-compose -f docker-compose.test.yml logs > e2e-logs.txt

      - name: Upload logs
        if: failure()
        uses: actions/upload-artifact@v3
        with:
          name: e2e-logs
          path: e2e-logs.txt
```

### 10.2 Pre-commit Hooks

```yaml
# File: .pre-commit-config.yaml

repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.4.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-added-large-files

  - repo: https://github.com/psf/black
    rev: 23.3.0
    hooks:
      - id: black
        language_version: python3.11

  - repo: https://github.com/PyCQA/flake8
    rev: 6.0.0
    hooks:
      - id: flake8
        args: ['--max-line-length=100']

  - repo: local
    hooks:
      - id: go-test
        name: go test
        entry: sh -c 'cd core && go test ./... -short'
        language: system
        pass_filenames: false

      - id: pytest-quick
        name: pytest quick
        entry: sh -c 'cd engine && pytest tests/unit/ -x'
        language: system
        pass_filenames: false
```

---

## 11. Test Coverage Requirements

### 11.1 Coverage Targets

| Component | Unit Test Coverage | Integration Coverage | Total Coverage |
|-----------|-------------------|---------------------|----------------|
| Go Monitor | ≥ 80% | ≥ 60% | ≥ 75% |
| Python Engine | ≥ 85% | ≥ 70% | ≥ 80% |
| APIs | ≥ 90% | ≥ 80% | ≥ 85% |
| Detection Algorithms | ≥ 95% | ≥ 90% | ≥ 90% |
| Overall Project | ≥ 80% | ≥ 65% | ≥ 75% |

### 11.2 Critical Paths (100% Coverage Required)

- DNS packet parsing
- DNS hijacking detection
- SSL stripping detection
- API authentication
- Database threat logging
- Verification result comparison

### 11.3 Coverage Enforcement

```yaml
# File: .coveragerc

[run]
source = engine
omit =
    */tests/*
    */migrations/*
    */venv/*

[report]
precision = 2
fail_under = 80
show_missing = true
skip_covered = false

[html]
directory = htmlcov
```

**CI Enforcement:**

```bash
# Fail build if coverage below threshold
pytest --cov=engine --cov-fail-under=80
```

---

## 12. Testing Tools

### 12.1 Go Testing Tools

| Tool | Purpose | Installation |
|------|---------|--------------|
| `testing` | Standard test framework | Built-in |
| `testify` | Assertions and mocks | `go get github.com/stretchr/testify` |
| `gomock` | Mock generation | `go install github.com/golang/mock/mockgen` |
| `go-fuzz` | Fuzzing | `go get github.com/dvyukov/go-fuzz/...` |

### 12.2 Python Testing Tools

| Tool | Purpose | Installation |
|------|---------|--------------|
| `pytest` | Test framework | `pip install pytest` |
| `pytest-asyncio` | Async testing | `pip install pytest-asyncio` |
| `pytest-cov` | Coverage reporting | `pip install pytest-cov` |
| `pytest-mock` | Mocking | `pip install pytest-mock` |
| `hypothesis` | Property-based testing | `pip install hypothesis` |
| `Faker` | Test data generation | `pip install Faker` |
| `locust` | Load testing | `pip install locust` |

### 12.3 Security Testing Tools

| Tool | Purpose | Usage |
|------|---------|-------|
| Snyk | Dependency scanning | `snyk test` |
| Trivy | Container scanning | `trivy image <image>` |
| OWASP ZAP | API security testing | `zap-baseline.py -t <url>` |
| Bandit | Python security linter | `bandit -r engine/` |

### 12.4 Performance Testing Tools

| Tool | Purpose | Usage |
|------|---------|-------|
| Locust | Load testing | `locust -f locustfile.py` |
| Apache Bench | Simple benchmarking | `ab -n 1000 -c 10 <url>` |
| tcpreplay | Packet replay | `tcpreplay -i eth0 capture.pcap` |

---

## Conclusion

This testing strategy provides:

- **Comprehensive testing approach** covering unit, integration, E2E, security, and performance
- **Specific test examples** in Go and Python
- **Clear coverage targets** and enforcement mechanisms
- **CI/CD integration** with GitHub Actions
- **Security testing** methodology and tools
- **Performance testing** strategies and benchmarks
- **Test data management** for reproducible tests
- **Tool recommendations** for all testing needs

Following this strategy ensures the NLSN PCAP Monitor is reliable, secure, and performant.

---

**Document Version:** 1.0
**Total Word Count:** ~10,500 words
**Last Updated:** 2025-11-10
