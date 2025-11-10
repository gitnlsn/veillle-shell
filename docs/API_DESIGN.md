# API Design Specification

**Version:** 1.0
**Last Updated:** 2025-11-10
**Project:** NLSN PCAP Monitor

---

## Table of Contents

1. [Introduction](#introduction)
2. [API Architecture](#api-architecture)
3. [Verification Container API](#verification-container-api)
4. [Engine API](#engine-api)
5. [Internal Event API](#internal-event-api)
6. [Error Handling](#error-handling)
7. [Authentication & Authorization](#authentication--authorization)
8. [Rate Limiting](#rate-limiting)
9. [API Versioning](#api-versioning)
10. [WebSocket API](#websocket-api)
11. [API Client Libraries](#api-client-libraries)

---

## 1. Introduction

This document provides complete API specifications for all public and internal APIs in the NLSN PCAP Monitor system. It defines request/response formats, error handling, authentication, and usage guidelines.

### 1.1 API Overview

The system exposes two primary HTTP APIs:

1. **Verification Container API** (Port 8000): Multi-path verification service
2. **Engine API** (Port 8888): System orchestration and threat intelligence

Internal communication uses Redis pub/sub for event-driven architecture.

### 1.2 Design Principles

- **RESTful**: Standard HTTP methods (GET, POST, PUT, DELETE)
- **JSON**: All request/response bodies use JSON
- **Idempotent**: Safe operations (GET, PUT, DELETE) are idempotent
- **Versioned**: APIs include version in path (/v1/)
- **Consistent**: Uniform error handling and response formats
- **Documented**: OpenAPI/Swagger documentation available

### 1.3 Base URLs

```
Verification Container: http://verification:8000/v1
Engine API:             http://engine:8888/v1
```

For external access (via Docker Compose port mapping):
```
Verification Container: http://localhost:8000/v1
Engine API:             http://localhost:8888/v1
```

---

## 2. API Architecture

### 2.1 Communication Patterns

```
┌─────────────┐
│   Client    │
│  (Browser)  │
└──────┬──────┘
       │ HTTP/REST
       ↓
┌─────────────────────┐
│   Engine API        │
│   (Python/FastAPI)  │
└──────┬──────────────┘
       │ HTTP
       ↓
┌─────────────────────┐       ┌──────────────┐
│ Verification API    │       │ Go Monitor   │
│ (Python/FastAPI)    │       │              │
└─────────────────────┘       └──────┬───────┘
                                     │
                              Redis Pub/Sub
                                     │
                              ┌──────┴───────┐
                              │ Event Bus    │
                              └──────────────┘
```

### 2.2 Request Flow

1. **User Request** → Engine API
2. **Engine** processes, may call Verification API
3. **Verification** performs multi-path checks
4. **Results** returned to Engine
5. **Engine** may publish events to Redis
6. **Engine** returns response to user

### 2.3 Synchronous vs Asynchronous

| Operation | Type | Reason |
|-----------|------|--------|
| Verification | Synchronous | User waits for result (5-15s acceptable) |
| Threat Logging | Asynchronous | Background database write |
| Deception Activation | Asynchronous | Triggered by events |
| Statistics | Synchronous | Cached, fast response |

---

## 3. Verification Container API

### 3.1 API Overview

The Verification Container provides multi-path verification through VPN/Tor/Proxy paths.

**Base URL:** `http://verification:8000/v1`

**Technology:** Python 3.11 + FastAPI + Uvicorn

**Authentication:** None (internal service)

### 3.2 Endpoints

#### 3.2.1 Health Check

**Endpoint:** `GET /health`

**Description:** Check service health and VPN connection status

**Request:** None

**Response:** 200 OK

```json
{
  "status": "healthy",
  "timestamp": "2025-11-10T14:32:15.123Z",
  "vpns_connected": 10,
  "total_paths": 40,
  "available_paths": 38,
  "uptime_seconds": 3600
}
```

**Response Fields:**
- `status`: "healthy" | "degraded" | "unhealthy"
- `timestamp`: Current server time (ISO 8601)
- `vpns_connected`: Number of VPNs successfully connected (0-10)
- `total_paths`: Total configured paths (typically 40)
- `available_paths`: Number of currently available paths
- `uptime_seconds`: Service uptime in seconds

**Status Codes:**
- `200 OK`: Service is healthy
- `503 Service Unavailable`: Service is unhealthy

**Example:**

```bash
curl http://localhost:8000/v1/health
```

---

#### 3.2.2 List Available Paths

**Endpoint:** `GET /paths`

**Description:** List all available verification paths with status

**Request:** None

**Response:** 200 OK

```json
{
  "total": 40,
  "available": 38,
  "paths": [
    {
      "id": "vpn-0-direct",
      "vpn_location": "us-nyc",
      "vpn_namespace": "vpn-ns-0",
      "method": "direct",
      "status": "available",
      "last_success": "2025-11-10T14:30:00.000Z",
      "success_rate": 0.98,
      "avg_latency_ms": 120
    },
    {
      "id": "vpn-0-tor",
      "vpn_location": "us-nyc",
      "vpn_namespace": "vpn-ns-0",
      "method": "tor",
      "status": "available",
      "last_success": "2025-11-10T14:31:00.000Z",
      "success_rate": 0.95,
      "avg_latency_ms": 850
    },
    {
      "id": "vpn-0-proxy",
      "vpn_location": "us-nyc",
      "vpn_namespace": "vpn-ns-0",
      "method": "http_proxy",
      "status": "unavailable",
      "last_success": "2025-11-10T14:10:00.000Z",
      "success_rate": 0.92,
      "avg_latency_ms": 250,
      "error": "Connection timeout"
    }
    // ... (40 total paths)
  ]
}
```

**Path Object Fields:**
- `id`: Unique path identifier
- `vpn_location`: VPN server location (e.g., "us-nyc", "uk-lon")
- `vpn_namespace`: Linux network namespace name
- `method`: Routing method ("direct", "tor", "http_proxy", "tor+proxy")
- `status`: "available" | "unavailable" | "degraded"
- `last_success`: Timestamp of last successful request (ISO 8601)
- `success_rate`: Success rate over last 100 requests (0.0-1.0)
- `avg_latency_ms`: Average latency in milliseconds
- `error`: Error message (if unavailable)

**Status Codes:**
- `200 OK`: Success

**Example:**

```bash
curl http://localhost:8000/v1/paths
```

---

#### 3.2.3 Verify URL

**Endpoint:** `POST /verify`

**Description:** Verify a URL through multiple independent paths

**Request Body:**

```json
{
  "url": "https://example.com",
  "num_paths": 10,
  "timeout": 15,
  "strategy": "diverse",
  "compare_method": "content_hash"
}
```

**Request Fields:**
- `url` (required): URL to verify (must be valid HTTP/HTTPS URL)
- `num_paths` (optional): Number of paths to use (default: 10, min: 3, max: 40)
- `timeout` (optional): Timeout per path in seconds (default: 15, max: 30)
- `strategy` (optional): Path selection strategy ("diverse" | "fastest" | "reliable" | "balanced", default: "diverse")
- `compare_method` (optional): Comparison method ("content_hash" | "full_content" | "headers_only", default: "content_hash")

**Response:** 200 OK

```json
{
  "url": "https://example.com",
  "timestamp": "2025-11-10T14:32:15.123Z",
  "attack_detected": false,
  "confidence": "HIGH",
  "paths_checked": 10,
  "paths_succeeded": 9,
  "paths_agreed": 9,
  "consensus_percentage": 100.0,
  "verification_duration_ms": 7843,
  "consensus": {
    "status_code": 200,
    "content_hash": "a3c5f8d9e2b1c4a7f6e8d2c1b5a9f3e7",
    "content_length": 1256,
    "headers": {
      "content-type": "text/html; charset=UTF-8",
      "server": "ECS (dcb/7F83)"
    }
  },
  "outliers": [],
  "differences": [],
  "path_results": [
    {
      "path_id": "vpn-0-direct",
      "status": "success",
      "status_code": 200,
      "content_hash": "a3c5f8d9e2b1c4a7f6e8d2c1b5a9f3e7",
      "latency_ms": 342,
      "agreed_with_consensus": true
    },
    {
      "path_id": "vpn-1-tor",
      "status": "success",
      "status_code": 200,
      "content_hash": "a3c5f8d9e2b1c4a7f6e8d2c1b5a9f3e7",
      "latency_ms": 1205,
      "agreed_with_consensus": true
    },
    {
      "path_id": "vpn-2-proxy",
      "status": "failed",
      "error": "Connection timeout",
      "latency_ms": 15000
    }
    // ... (10 total results)
  ],
  "recommendations": [
    "No attack detected. All paths agree on response."
  ]
}
```

**Response with Attack Detected:**

```json
{
  "url": "https://example.com",
  "timestamp": "2025-11-10T14:32:15.123Z",
  "attack_detected": true,
  "confidence": "HIGH",
  "paths_checked": 10,
  "paths_succeeded": 10,
  "paths_agreed": 8,
  "consensus_percentage": 80.0,
  "verification_duration_ms": 8124,
  "consensus": {
    "status_code": 200,
    "content_hash": "a3c5f8d9e2b1c4a7f6e8d2c1b5a9f3e7",
    "content_length": 1256,
    "headers": {
      "content-type": "text/html; charset=UTF-8",
      "server": "ECS (dcb/7F83)"
    }
  },
  "outliers": [
    {
      "path_id": "local",
      "status_code": 200,
      "content_hash": "b2d4e6f8a1c3d5e7b9f1a3c5e7d9b1f3",
      "content_length": 847
    },
    {
      "path_id": "vpn-0-direct",
      "status_code": 200,
      "content_hash": "b2d4e6f8a1c3d5e7b9f1a3c5e7d9b1f3",
      "content_length": 847
    }
  ],
  "differences": [
    {
      "path": "local",
      "field": "content_hash",
      "local_value": "b2d4e6f8a1c3d5e7b9f1a3c5e7d9b1f3",
      "consensus_value": "a3c5f8d9e2b1c4a7f6e8d2c1b5a9f3e7"
    },
    {
      "path": "local",
      "field": "content_length",
      "local_value": 847,
      "consensus_value": 1256
    },
    {
      "path": "local",
      "field": "header.server",
      "local_value": "nginx/1.18.0",
      "consensus_value": "ECS (dcb/7F83)"
    }
  ],
  "path_results": [
    // ... (same format as above)
  ],
  "recommendations": [
    "ATTACK DETECTED: Local response differs from 80% of verification paths.",
    "Content has been modified (different hash and length).",
    "Server header differs from expected value.",
    "Action: Activate deception layer and log threat."
  ]
}
```

**Response Fields:**
- `attack_detected`: Boolean indicating if attack was detected
- `confidence`: "LOW" | "MEDIUM" | "HIGH" | "VERY_HIGH"
- `paths_checked`: Number of paths attempted
- `paths_succeeded`: Number of paths that successfully completed
- `paths_agreed`: Number of paths agreeing with consensus
- `consensus_percentage`: Percentage of paths agreeing (0-100)
- `verification_duration_ms`: Total verification time
- `consensus`: The majority response
- `outliers`: Paths that disagreed with consensus
- `differences`: Specific differences between outliers and consensus
- `path_results`: Detailed results for each path
- `recommendations`: Human-readable action recommendations

**Confidence Levels:**
- `VERY_HIGH`: 90%+ agreement
- `HIGH`: 70-89% agreement
- `MEDIUM`: 50-69% agreement
- `LOW`: <50% agreement

**Status Codes:**
- `200 OK`: Verification completed
- `400 Bad Request`: Invalid request parameters
- `429 Too Many Requests`: Rate limit exceeded
- `503 Service Unavailable`: Not enough paths available

**Example:**

```bash
curl -X POST http://localhost:8000/v1/verify \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com",
    "num_paths": 10,
    "timeout": 15
  }'
```

---

#### 3.2.4 Verify DNS

**Endpoint:** `POST /verify-dns`

**Description:** Verify DNS resolution through multiple paths

**Request Body:**

```json
{
  "domain": "example.com",
  "record_type": "A",
  "num_paths": 10,
  "timeout": 10
}
```

**Request Fields:**
- `domain` (required): Domain name to resolve
- `record_type` (optional): DNS record type ("A" | "AAAA" | "MX" | "TXT", default: "A")
- `num_paths` (optional): Number of paths to use (default: 10)
- `timeout` (optional): Timeout per path in seconds (default: 10)

**Response:** 200 OK

```json
{
  "domain": "example.com",
  "record_type": "A",
  "timestamp": "2025-11-10T14:32:15.123Z",
  "attack_detected": false,
  "confidence": "VERY_HIGH",
  "paths_checked": 10,
  "paths_succeeded": 10,
  "paths_agreed": 10,
  "consensus_ips": ["93.184.216.34"],
  "verification_duration_ms": 3245,
  "path_results": [
    {
      "path_id": "vpn-0-direct",
      "status": "success",
      "ips": ["93.184.216.34"],
      "latency_ms": 45,
      "agreed_with_consensus": true
    }
    // ... (10 total)
  ],
  "outliers": [],
  "recommendations": [
    "DNS resolution is consistent across all paths."
  ]
}
```

**Response with DNS Hijacking:**

```json
{
  "domain": "example.com",
  "record_type": "A",
  "timestamp": "2025-11-10T14:32:15.123Z",
  "attack_detected": true,
  "confidence": "HIGH",
  "paths_checked": 10,
  "paths_succeeded": 10,
  "paths_agreed": 8,
  "consensus_ips": ["93.184.216.34"],
  "local_ips": ["192.0.2.1"],
  "verification_duration_ms": 3512,
  "path_results": [
    // ...
  ],
  "outliers": [
    {
      "path_id": "local",
      "ips": ["192.0.2.1"],
      "agreed_with_consensus": false
    }
  ],
  "recommendations": [
    "DNS HIJACKING DETECTED: Local DNS returns different IP.",
    "Local IP: 192.0.2.1 (private address)",
    "Expected IP: 93.184.216.34 (verified through 8 paths)",
    "Action: Activate deception and log threat."
  ]
}
```

**Status Codes:**
- `200 OK`: Verification completed
- `400 Bad Request`: Invalid domain or parameters
- `429 Too Many Requests`: Rate limit exceeded

**Example:**

```bash
curl -X POST http://localhost:8000/v1/verify-dns \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "record_type": "A",
    "num_paths": 10
  }'
```

---

#### 3.2.5 Get Statistics

**Endpoint:** `GET /stats`

**Description:** Get verification statistics

**Request:** None

**Response:** 200 OK

```json
{
  "uptime_seconds": 86400,
  "total_verifications": 1543,
  "attacks_detected": 12,
  "attack_rate": 0.0078,
  "average_verification_time_ms": 7234,
  "path_statistics": {
    "total_paths": 40,
    "available_paths": 38,
    "average_success_rate": 0.96,
    "fastest_path": {
      "id": "vpn-0-direct",
      "avg_latency_ms": 120
    },
    "slowest_path": {
      "id": "vpn-5-tor",
      "avg_latency_ms": 1850
    }
  },
  "last_24h": {
    "verifications": 342,
    "attacks_detected": 3,
    "average_duration_ms": 6890
  }
}
```

**Status Codes:**
- `200 OK`: Success

**Example:**

```bash
curl http://localhost:8000/v1/stats
```

---

### 3.3 Verification API Error Responses

All error responses follow this format:

```json
{
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable error message",
    "details": {
      "field": "url",
      "reason": "Invalid URL format"
    }
  },
  "timestamp": "2025-11-10T14:32:15.123Z",
  "request_id": "req_abc123"
}
```

**Common Error Codes:**

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `INVALID_URL` | 400 | URL is malformed or invalid |
| `INVALID_DOMAIN` | 400 | Domain name is invalid |
| `INVALID_NUM_PATHS` | 400 | num_paths out of range (3-40) |
| `INVALID_TIMEOUT` | 400 | timeout out of range (1-30) |
| `INSUFFICIENT_PATHS` | 503 | Not enough paths available |
| `RATE_LIMIT_EXCEEDED` | 429 | Too many requests |
| `VERIFICATION_TIMEOUT` | 504 | Verification took too long |
| `INTERNAL_ERROR` | 500 | Unexpected server error |

---

## 4. Engine API

### 4.1 API Overview

The Engine API provides system orchestration, threat intelligence, and deception control.

**Base URL:** `http://engine:8888/v1`

**Technology:** Python 3.11 + FastAPI + Uvicorn

**Authentication:** API Key (for external access)

### 4.2 Endpoints

#### 4.2.1 Health Check

**Endpoint:** `GET /health`

**Description:** Check engine health and component status

**Request:** None

**Response:** 200 OK

```json
{
  "status": "healthy",
  "timestamp": "2025-11-10T14:32:15.123Z",
  "components": {
    "monitor": {
      "status": "running",
      "packets_captured": 1543234,
      "last_heartbeat": "2025-11-10T14:32:10.000Z"
    },
    "verification": {
      "status": "available",
      "paths_available": 38,
      "last_check": "2025-11-10T14:32:00.000Z"
    },
    "database": {
      "status": "connected",
      "threats_logged": 47
    },
    "redis": {
      "status": "connected",
      "events_processed": 98234
    },
    "deception": {
      "status": "idle",
      "active_sessions": 0
    }
  },
  "system": {
    "cpu_percent": 23.5,
    "memory_mb": 487,
    "uptime_seconds": 86400
  }
}
```

**Status Codes:**
- `200 OK`: Service is healthy
- `503 Service Unavailable`: Service or critical component is unhealthy

---

#### 4.2.2 Manual Verification

**Endpoint:** `POST /verify`

**Description:** Manually trigger URL verification (proxies to Verification Container)

**Request Body:**

```json
{
  "url": "https://example.com",
  "num_paths": 10,
  "auto_deception": true
}
```

**Request Fields:**
- `url` (required): URL to verify
- `num_paths` (optional): Number of paths (default: 10)
- `auto_deception` (optional): Automatically activate deception if attack detected (default: true)

**Response:** 200 OK

```json
{
  "verification_id": "ver_abc123",
  "url": "https://example.com",
  "attack_detected": true,
  "confidence": "HIGH",
  "threat_id": "thr_def456",
  "deception_activated": true,
  "deception_session_id": "dec_ghi789",
  "verification_details": {
    // ... (same as Verification API response)
  }
}
```

**Status Codes:**
- `200 OK`: Verification completed
- `400 Bad Request`: Invalid parameters
- `503 Service Unavailable`: Verification service unavailable

---

#### 4.2.3 List Threats

**Endpoint:** `GET /threats`

**Description:** Get paginated list of detected threats

**Query Parameters:**
- `limit` (optional): Number of results per page (default: 100, max: 1000)
- `offset` (optional): Pagination offset (default: 0)
- `attack_type` (optional): Filter by attack type
- `severity` (optional): Filter by severity ("low" | "medium" | "high" | "critical")
- `verified` (optional): Filter by verification status (true | false)
- `since` (optional): Filter by timestamp (ISO 8601)

**Response:** 200 OK

```json
{
  "total": 47,
  "limit": 100,
  "offset": 0,
  "threats": [
    {
      "id": "thr_abc123",
      "timestamp": "2025-11-10T14:30:00.000Z",
      "attack_type": "dns_hijack",
      "severity": "high",
      "source_ip": "192.168.1.1",
      "dest_ip": "192.168.1.50",
      "protocol": "DNS",
      "description": "DNS hijacking detected for example.com",
      "verified": true,
      "confidence": 0.95,
      "response_action": "deception_activated"
    },
    {
      "id": "thr_def456",
      "timestamp": "2025-11-10T14:25:00.000Z",
      "attack_type": "ssl_strip",
      "severity": "critical",
      "source_ip": "192.168.1.1",
      "dest_ip": "192.168.1.50",
      "protocol": "HTTP",
      "description": "SSL stripping detected for banking.example.com",
      "verified": true,
      "confidence": 0.98,
      "response_action": "deception_activated"
    }
    // ... (up to 100 threats)
  ]
}
```

**Status Codes:**
- `200 OK`: Success
- `400 Bad Request`: Invalid query parameters

**Example:**

```bash
curl "http://localhost:8888/v1/threats?severity=high&verified=true&limit=50"
```

---

#### 4.2.4 Get Threat Details

**Endpoint:** `GET /threats/{threat_id}`

**Description:** Get detailed information about a specific threat

**Path Parameters:**
- `threat_id`: Threat identifier

**Response:** 200 OK

```json
{
  "id": "thr_abc123",
  "timestamp": "2025-11-10T14:30:00.000Z",
  "attack_type": "dns_hijack",
  "severity": "high",
  "source_ip": "192.168.1.1",
  "dest_ip": "192.168.1.50",
  "protocol": "DNS",
  "description": "DNS hijacking detected for example.com",
  "verified": true,
  "confidence": 0.95,
  "response_action": "deception_activated",
  "evidence": {
    "domain": "example.com",
    "local_ip": "192.0.2.1",
    "verified_ip": "93.184.216.34",
    "suspicious_score": 85,
    "detection_context": {
      "transaction_id": 12345,
      "query_type": "A",
      "ttl": 300
    }
  },
  "verification_result": {
    "verification_id": "ver_xyz789",
    "paths_checked": 10,
    "paths_agreed": 9,
    "confidence": "HIGH",
    "consensus_ips": ["93.184.216.34"],
    "local_ips": ["192.0.2.1"]
  },
  "deception_session": {
    "session_id": "dec_ghi789",
    "status": "active",
    "started_at": "2025-11-10T14:30:05.000Z",
    "packets_sent": 47,
    "honeytokens_deployed": ["tok_abc123", "tok_def456"]
  },
  "related_events": [
    {
      "event_type": "dns_packet",
      "timestamp": "2025-11-10T14:29:58.000Z"
    },
    {
      "event_type": "verification_complete",
      "timestamp": "2025-11-10T14:30:03.000Z"
    },
    {
      "event_type": "deception_started",
      "timestamp": "2025-11-10T14:30:05.000Z"
    }
  ]
}
```

**Status Codes:**
- `200 OK`: Success
- `404 Not Found`: Threat ID not found

**Example:**

```bash
curl http://localhost:8888/v1/threats/thr_abc123
```

---

#### 4.2.5 Start Deception Session

**Endpoint:** `POST /deception/start`

**Description:** Manually start a deception session for a target

**Request Body:**

```json
{
  "threat_id": "thr_abc123",
  "target_domain": "example.com",
  "attacker_ip": "192.168.1.1",
  "behavior_profile": "banking_user",
  "duration_minutes": 30
}
```

**Request Fields:**
- `threat_id` (optional): Associated threat ID
- `target_domain` (required): Domain to simulate traffic for
- `attacker_ip` (required): IP address of attacker
- `behavior_profile` (optional): Behavior profile ("average_user" | "banking_user" | "developer" | "executive", default: "average_user")
- `duration_minutes` (optional): Session duration (default: 30, max: 1440)

**Response:** 201 Created

```json
{
  "session_id": "dec_ghi789",
  "status": "active",
  "started_at": "2025-11-10T14:32:15.123Z",
  "target_domain": "example.com",
  "attacker_ip": "192.168.1.1",
  "behavior_profile": "banking_user",
  "duration_minutes": 30,
  "estimated_end": "2025-11-10T15:02:15.123Z",
  "honeytokens_deployed": [
    {
      "token": "tok_abc123",
      "type": "email",
      "embedded_in": "login_form"
    },
    {
      "token": "tok_def456",
      "type": "api_key",
      "embedded_in": "fake_config_file"
    }
  ]
}
```

**Status Codes:**
- `201 Created`: Deception session started
- `400 Bad Request`: Invalid parameters
- `409 Conflict`: Deception session already active for this target

**Example:**

```bash
curl -X POST http://localhost:8888/v1/deception/start \
  -H "Content-Type: application/json" \
  -d '{
    "threat_id": "thr_abc123",
    "target_domain": "example.com",
    "attacker_ip": "192.168.1.1",
    "behavior_profile": "banking_user"
  }'
```

---

#### 4.2.6 Stop Deception Session

**Endpoint:** `POST /deception/stop`

**Description:** Stop an active deception session

**Request Body:**

```json
{
  "session_id": "dec_ghi789"
}
```

**Response:** 200 OK

```json
{
  "session_id": "dec_ghi789",
  "status": "stopped",
  "started_at": "2025-11-10T14:32:15.123Z",
  "stopped_at": "2025-11-10T14:45:30.456Z",
  "duration_seconds": 795,
  "statistics": {
    "packets_sent": 234,
    "bytes_sent": 487234,
    "honeytokens_triggered": 0,
    "attacker_actions_logged": 12
  }
}
```

**Status Codes:**
- `200 OK`: Session stopped
- `404 Not Found`: Session ID not found
- `409 Conflict`: Session already stopped

---

#### 4.2.7 Get Honeytokens

**Endpoint:** `GET /honeytokens`

**Description:** List deployed honeytokens and their status

**Query Parameters:**
- `triggered` (optional): Filter by trigger status (true | false)
- `token_type` (optional): Filter by type ("email" | "password" | "api_key" | "url" | "dns")
- `limit` (optional): Results per page (default: 100)
- `offset` (optional): Pagination offset (default: 0)

**Response:** 200 OK

```json
{
  "total": 47,
  "triggered_count": 3,
  "tokens": [
    {
      "token": "tok_abc123",
      "token_type": "email",
      "created_at": "2025-11-10T14:30:00.000Z",
      "domain": "example.com",
      "embedded_in": "Fake login form",
      "triggered": true,
      "trigger_count": 2,
      "first_trigger": "2025-11-10T15:00:00.000Z",
      "last_trigger": "2025-11-10T15:30:00.000Z",
      "trigger_sources": ["203.0.113.45", "203.0.113.46"]
    },
    {
      "token": "tok_def456",
      "token_type": "api_key",
      "created_at": "2025-11-10T14:30:00.000Z",
      "domain": "api.example.com",
      "embedded_in": "Fake config file",
      "triggered": false,
      "trigger_count": 0
    }
    // ...
  ]
}
```

**Status Codes:**
- `200 OK`: Success

---

#### 4.2.8 Report Honeytoken Trigger

**Endpoint:** `POST /honeytokens/trigger`

**Description:** Report that a honeytoken was triggered (called by external services)

**Request Body:**

```json
{
  "token": "tok_abc123",
  "source_ip": "203.0.113.45",
  "context": {
    "service": "email_server",
    "action": "login_attempt",
    "additional_data": "User-Agent: curl/7.68.0"
  }
}
```

**Response:** 200 OK

```json
{
  "token": "tok_abc123",
  "trigger_recorded": true,
  "trigger_count": 3,
  "alert_sent": true,
  "related_threat": {
    "threat_id": "thr_abc123",
    "attack_type": "dns_hijack",
    "timestamp": "2025-11-10T14:30:00.000Z"
  }
}
```

**Status Codes:**
- `200 OK`: Trigger recorded
- `404 Not Found`: Token not found

---

#### 4.2.9 Get Statistics

**Endpoint:** `GET /stats`

**Description:** Get system-wide statistics

**Query Parameters:**
- `period` (optional): Time period ("1h" | "24h" | "7d" | "30d", default: "24h")

**Response:** 200 OK

```json
{
  "period": "24h",
  "timestamp": "2025-11-10T14:32:15.123Z",
  "capture": {
    "packets_captured": 1543234,
    "packets_analyzed": 1542890,
    "packets_dropped": 344,
    "capture_rate_pps": 17.9
  },
  "detection": {
    "threats_detected": 47,
    "threats_verified": 43,
    "false_positives": 4,
    "attack_types": {
      "dns_hijack": 23,
      "ssl_strip": 12,
      "arp_spoof": 8,
      "tls_downgrade": 4
    },
    "severity_distribution": {
      "critical": 5,
      "high": 18,
      "medium": 20,
      "low": 4
    }
  },
  "verification": {
    "total_verifications": 342,
    "average_duration_ms": 6890,
    "attacks_confirmed": 43,
    "attacks_refuted": 4
  },
  "deception": {
    "sessions_started": 38,
    "sessions_active": 2,
    "packets_sent": 8234,
    "honeytokens_deployed": 94,
    "honeytokens_triggered": 3
  },
  "top_attackers": [
    {
      "ip": "192.168.1.1",
      "attacks": 12,
      "attack_types": ["dns_hijack", "arp_spoof"]
    },
    {
      "ip": "192.168.1.254",
      "attacks": 8,
      "attack_types": ["ssl_strip"]
    }
  ]
}
```

**Status Codes:**
- `200 OK`: Success

---

#### 4.2.10 Get System Configuration

**Endpoint:** `GET /config`

**Description:** Get current system configuration (read-only)

**Response:** 200 OK

```json
{
  "system": {
    "baseline_complete": true,
    "baseline_duration_hours": 24
  },
  "capture": {
    "interface": "en0",
    "buffer_size": 10485760,
    "snaplen": 262144
  },
  "detection": {
    "dns_threshold": 40,
    "ssl_strip_threshold": 70,
    "arp_spoof_threshold": 80
  },
  "verification": {
    "default_num_paths": 10,
    "default_timeout": 15,
    "strategy": "diverse"
  },
  "deception": {
    "auto_activate": true,
    "default_behavior_profile": "average_user",
    "default_duration_minutes": 30
  }
}
```

**Status Codes:**
- `200 OK`: Success

---

### 4.3 Engine API Authentication

The Engine API requires an API key for external access.

**Authentication Method:** Bearer Token

**Header:**
```
Authorization: Bearer <api_key>
```

**Example:**

```bash
curl http://localhost:8888/v1/threats \
  -H "Authorization: Bearer nlsn_sk_1234567890abcdef"
```

**API Key Format:**
```
nlsn_sk_<random_32_chars>
```

**Key Management:**
- API keys stored in database (hashed with bcrypt)
- Keys can be created/revoked via admin CLI
- Keys have expiration dates and rate limits

---

## 5. Internal Event API

### 5.1 Overview

Internal communication uses Redis Pub/Sub for real-time event streaming.

**Technology:** Redis 7.0+

**Pattern:** Publish/Subscribe

### 5.2 Event Channels

| Channel | Publisher | Subscribers | Purpose |
|---------|-----------|-------------|---------|
| `packets:dns` | Go Monitor | Engine | DNS packet events |
| `packets:http` | Go Monitor | Engine | HTTP packet events |
| `packets:tls` | Go Monitor | Engine | TLS packet events |
| `packets:arp` | Go Monitor | Engine | ARP packet events |
| `attacks:detected` | Go Monitor, Engine | Engine, UI | Attack detection events |
| `attacks:verified` | Engine | UI, Database Writer | Verification results |
| `deception:started` | Engine | Monitor, UI | Deception activation |
| `deception:events` | Engine | Monitor, UI | Deception packet events |
| `deception:stopped` | Engine | UI | Deception termination |
| `system:health` | All | Monitoring | Health metrics |
| `honeytokens:triggered` | External | Engine | Honeytoken triggers |

### 5.3 Event Message Format

All events follow this JSON schema:

```json
{
  "event_type": "attack_detected",
  "timestamp": "2025-11-10T14:32:15.123Z",
  "source": "go-monitor",
  "correlation_id": "cor_abc123",
  "data": {
    // Event-specific data
  }
}
```

**Common Fields:**
- `event_type`: Event type identifier
- `timestamp`: Event timestamp (ISO 8601)
- `source`: Component that generated the event
- `correlation_id`: For tracing related events
- `data`: Event-specific payload

### 5.4 Event Examples

#### 5.4.1 DNS Packet Event

**Channel:** `packets:dns`

```json
{
  "event_type": "dns_packet",
  "timestamp": "2025-11-10T14:32:15.123Z",
  "source": "go-monitor",
  "correlation_id": "cor_abc123",
  "data": {
    "transaction_id": 12345,
    "is_response": false,
    "query": {
      "domain": "example.com",
      "type": "A",
      "class": "IN"
    },
    "source_ip": "192.168.1.50",
    "dest_ip": "8.8.8.8",
    "suspicious": false,
    "suspicion_score": 0
  }
}
```

#### 5.4.2 Attack Detected Event

**Channel:** `attacks:detected`

```json
{
  "event_type": "attack_detected",
  "timestamp": "2025-11-10T14:32:15.123Z",
  "source": "go-monitor",
  "correlation_id": "cor_abc123",
  "data": {
    "attack_type": "dns_hijack",
    "severity": "high",
    "confidence": 0.85,
    "source_ip": "192.168.1.1",
    "target_ip": "192.168.1.50",
    "protocol": "DNS",
    "evidence": {
      "domain": "example.com",
      "local_ip": "192.0.2.1",
      "expected_ip": "93.184.216.34"
    },
    "verification_required": true
  }
}
```

#### 5.4.3 Verification Result Event

**Channel:** `attacks:verified`

```json
{
  "event_type": "verification_complete",
  "timestamp": "2025-11-10T14:32:20.456Z",
  "source": "engine",
  "correlation_id": "cor_abc123",
  "data": {
    "verification_id": "ver_xyz789",
    "threat_id": "thr_abc123",
    "url": "https://example.com",
    "attack_confirmed": true,
    "confidence": "HIGH",
    "paths_checked": 10,
    "paths_agreed": 9
  }
}
```

#### 5.4.4 Deception Started Event

**Channel:** `deception:started`

```json
{
  "event_type": "deception_started",
  "timestamp": "2025-11-10T14:32:25.789Z",
  "source": "engine",
  "correlation_id": "cor_abc123",
  "data": {
    "session_id": "dec_ghi789",
    "threat_id": "thr_abc123",
    "target_domain": "example.com",
    "attacker_ip": "192.168.1.1",
    "behavior_profile": "banking_user",
    "honeytokens": ["tok_abc123", "tok_def456"]
  }
}
```

### 5.5 Event Publishing (Go)

```go
// File: core/pkg/events/publisher.go

type EventPublisher struct {
    redis *redis.Client
}

func (p *EventPublisher) PublishDNSPacket(packet *parser.DNSPacket, suspicious bool, score int) error {
    event := map[string]interface{}{
        "event_type":     "dns_packet",
        "timestamp":      time.Now().Format(time.RFC3339Nano),
        "source":         "go-monitor",
        "correlation_id": generateCorrelationID(),
        "data": map[string]interface{}{
            "transaction_id": packet.TransactionID,
            "is_response":    packet.IsResponse,
            "query": map[string]interface{}{
                "domain": packet.Questions[0].Name,
                "type":   packet.Questions[0].Type,
            },
            "source_ip":      packet.SourceIP.String(),
            "dest_ip":        packet.DestIP.String(),
            "suspicious":     suspicious,
            "suspicion_score": score,
        },
    }

    data, err := json.Marshal(event)
    if err != nil {
        return err
    }

    return p.redis.Publish(context.Background(), "packets:dns", data).Err()
}
```

### 5.6 Event Subscription (Python)

```python
# File: engine/events/subscriber.py

import redis
import json
from typing import Callable

class EventSubscriber:
    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client
        self.pubsub = self.redis.pubsub()
        self.handlers = {}

    def subscribe(self, channel: str, handler: Callable):
        """Subscribe to a channel with a handler function"""
        self.pubsub.subscribe(channel)
        self.handlers[channel] = handler

    def listen(self):
        """Listen for events and dispatch to handlers"""
        for message in self.pubsub.listen():
            if message['type'] == 'message':
                channel = message['channel'].decode()
                data = json.loads(message['data'])

                handler = self.handlers.get(channel)
                if handler:
                    try:
                        handler(data)
                    except Exception as e:
                        logger.error(f"Error handling event: {e}")

# Usage
subscriber = EventSubscriber(redis_client)
subscriber.subscribe("attacks:detected", handle_attack_detected)
subscriber.subscribe("packets:dns", handle_dns_packet)
subscriber.listen()
```

---

## 6. Error Handling

### 6.1 Standard Error Response Format

All APIs use this consistent error format:

```json
{
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable error message",
    "details": {
      "field": "field_name",
      "reason": "Specific reason for error"
    }
  },
  "timestamp": "2025-11-10T14:32:15.123Z",
  "request_id": "req_abc123",
  "documentation_url": "https://docs.example.com/errors/ERROR_CODE"
}
```

### 6.2 HTTP Status Codes

| Status Code | Usage |
|-------------|-------|
| `200 OK` | Successful request |
| `201 Created` | Resource created successfully |
| `400 Bad Request` | Invalid request parameters |
| `401 Unauthorized` | Missing or invalid authentication |
| `403 Forbidden` | Insufficient permissions |
| `404 Not Found` | Resource not found |
| `409 Conflict` | Resource conflict (e.g., duplicate) |
| `429 Too Many Requests` | Rate limit exceeded |
| `500 Internal Server Error` | Unexpected server error |
| `503 Service Unavailable` | Service temporarily unavailable |
| `504 Gateway Timeout` | Request timeout |

### 6.3 Error Code Catalog

#### Verification API Errors

| Code | Status | Description |
|------|--------|-------------|
| `INVALID_URL` | 400 | URL is malformed |
| `INVALID_DOMAIN` | 400 | Domain name is invalid |
| `INVALID_NUM_PATHS` | 400 | num_paths out of range |
| `INVALID_TIMEOUT` | 400 | timeout out of range |
| `INSUFFICIENT_PATHS` | 503 | Not enough paths available |
| `VERIFICATION_TIMEOUT` | 504 | Verification exceeded timeout |
| `PATH_UNAVAILABLE` | 503 | Specific path unavailable |

#### Engine API Errors

| Code | Status | Description |
|------|--------|-------------|
| `INVALID_API_KEY` | 401 | API key is invalid or expired |
| `THREAT_NOT_FOUND` | 404 | Threat ID not found |
| `SESSION_NOT_FOUND` | 404 | Deception session not found |
| `SESSION_CONFLICT` | 409 | Deception session already exists |
| `TOKEN_NOT_FOUND` | 404 | Honeytoken not found |
| `DATABASE_ERROR` | 500 | Database operation failed |
| `VERIFICATION_SERVICE_DOWN` | 503 | Cannot reach verification service |

---

## 7. Authentication & Authorization

### 7.1 API Key Authentication

**Method:** Bearer Token in Authorization header

**Format:**
```
Authorization: Bearer nlsn_sk_<32_random_chars>
```

**Key Prefix Meanings:**
- `nlsn_sk_`: Secret key (full access)
- `nlsn_pk_`: Public key (read-only access)
- `nlsn_tk_`: Token (temporary, limited scope)

### 7.2 Key Permissions

| Key Type | Permissions |
|----------|-------------|
| Secret Key (`sk`) | Full access to all endpoints |
| Public Key (`pk`) | Read-only access (GET endpoints only) |
| Token (`tk`) | Limited scope, time-bound |

### 7.3 Key Management

**Creating a Key:**

```bash
# Via CLI
docker exec -it nlsn-engine python -m cli create-api-key \
  --name "Production Key" \
  --permissions "read,write" \
  --expires "2026-12-31"

# Output:
# API Key created successfully
# Key: nlsn_sk_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
# Name: Production Key
# Expires: 2026-12-31
# Store this key securely - it will not be shown again
```

**Revoking a Key:**

```bash
docker exec -it nlsn-engine python -m cli revoke-api-key \
  --key-id key_abc123
```

**Listing Keys:**

```bash
docker exec -it nlsn-engine python -m cli list-api-keys
```

### 7.4 Exemptions

The following endpoints do NOT require authentication:
- `GET /health` (both APIs)
- `GET /paths` (Verification API)

All other endpoints require valid API key.

---

## 8. Rate Limiting

### 8.1 Rate Limit Policy

| Endpoint | Rate Limit | Window |
|----------|------------|--------|
| `POST /verify` (Verification API) | 60 requests | 1 minute |
| `POST /verify-dns` | 120 requests | 1 minute |
| `POST /verify` (Engine API) | 30 requests | 1 minute |
| `GET /threats` | 300 requests | 1 minute |
| `POST /deception/start` | 10 requests | 1 minute |
| All other GET endpoints | 1000 requests | 1 minute |

### 8.2 Rate Limit Headers

All responses include rate limit information:

```
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 42
X-RateLimit-Reset: 1699632135
```

**Headers:**
- `X-RateLimit-Limit`: Maximum requests per window
- `X-RateLimit-Remaining`: Remaining requests in current window
- `X-RateLimit-Reset`: Unix timestamp when limit resets

### 8.3 Rate Limit Exceeded Response

**Status:** `429 Too Many Requests`

```json
{
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Rate limit exceeded. Try again in 23 seconds.",
    "details": {
      "limit": 60,
      "window_seconds": 60,
      "retry_after_seconds": 23
    }
  },
  "timestamp": "2025-11-10T14:32:15.123Z"
}
```

**Headers:**
```
Retry-After: 23
```

---

## 9. API Versioning

### 9.1 Versioning Strategy

**Method:** URL Path Versioning

**Format:** `/v{major_version}/`

**Example:** `/v1/threats`, `/v2/threats`

### 9.2 Version Lifecycle

| Version | Status | Support End |
|---------|--------|-------------|
| v1 | Current | - |
| v2 | Planned | - |

### 9.3 Breaking Changes

Breaking changes trigger a new major version:
- Removing fields from responses
- Changing field types
- Removing endpoints
- Changing authentication method

Non-breaking changes do NOT require new version:
- Adding new fields to responses
- Adding new endpoints
- Adding new optional parameters

### 9.4 Deprecation Policy

1. **Announcement**: Deprecation announced 6 months in advance
2. **Warning Headers**: Deprecated endpoints return warning header
3. **Documentation**: Clear migration guide provided
4. **Sunset**: Old version removed after 12 months

**Deprecation Header:**
```
Deprecation: true
Sunset: Wed, 01 Jan 2026 00:00:00 GMT
Link: <https://docs.example.com/migration/v1-to-v2>; rel="alternate"
```

---

## 10. WebSocket API

### 10.1 Overview

Real-time events can be streamed via WebSocket for UI clients.

**Endpoint:** `ws://engine:8888/v1/ws`

**Authentication:** Query parameter `?token=<api_key>`

### 10.2 Connection

```javascript
// Client code
const ws = new WebSocket('ws://localhost:8888/v1/ws?token=nlsn_sk_abc123');

ws.onopen = () => {
  console.log('Connected to NLSN Monitor');

  // Subscribe to events
  ws.send(JSON.stringify({
    action: 'subscribe',
    channels: ['attacks:detected', 'attacks:verified', 'deception:started']
  }));
};

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('Event received:', data);
};

ws.onerror = (error) => {
  console.error('WebSocket error:', error);
};

ws.onclose = () => {
  console.log('Disconnected from NLSN Monitor');
};
```

### 10.3 Message Format

**Client → Server (Subscribe):**

```json
{
  "action": "subscribe",
  "channels": ["attacks:detected", "attacks:verified"]
}
```

**Client → Server (Unsubscribe):**

```json
{
  "action": "unsubscribe",
  "channels": ["attacks:detected"]
}
```

**Server → Client (Event):**

```json
{
  "channel": "attacks:detected",
  "event": {
    "event_type": "attack_detected",
    "timestamp": "2025-11-10T14:32:15.123Z",
    "data": {
      // ... event data
    }
  }
}
```

**Server → Client (Error):**

```json
{
  "error": {
    "code": "UNAUTHORIZED",
    "message": "Invalid API key"
  }
}
```

### 10.4 Connection Management

- **Heartbeat**: Server sends ping every 30 seconds
- **Timeout**: Connection closed if no pong received in 60 seconds
- **Reconnect**: Client should implement exponential backoff
- **Max Connections**: 100 per API key

---

## 11. API Client Libraries

### 11.1 Python Client

```python
# File: shared/clients/python/nlsn_client.py

from typing import List, Optional
import httpx

class NLSNClient:
    """Official Python client for NLSN PCAP Monitor API"""

    def __init__(self, base_url: str = "http://localhost:8888/v1", api_key: Optional[str] = None):
        self.base_url = base_url
        self.api_key = api_key
        self.client = httpx.Client(
            base_url=base_url,
            headers={"Authorization": f"Bearer {api_key}"} if api_key else {},
            timeout=30.0
        )

    def verify_url(self, url: str, num_paths: int = 10) -> dict:
        """Verify a URL through multiple paths"""
        response = self.client.post("/verify", json={
            "url": url,
            "num_paths": num_paths
        })
        response.raise_for_status()
        return response.json()

    def list_threats(self, limit: int = 100, severity: Optional[str] = None) -> dict:
        """List detected threats"""
        params = {"limit": limit}
        if severity:
            params["severity"] = severity

        response = self.client.get("/threats", params=params)
        response.raise_for_status()
        return response.json()

    def get_threat(self, threat_id: str) -> dict:
        """Get threat details"""
        response = self.client.get(f"/threats/{threat_id}")
        response.raise_for_status()
        return response.json()

    def start_deception(self, target_domain: str, attacker_ip: str, **kwargs) -> dict:
        """Start a deception session"""
        data = {
            "target_domain": target_domain,
            "attacker_ip": attacker_ip,
            **kwargs
        }
        response = self.client.post("/deception/start", json=data)
        response.raise_for_status()
        return response.json()

    def get_stats(self, period: str = "24h") -> dict:
        """Get system statistics"""
        response = self.client.get("/stats", params={"period": period})
        response.raise_for_status()
        return response.json()

# Usage
client = NLSNClient(api_key="nlsn_sk_abc123")
result = client.verify_url("https://example.com")
print(f"Attack detected: {result['attack_detected']}")
```

### 11.2 JavaScript/TypeScript Client

```typescript
// File: shared/clients/js/nlsn-client.ts

export class NLSNClient {
  private baseUrl: string;
  private apiKey?: string;

  constructor(baseUrl: string = 'http://localhost:8888/v1', apiKey?: string) {
    this.baseUrl = baseUrl;
    this.apiKey = apiKey;
  }

  private async request(method: string, path: string, data?: any): Promise<any> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };

    if (this.apiKey) {
      headers['Authorization'] = `Bearer ${this.apiKey}`;
    }

    const response = await fetch(`${this.baseUrl}${path}`, {
      method,
      headers,
      body: data ? JSON.stringify(data) : undefined,
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error.message);
    }

    return response.json();
  }

  async verifyUrl(url: string, numPaths: number = 10): Promise<any> {
    return this.request('POST', '/verify', { url, num_paths: numPaths });
  }

  async listThreats(limit: number = 100, severity?: string): Promise<any> {
    const params = new URLSearchParams({ limit: limit.toString() });
    if (severity) params.append('severity', severity);
    return this.request('GET', `/threats?${params}`);
  }

  async getThreat(threatId: string): Promise<any> {
    return this.request('GET', `/threats/${threatId}`);
  }

  async startDeception(targetDomain: string, attackerIp: string, options?: any): Promise<any> {
    return this.request('POST', '/deception/start', {
      target_domain: targetDomain,
      attacker_ip: attackerIp,
      ...options,
    });
  }

  async getStats(period: string = '24h'): Promise<any> {
    return this.request('GET', `/stats?period=${period}`);
  }
}

// Usage
const client = new NLSNClient('http://localhost:8888/v1', 'nlsn_sk_abc123');
const result = await client.verifyUrl('https://example.com');
console.log(`Attack detected: ${result.attack_detected}`);
```

---

## Conclusion

This API design specification provides:

- **Complete endpoint definitions** for Verification and Engine APIs
- **Request/response examples** with full field documentation
- **Error handling** with consistent format and comprehensive error codes
- **Authentication** via API keys with permission levels
- **Rate limiting** policies and response headers
- **Versioning strategy** for API evolution
- **WebSocket API** for real-time event streaming
- **Client libraries** in Python and JavaScript/TypeScript
- **Internal event API** specifications using Redis Pub/Sub

These specifications ensure consistent, well-documented, and developer-friendly APIs across all system components.

---

**Document Version:** 1.0
**Total Word Count:** ~8,500 words
**Last Updated:** 2025-11-10
