# Technical Specifications

**Version:** 1.0
**Last Updated:** 2025-11-10
**Project:** NLSN PCAP Monitor

---

## Table of Contents

1. [Introduction](#introduction)
2. [Packet Format Specifications](#packet-format-specifications)
3. [Detection Algorithm Specifications](#detection-algorithm-specifications)
4. [Performance Requirements](#performance-requirements)
5. [Data Structure Specifications](#data-structure-specifications)
6. [Protocol Handling](#protocol-handling)
7. [Error Handling](#error-handling)
8. [State Management](#state-management)
9. [Event Schemas](#event-schemas)
10. [Database Schemas](#database-schemas)
11. [API Specifications](#api-specifications)
12. [Deception Specifications](#deception-specifications)
13. [Verification Specifications](#verification-specifications)
14. [Honeypot Specifications](#honeypot-specifications)

---

## 1. Introduction

This document provides detailed technical specifications for all components of the NLSN PCAP Monitor system. It serves as the authoritative reference for implementation, defining exact data formats, algorithms, performance criteria, and behavioral specifications.

### 1.1 Purpose

- Define precise technical requirements for each system component
- Provide implementation guidance with pseudocode and examples
- Establish performance benchmarks and acceptance criteria
- Document data structures, protocols, and interfaces
- Ensure consistency across Go and Python components

### 1.2 Scope

This specification covers:
- **Go Monitor**: Packet capture, parsing, and initial detection
- **Python Engine**: Orchestration, verification coordination, deception automation
- **Verification Container**: Multi-path verification logic
- **Honeypot System**: Tarpit behaviors and logging
- **Data Layer**: Database schemas and event formats

### 1.3 Conventions

- **MUST**: Absolute requirement
- **SHOULD**: Strong recommendation (deviation requires justification)
- **MAY**: Optional feature
- **Pseudocode**: Language-agnostic implementation guidance
- **Performance**: Specified with target and acceptable ranges

---

## 2. Packet Format Specifications

### 2.1 DNS Packet Parsing

#### 2.1.1 DNS Header Format

```
DNS Header Structure (12 bytes):
┌──────────────────────────────────────┐
│ Transaction ID (16 bits)             │
├──────────────────────────────────────┤
│ Flags (16 bits)                      │
│  QR(1) OPCODE(4) AA(1) TC(1) RD(1)  │
│  RA(1) Z(3) RCODE(4)                 │
├──────────────────────────────────────┤
│ Question Count (16 bits)             │
├──────────────────────────────────────┤
│ Answer Count (16 bits)               │
├──────────────────────────────────────┤
│ Authority Count (16 bits)            │
├──────────────────────────────────────┤
│ Additional Count (16 bits)           │
└──────────────────────────────────────┘
```

#### 2.1.2 Required DNS Fields for Detection

**Query Packet (MUST parse):**
- Transaction ID: uint16
- Query Name: string (FQDN)
- Query Type: uint16 (A=1, AAAA=28, MX=15, TXT=16, etc.)
- Query Class: uint16 (IN=1)

**Response Packet (MUST parse):**
- Transaction ID: uint16 (MUST match query)
- Response Code: uint8 (NOERROR=0, NXDOMAIN=3, SERVFAIL=2)
- Answer Records: []DNSAnswer
  - Name: string
  - Type: uint16
  - Class: uint16
  - TTL: uint32
  - Data: []byte (IP address for A/AAAA records)

#### 2.1.3 DNS Parsing Implementation

```go
// File: core/pkg/parser/dns.go

type DNSPacket struct {
    TransactionID uint16
    IsResponse    bool
    Opcode        uint8
    ResponseCode  uint8
    Questions     []DNSQuestion
    Answers       []DNSAnswer
    Timestamp     time.Time
    SourceIP      net.IP
    DestIP        net.IP
}

type DNSQuestion struct {
    Name  string  // FQDN (e.g., "example.com")
    Type  uint16  // Record type (A, AAAA, MX, etc.)
    Class uint16  // Query class (typically IN=1)
}

type DNSAnswer struct {
    Name  string
    Type  uint16
    Class uint16
    TTL   uint32
    Data  []byte  // Raw answer data
    IP    net.IP  // Parsed IP (for A/AAAA records)
}

// ParseDNS parses a DNS packet from raw bytes
func ParseDNS(data []byte, srcIP, dstIP net.IP, timestamp time.Time) (*DNSPacket, error) {
    // MUST validate minimum packet size (12 bytes header)
    if len(data) < 12 {
        return nil, ErrDNSPacketTooShort
    }

    packet := &DNSPacket{
        Timestamp: timestamp,
        SourceIP:  srcIP,
        DestIP:    dstIP,
    }

    // Parse header
    packet.TransactionID = binary.BigEndian.Uint16(data[0:2])
    flags := binary.BigEndian.Uint16(data[2:4])
    packet.IsResponse = (flags & 0x8000) != 0
    packet.Opcode = uint8((flags >> 11) & 0x0F)
    packet.ResponseCode = uint8(flags & 0x0F)

    questionCount := binary.BigEndian.Uint16(data[4:6])
    answerCount := binary.BigEndian.Uint16(data[6:8])

    // Parse questions
    offset := 12
    for i := 0; i < int(questionCount); i++ {
        question, newOffset, err := parseDNSQuestion(data, offset)
        if err != nil {
            return nil, err
        }
        packet.Questions = append(packet.Questions, question)
        offset = newOffset
    }

    // Parse answers (if response)
    if packet.IsResponse {
        for i := 0; i < int(answerCount); i++ {
            answer, newOffset, err := parseDNSAnswer(data, offset)
            if err != nil {
                return nil, err
            }
            packet.Answers = append(packet.Answers, answer)
            offset = newOffset
        }
    }

    return packet, nil
}
```

#### 2.1.4 DNS Name Compression Handling

DNS names MAY use compression (RFC 1035 Section 4.1.4). The parser MUST handle:

- **Pointer format**: Byte with top 2 bits set (0xC0) followed by offset
- **Maximum jumps**: 10 (prevent infinite loops)
- **Circular references**: Detect and reject

```go
func parseDNSName(data []byte, offset int) (string, int, error) {
    var name strings.Builder
    jumpCount := 0
    originalOffset := offset
    jumped := false

    for {
        if offset >= len(data) {
            return "", 0, ErrDNSInvalidName
        }

        length := int(data[offset])

        // Check for compression pointer
        if (length & 0xC0) == 0xC0 {
            if offset+1 >= len(data) {
                return "", 0, ErrDNSInvalidPointer
            }

            // Follow pointer
            pointerOffset := int(binary.BigEndian.Uint16(data[offset:offset+2]) & 0x3FFF)
            if !jumped {
                originalOffset = offset + 2
                jumped = true
            }
            offset = pointerOffset

            jumpCount++
            if jumpCount > 10 {
                return "", 0, ErrDNSTooManyJumps
            }
            continue
        }

        // End of name
        if length == 0 {
            if !jumped {
                originalOffset = offset + 1
            }
            break
        }

        // Read label
        offset++
        if offset+length > len(data) {
            return "", 0, ErrDNSInvalidName
        }

        if name.Len() > 0 {
            name.WriteByte('.')
        }
        name.Write(data[offset:offset+length])
        offset += length
    }

    return name.String(), originalOffset, nil
}
```

### 2.2 HTTP Packet Parsing

#### 2.2.1 HTTP Request Format

```
HTTP Request Structure:
┌────────────────────────────────────────────────┐
│ Request Line:                                  │
│   METHOD SP REQUEST-URI SP HTTP-VERSION CRLF  │
├────────────────────────────────────────────────┤
│ Headers: (0 or more)                           │
│   Field-Name: Field-Value CRLF                 │
├────────────────────────────────────────────────┤
│ CRLF (empty line)                              │
├────────────────────────────────────────────────┤
│ Body: (optional)                               │
│   [Content based on Content-Type]             │
└────────────────────────────────────────────────┘
```

#### 2.2.2 Required HTTP Fields for Detection

**Request (MUST parse):**
- Method: string (GET, POST, PUT, DELETE, etc.)
- URI: string (full request path with query parameters)
- HTTP Version: string ("HTTP/1.0", "HTTP/1.1", "HTTP/2")
- Host header: string (REQUIRED for HTTP/1.1)
- User-Agent: string
- Referer: string (if present)
- Cookie: string (if present)

**Response (MUST parse):**
- HTTP Version: string
- Status Code: uint16 (200, 301, 404, etc.)
- Status Text: string ("OK", "Not Found", etc.)
- Content-Type: string
- Content-Length: int64
- Location: string (for redirects)
- Set-Cookie: []string

#### 2.2.3 HTTP Parsing Implementation

```go
// File: core/pkg/parser/http.go

type HTTPPacket struct {
    IsRequest     bool
    Method        string            // GET, POST, etc.
    URI           string            // Request URI
    Version       string            // HTTP/1.1, HTTP/2
    StatusCode    uint16            // 200, 404, etc.
    StatusText    string            // OK, Not Found
    Headers       map[string]string
    Body          []byte
    Timestamp     time.Time
    SourceIP      net.IP
    DestIP        net.IP
    SourcePort    uint16
    DestPort      uint16
    IsHTTPS       bool              // Detected via port or upgrade
}

// ParseHTTP parses HTTP from TCP payload
func ParseHTTP(tcpPayload []byte, srcIP, dstIP net.IP, srcPort, dstPort uint16, timestamp time.Time) (*HTTPPacket, error) {
    // MUST check for minimum data
    if len(tcpPayload) < 16 {
        return nil, ErrHTTPTooShort
    }

    packet := &HTTPPacket{
        Timestamp:  timestamp,
        SourceIP:   srcIP,
        DestIP:     dstIP,
        SourcePort: srcPort,
        DestPort:   dstPort,
        Headers:    make(map[string]string),
        IsHTTPS:    dstPort == 443 || srcPort == 443,
    }

    // Split headers and body
    parts := bytes.SplitN(tcpPayload, []byte("\r\n\r\n"), 2)
    headerSection := parts[0]
    if len(parts) > 1 {
        packet.Body = parts[1]
    }

    // Parse header lines
    lines := bytes.Split(headerSection, []byte("\r\n"))
    if len(lines) == 0 {
        return nil, ErrHTTPInvalidFormat
    }

    // Parse request/status line
    firstLine := string(lines[0])
    if strings.HasPrefix(firstLine, "HTTP/") {
        // Response
        packet.IsRequest = false
        if err := parseHTTPStatusLine(firstLine, packet); err != nil {
            return nil, err
        }
    } else {
        // Request
        packet.IsRequest = true
        if err := parseHTTPRequestLine(firstLine, packet); err != nil {
            return nil, err
        }
    }

    // Parse headers
    for _, line := range lines[1:] {
        if len(line) == 0 {
            continue
        }

        parts := bytes.SplitN(line, []byte(":"), 2)
        if len(parts) != 2 {
            continue
        }

        key := string(bytes.TrimSpace(parts[0]))
        value := string(bytes.TrimSpace(parts[1]))
        packet.Headers[key] = value
    }

    return packet, nil
}

func parseHTTPRequestLine(line string, packet *HTTPPacket) error {
    parts := strings.SplitN(line, " ", 3)
    if len(parts) != 3 {
        return ErrHTTPInvalidRequestLine
    }

    packet.Method = parts[0]
    packet.URI = parts[1]
    packet.Version = parts[2]

    return nil
}

func parseHTTPStatusLine(line string, packet *HTTPPacket) error {
    parts := strings.SplitN(line, " ", 3)
    if len(parts) < 2 {
        return ErrHTTPInvalidStatusLine
    }

    packet.Version = parts[0]
    statusCode, err := strconv.Atoi(parts[1])
    if err != nil {
        return ErrHTTPInvalidStatusCode
    }
    packet.StatusCode = uint16(statusCode)

    if len(parts) == 3 {
        packet.StatusText = parts[2]
    }

    return nil
}
```

#### 2.2.4 HTTP Detection Targets

The parser MUST identify these suspicious patterns:

1. **HTTP on non-standard ports**: Detect HTTP traffic on ports other than 80, 8080, 8000
2. **Cleartext credentials**: Parse Authorization header for Basic auth
3. **Downgrade attempts**: Detect "Upgrade-Insecure-Requests: 0"
4. **Missing security headers**: Track absence of HSTS, X-Frame-Options
5. **Suspicious User-Agents**: Empty or malformed User-Agent strings

### 2.3 TLS/SSL Packet Parsing

#### 2.3.1 TLS Handshake Format

```
TLS Record Structure:
┌────────────────────────────────┐
│ Content Type (1 byte)          │
│   20=Change Cipher Spec        │
│   21=Alert                     │
│   22=Handshake                 │
│   23=Application Data          │
├────────────────────────────────┤
│ Protocol Version (2 bytes)     │
│   0x0301 = TLS 1.0             │
│   0x0302 = TLS 1.1             │
│   0x0303 = TLS 1.2             │
│   0x0304 = TLS 1.3             │
├────────────────────────────────┤
│ Length (2 bytes)               │
├────────────────────────────────┤
│ Payload (variable)             │
└────────────────────────────────┘

TLS Handshake Message:
┌────────────────────────────────┐
│ Handshake Type (1 byte)        │
│   1=ClientHello                │
│   2=ServerHello                │
│   11=Certificate               │
│   12=ServerKeyExchange         │
│   14=ServerHelloDone           │
│   16=ClientKeyExchange         │
├────────────────────────────────┤
│ Length (3 bytes)               │
├────────────────────────────────┤
│ Message (variable)             │
└────────────────────────────────┘
```

#### 2.3.2 Required TLS Fields for Detection

**ClientHello (MUST parse):**
- TLS Version: uint16
- Random: [32]byte (client random)
- Cipher Suites: []uint16
- Compression Methods: []uint8
- Extensions: map[uint16][]byte
  - SNI (Server Name Indication): Extension 0x0000
  - Supported Versions: Extension 0x002B

**ServerHello (MUST parse):**
- TLS Version: uint16
- Random: [32]byte (server random)
- Cipher Suite: uint16 (selected)
- Compression Method: uint8
- Extensions: map[uint16][]byte

**Certificate (MUST parse):**
- Certificate Chain: [][]byte (DER-encoded X.509)
- Subject: string (CN from first certificate)
- Issuer: string
- Not Before: time.Time
- Not After: time.Time

#### 2.3.3 TLS Parsing Implementation

```go
// File: core/pkg/parser/tls.go

type TLSPacket struct {
    ContentType      uint8
    Version          uint16
    HandshakeType    uint8
    ClientHello      *TLSClientHello
    ServerHello      *TLSServerHello
    Certificate      *TLSCertificate
    Alert            *TLSAlert
    Timestamp        time.Time
    SourceIP         net.IP
    DestIP           net.IP
    SourcePort       uint16
    DestPort         uint16
}

type TLSClientHello struct {
    Version            uint16
    Random             [32]byte
    SessionID          []byte
    CipherSuites       []uint16
    CompressionMethods []uint8
    Extensions         map[uint16][]byte
    SNI                string  // Parsed from extension 0x0000
}

type TLSServerHello struct {
    Version            uint16
    Random             [32]byte
    SessionID          []byte
    CipherSuite        uint16
    CompressionMethod  uint8
    Extensions         map[uint16][]byte
}

type TLSCertificate struct {
    Certificates [][]byte  // DER-encoded
    Subject      string
    Issuer       string
    NotBefore    time.Time
    NotAfter     time.Time
    DNSNames     []string
}

type TLSAlert struct {
    Level       uint8  // 1=warning, 2=fatal
    Description uint8
}

// ParseTLS parses TLS record from TCP payload
func ParseTLS(tcpPayload []byte, srcIP, dstIP net.IP, srcPort, dstPort uint16, timestamp time.Time) (*TLSPacket, error) {
    // MUST validate minimum TLS record size (5 bytes header)
    if len(tcpPayload) < 5 {
        return nil, ErrTLSPacketTooShort
    }

    packet := &TLSPacket{
        Timestamp:  timestamp,
        SourceIP:   srcIP,
        DestIP:     dstIP,
        SourcePort: srcPort,
        DestPort:   dstPort,
    }

    // Parse TLS record header
    packet.ContentType = tcpPayload[0]
    packet.Version = binary.BigEndian.Uint16(tcpPayload[1:3])
    recordLength := binary.BigEndian.Uint16(tcpPayload[3:5])

    // Validate record length
    if len(tcpPayload) < int(5+recordLength) {
        return nil, ErrTLSIncompleteRecord
    }

    payload := tcpPayload[5:5+recordLength]

    // Parse based on content type
    switch packet.ContentType {
    case 22: // Handshake
        if len(payload) < 4 {
            return nil, ErrTLSInvalidHandshake
        }
        packet.HandshakeType = payload[0]
        handshakeLength := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
        handshakeData := payload[4:]

        if len(handshakeData) < handshakeLength {
            return nil, ErrTLSIncompleteHandshake
        }

        switch packet.HandshakeType {
        case 1: // ClientHello
            clientHello, err := parseClientHello(handshakeData[:handshakeLength])
            if err != nil {
                return nil, err
            }
            packet.ClientHello = clientHello

        case 2: // ServerHello
            serverHello, err := parseServerHello(handshakeData[:handshakeLength])
            if err != nil {
                return nil, err
            }
            packet.ServerHello = serverHello

        case 11: // Certificate
            cert, err := parseCertificate(handshakeData[:handshakeLength])
            if err != nil {
                return nil, err
            }
            packet.Certificate = cert
        }

    case 21: // Alert
        if len(payload) < 2 {
            return nil, ErrTLSInvalidAlert
        }
        packet.Alert = &TLSAlert{
            Level:       payload[0],
            Description: payload[1],
        }
    }

    return packet, nil
}

func parseClientHello(data []byte) (*TLSClientHello, error) {
    if len(data) < 38 {
        return nil, ErrTLSInvalidClientHello
    }

    hello := &TLSClientHello{
        Extensions: make(map[uint16][]byte),
    }

    // Parse version
    hello.Version = binary.BigEndian.Uint16(data[0:2])

    // Parse random
    copy(hello.Random[:], data[2:34])

    offset := 34

    // Parse session ID
    sessionIDLength := int(data[offset])
    offset++
    if len(data) < offset+sessionIDLength {
        return nil, ErrTLSInvalidClientHello
    }
    hello.SessionID = data[offset:offset+sessionIDLength]
    offset += sessionIDLength

    // Parse cipher suites
    if len(data) < offset+2 {
        return nil, ErrTLSInvalidClientHello
    }
    cipherSuitesLength := int(binary.BigEndian.Uint16(data[offset:offset+2]))
    offset += 2
    if len(data) < offset+cipherSuitesLength {
        return nil, ErrTLSInvalidClientHello
    }
    for i := 0; i < cipherSuitesLength; i += 2 {
        suite := binary.BigEndian.Uint16(data[offset+i:offset+i+2])
        hello.CipherSuites = append(hello.CipherSuites, suite)
    }
    offset += cipherSuitesLength

    // Parse compression methods
    if len(data) < offset+1 {
        return nil, ErrTLSInvalidClientHello
    }
    compressionLength := int(data[offset])
    offset++
    if len(data) < offset+compressionLength {
        return nil, ErrTLSInvalidClientHello
    }
    hello.CompressionMethods = data[offset:offset+compressionLength]
    offset += compressionLength

    // Parse extensions
    if len(data) > offset+2 {
        extensionsLength := int(binary.BigEndian.Uint16(data[offset:offset+2]))
        offset += 2
        if len(data) >= offset+extensionsLength {
            if err := parseExtensions(data[offset:offset+extensionsLength], hello.Extensions); err != nil {
                return nil, err
            }

            // Extract SNI if present
            if sniData, ok := hello.Extensions[0x0000]; ok {
                hello.SNI = parseSNI(sniData)
            }
        }
    }

    return hello, nil
}

func parseSNI(data []byte) string {
    if len(data) < 5 {
        return ""
    }

    // Skip list length (2 bytes) and name type (1 byte)
    nameLength := int(binary.BigEndian.Uint16(data[3:5]))
    if len(data) < 5+nameLength {
        return ""
    }

    return string(data[5:5+nameLength])
}
```

#### 2.3.4 Weak Cipher Suite Detection

The parser MUST identify weak/deprecated cipher suites:

```go
var WeakCipherSuites = map[uint16]string{
    0x0000: "TLS_NULL_WITH_NULL_NULL",
    0x0001: "TLS_RSA_WITH_NULL_MD5",
    0x0002: "TLS_RSA_WITH_NULL_SHA",
    0x0004: "TLS_RSA_WITH_RC4_128_MD5",
    0x0005: "TLS_RSA_WITH_RC4_128_SHA",
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",    // Deprecated (CBC mode)
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",    // Deprecated (CBC mode)
    0x0039: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", // Deprecated (CBC mode)
    0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",  // Deprecated (CBC mode)
}

// IsWeakCipherSuite checks if cipher suite is considered weak
func IsWeakCipherSuite(suite uint16) bool {
    _, weak := WeakCipherSuites[suite]
    return weak
}
```

### 2.4 ARP Packet Parsing

#### 2.4.1 ARP Packet Format

```
ARP Packet Structure (28 bytes):
┌──────────────────────────────────┐
│ Hardware Type (2 bytes)          │
│   1 = Ethernet                   │
├──────────────────────────────────┤
│ Protocol Type (2 bytes)          │
│   0x0800 = IPv4                  │
├──────────────────────────────────┤
│ Hardware Address Length (1 byte) │
│   6 = MAC address                │
├──────────────────────────────────┤
│ Protocol Address Length (1 byte) │
│   4 = IPv4 address               │
├──────────────────────────────────┤
│ Operation (2 bytes)              │
│   1 = ARP Request                │
│   2 = ARP Reply                  │
├──────────────────────────────────┤
│ Sender Hardware Address (6 bytes)│
├──────────────────────────────────┤
│ Sender Protocol Address (4 bytes)│
├──────────────────────────────────┤
│ Target Hardware Address (6 bytes)│
├──────────────────────────────────┤
│ Target Protocol Address (4 bytes)│
└──────────────────────────────────┘
```

#### 2.4.2 ARP Parsing Implementation

```go
// File: core/pkg/parser/arp.go

type ARPPacket struct {
    Operation     uint16          // 1=Request, 2=Reply
    SenderMAC     net.HardwareAddr
    SenderIP      net.IP
    TargetMAC     net.HardwareAddr
    TargetIP      net.IP
    Timestamp     time.Time
}

// ParseARP parses ARP packet from Ethernet frame
func ParseARP(data []byte, timestamp time.Time) (*ARPPacket, error) {
    // MUST validate ARP packet size (28 bytes)
    if len(data) < 28 {
        return nil, ErrARPPacketTooShort
    }

    // Validate hardware type (Ethernet = 1)
    hwType := binary.BigEndian.Uint16(data[0:2])
    if hwType != 1 {
        return nil, ErrARPInvalidHardwareType
    }

    // Validate protocol type (IPv4 = 0x0800)
    protoType := binary.BigEndian.Uint16(data[2:4])
    if protoType != 0x0800 {
        return nil, ErrARPInvalidProtocolType
    }

    packet := &ARPPacket{
        Timestamp: timestamp,
    }

    // Parse operation
    packet.Operation = binary.BigEndian.Uint16(data[6:8])

    // Parse addresses
    packet.SenderMAC = net.HardwareAddr(data[8:14])
    packet.SenderIP = net.IP(data[14:18])
    packet.TargetMAC = net.HardwareAddr(data[18:24])
    packet.TargetIP = net.IP(data[24:28])

    return packet, nil
}
```

---

## 3. Detection Algorithm Specifications

### 3.1 DNS Hijacking Detection

#### 3.1.1 Algorithm Overview

DNS hijacking detection uses temporal correlation of DNS queries and responses, combined with verification through trusted paths when anomalies are detected.

#### 3.1.2 Detection Stages

**Stage 1: Passive Monitoring** (Go Monitor)
- Track all DNS queries and responses
- Build baseline of expected DNS behavior
- Detect anomalies that trigger verification

**Stage 2: Active Verification** (Python Engine + Verification Container)
- Query same domain through 10-40 independent paths
- Compare responses using majority voting
- Confirm attack if local response differs from majority

#### 3.1.3 Anomaly Detection Heuristics

```pseudocode
FUNCTION DetectDNSAnomaly(query, response):
    suspicious_score = 0

    // 1. Check for known good domains with unexpected IPs
    IF query.name IN known_domains:
        expected_ips = known_domains[query.name]
        IF response.ip NOT IN expected_ips:
            suspicious_score += 50
            TRIGGER_REASON = "Known domain with unexpected IP"

    // 2. Check for private/reserved IP responses to public domains
    IF IsPublicDomain(query.name) AND IsPrivateIP(response.ip):
        suspicious_score += 40
        TRIGGER_REASON = "Public domain resolving to private IP"

    // 3. Check for suspicious TLD responses
    IF query.name ENDS_WITH suspicious_tlds:  // .tk, .ml, .ga, .cf
        suspicious_score += 20
        TRIGGER_REASON = "Suspicious TLD"

    // 4. Check response time anomaly
    response_time = response.timestamp - query.timestamp
    average_response_time = GetAverageResponseTime(query.nameserver)
    IF response_time < average_response_time * 0.1:
        suspicious_score += 30
        TRIGGER_REASON = "Suspiciously fast response (possible cache poisoning)"

    // 5. Check for DNS server changes
    IF response.source_ip != GetExpectedNameserver():
        suspicious_score += 35
        TRIGGER_REASON = "Response from unexpected nameserver"

    // 6. Check TTL anomalies
    IF response.ttl < 60 AND query.name IN high_traffic_domains:
        suspicious_score += 25
        TRIGGER_REASON = "Abnormally low TTL for high-traffic domain"

    // 7. Check for NXDOMAIN on known domains
    IF query.name IN known_domains AND response.rcode == NXDOMAIN:
        suspicious_score += 45
        TRIGGER_REASON = "NXDOMAIN for known good domain"

    // Determine action based on score
    IF suspicious_score >= 80:
        RETURN ATTACK_CONFIRMED, TRIGGER_REASON
    ELSE IF suspicious_score >= 40:
        RETURN VERIFY_REQUIRED, TRIGGER_REASON
    ELSE:
        RETURN BENIGN, ""
END FUNCTION
```

#### 3.1.4 Multi-Path Verification Algorithm

```pseudocode
FUNCTION VerifyDNSResponse(domain, suspicious_ip):
    // Query through multiple independent paths
    verification_paths = SelectVerificationPaths(10)  // 10 VPN paths
    results = []

    FOR EACH path IN verification_paths:
        TRY:
            // Query through this path with timeout
            response = QueryDNSThroughPath(domain, path, timeout=10s)
            results.APPEND({
                path: path,
                ip: response.ip,
                success: TRUE
            })
        CATCH error:
            results.APPEND({
                path: path,
                error: error,
                success: FALSE
            })

    // Analyze results using majority voting
    successful_results = FILTER(results, r => r.success)

    IF LENGTH(successful_results) < 5:
        RETURN INCONCLUSIVE, "Insufficient verification paths succeeded"

    // Count IP occurrences
    ip_counts = CountOccurrences(successful_results, "ip")
    majority_ip, majority_count = FindMajority(ip_counts)

    // Calculate confidence
    confidence = majority_count / LENGTH(successful_results)

    // Determine if attack occurred
    IF suspicious_ip != majority_ip:
        IF confidence >= 0.7:
            RETURN ATTACK_CONFIRMED, {
                local_ip: suspicious_ip,
                verified_ip: majority_ip,
                confidence: confidence,
                paths_checked: LENGTH(successful_results),
                paths_agreed: majority_count
            }
        ELSE:
            RETURN INCONCLUSIVE, "Low confidence in verification"
    ELSE:
        RETURN BENIGN, "Local response matches verification"
END FUNCTION
```

#### 3.1.5 DNS Cache Management

The monitor MUST maintain an in-memory cache of recent DNS queries and responses:

```go
type DNSCache struct {
    queries   map[uint16]*DNSQuery      // Indexed by transaction ID
    responses map[string]*DNSResponse   // Indexed by domain name
    mutex     sync.RWMutex
    ttl       time.Duration
}

type DNSQuery struct {
    TransactionID uint16
    Domain        string
    QueryType     uint16
    Timestamp     time.Time
    SourceIP      net.IP
}

type DNSResponse struct {
    Domain      string
    IPs         []net.IP
    TTL         uint32
    Timestamp   time.Time
    Nameserver  net.IP
}

// AddQuery stores a DNS query
func (c *DNSCache) AddQuery(query *DNSQuery) {
    c.mutex.Lock()
    defer c.mutex.Unlock()

    c.queries[query.TransactionID] = query

    // Cleanup old queries (older than 30 seconds)
    cutoff := time.Now().Add(-30 * time.Second)
    for id, q := range c.queries {
        if q.Timestamp.Before(cutoff) {
            delete(c.queries, id)
        }
    }
}

// MatchResponse matches a response to its query
func (c *DNSCache) MatchResponse(transactionID uint16) (*DNSQuery, bool) {
    c.mutex.RLock()
    defer c.mutex.RUnlock()

    query, found := c.queries[transactionID]
    return query, found
}
```

### 3.2 SSL Stripping Detection

#### 3.2.1 Algorithm Overview

SSL stripping detection identifies downgrade attacks where HTTPS connections are converted to HTTP by a MITM attacker.

#### 3.2.2 HTTPS Expectation Tracking

```go
type HTTPSExpectation struct {
    Domain         string
    Expected       bool          // Should this domain use HTTPS?
    HSTSEnabled    bool          // Has HSTS header been seen?
    HSTSMaxAge     int64
    LastHTTPSVisit time.Time
    HTTPSScore     int           // Confidence score (0-100)
}

type HTTPSTracker struct {
    expectations map[string]*HTTPSExpectation
    mutex        sync.RWMutex
}
```

#### 3.2.3 SSL Stripping Detection Algorithm

```pseudocode
FUNCTION DetectSSLStripping(http_packet):
    domain = ExtractDomain(http_packet.headers["Host"])
    suspicious_score = 0

    // 1. Check if domain was previously accessed via HTTPS
    expectation = GetHTTPSExpectation(domain)
    IF expectation.Expected:
        IF http_packet.dest_port == 80:  // HTTP on port 80
            suspicious_score += 60
            TRIGGER_REASON = "HTTP used for domain with HTTPS history"

    // 2. Check for HSTS violations
    IF expectation.HSTSEnabled:
        IF http_packet.dest_port == 80:
            suspicious_score += 70
            TRIGGER_REASON = "HSTS policy violation - HTTP to HSTS domain"

    // 3. Check for known HTTPS-only domains
    IF domain IN https_only_domains:  // google.com, facebook.com, etc.
        IF http_packet.dest_port == 80:
            suspicious_score += 80
            TRIGGER_REASON = "HTTP to known HTTPS-only domain"

    // 4. Check for mixed content patterns
    IF http_packet.referer STARTS_WITH "https://":
        IF http_packet.dest_port == 80:
            suspicious_score += 50
            TRIGGER_REASON = "HTTP request from HTTPS referrer"

    // 5. Check for authentication over HTTP
    IF "Authorization" IN http_packet.headers:
        IF http_packet.dest_port == 80:
            suspicious_score += 90
            TRIGGER_REASON = "Authentication credentials sent over HTTP"

    // 6. Check for form submissions over HTTP
    IF http_packet.method == "POST":
        IF ContainsSensitiveFields(http_packet.body):
            suspicious_score += 85
            TRIGGER_REASON = "Sensitive form data sent over HTTP"

    // Determine action
    IF suspicious_score >= 70:
        RETURN ATTACK_CONFIRMED, TRIGGER_REASON
    ELSE IF suspicious_score >= 40:
        RETURN VERIFY_REQUIRED, TRIGGER_REASON
    ELSE:
        RETURN BENIGN, ""
END FUNCTION
```

#### 3.2.4 HSTS Preload List

The system MUST include a curated list of domains with HSTS preload:

```go
var HSTSPreloadDomains = map[string]bool{
    "google.com":    true,
    "facebook.com":  true,
    "twitter.com":   true,
    "github.com":    true,
    "amazon.com":    true,
    "apple.com":     true,
    "microsoft.com": true,
    "netflix.com":   true,
    "paypal.com":    true,
    // ... (full list: ~100,000 domains from chromium preload list)
}
```

#### 3.2.5 SSL Stripping Verification

```pseudocode
FUNCTION VerifySSLStripping(domain, http_url):
    // Construct HTTPS version of URL
    https_url = ConvertToHTTPS(http_url)

    // Try through local network first
    local_https_result = TryHTTPSConnection(https_url, local_network)

    // Verify through trusted paths
    verification_paths = SelectVerificationPaths(5)
    verified_results = []

    FOR EACH path IN verification_paths:
        http_result = FetchThroughPath(http_url, path)
        https_result = FetchThroughPath(https_url, path)

        verified_results.APPEND({
            path: path,
            http_works: http_result.success,
            https_works: https_result.success,
            https_content: https_result.content
        })

    // Analyze results
    https_should_work_count = COUNT(verified_results, r => r.https_works)

    IF https_should_work_count >= 3:
        IF NOT local_https_result.success:
            RETURN ATTACK_CONFIRMED, "HTTPS blocked locally but works through VPN"
        ELSE:
            // Check if content matches
            local_content_hash = HASH(local_https_result.content)
            vpn_content_hash = HASH(verified_results[0].https_content)

            IF local_content_hash != vpn_content_hash:
                RETURN ATTACK_CONFIRMED, "HTTPS content differs between local and VPN"

    RETURN BENIGN, "No SSL stripping detected"
END FUNCTION
```

### 3.3 ARP Spoofing Detection

#### 3.3.1 Algorithm Overview

ARP spoofing detection maintains a MAC-IP binding table and detects inconsistencies.

#### 3.3.2 ARP Table Structure

```go
type ARPEntry struct {
    IP           net.IP
    MAC          net.HardwareAddr
    FirstSeen    time.Time
    LastSeen     time.Time
    PacketCount  uint64
    IsGateway    bool
}

type ARPTable struct {
    entries map[string]*ARPEntry  // Key: IP address
    mutex   sync.RWMutex
}
```

#### 3.3.3 ARP Spoofing Detection Algorithm

```pseudocode
FUNCTION DetectARPSpoofing(arp_packet):
    suspicious_score = 0

    // Only process ARP replies
    IF arp_packet.operation != ARP_REPLY:
        RETURN BENIGN, ""

    sender_ip = arp_packet.sender_ip
    sender_mac = arp_packet.sender_mac

    // 1. Check for MAC address change
    existing_entry = GetARPEntry(sender_ip)
    IF existing_entry EXISTS:
        IF existing_entry.mac != sender_mac:
            // MAC changed for same IP
            suspicious_score += 70
            TRIGGER_REASON = "MAC address changed for IP " + sender_ip

            // Higher score if it's the gateway
            IF existing_entry.is_gateway:
                suspicious_score += 20
                TRIGGER_REASON = "Gateway MAC address changed"

    // 2. Check for gratuitous ARP anomalies
    IF arp_packet.sender_ip == arp_packet.target_ip:
        // Gratuitous ARP (announcing own IP)
        IF existing_entry EXISTS AND existing_entry.mac != sender_mac:
            suspicious_score += 60
            TRIGGER_REASON = "Gratuitous ARP with different MAC"

    // 3. Check for duplicate IP (same IP, different MAC in short time)
    recent_packets = GetRecentARPPackets(sender_ip, last_10_seconds)
    unique_macs = ExtractUniqueMacs(recent_packets)
    IF LENGTH(unique_macs) > 1:
        suspicious_score += 65
        TRIGGER_REASON = "Multiple MACs claiming same IP"

    // 4. Check ARP reply rate (potential ARP storm)
    reply_rate = CountARPReplies(sender_mac, last_5_seconds)
    IF reply_rate > 50:  // More than 50 ARP replies in 5 seconds
        suspicious_score += 40
        TRIGGER_REASON = "Abnormally high ARP reply rate"

    // 5. Check for unsolicited ARP replies
    IF NOT HasMatchingARPRequest(arp_packet):
        suspicious_score += 35
        TRIGGER_REASON = "Unsolicited ARP reply"

    // Determine action
    IF suspicious_score >= 80:
        RETURN ATTACK_CONFIRMED, TRIGGER_REASON
    ELSE IF suspicious_score >= 50:
        RETURN INVESTIGATE, TRIGGER_REASON
    ELSE:
        // Update ARP table
        UpdateARPEntry(sender_ip, sender_mac)
        RETURN BENIGN, ""
END FUNCTION
```

#### 3.3.4 Gateway MAC Protection

The system SHOULD maintain a trusted gateway MAC address:

```go
type GatewayProtection struct {
    TrustedMAC   net.HardwareAddr
    GatewayIP    net.IP
    Locked       bool
    LockedAt     time.Time
    AlertCount   int
}

// LockGatewayMAC locks the gateway MAC after stable operation
func (gp *GatewayProtection) LockGatewayMAC(mac net.HardwareAddr, ip net.IP) {
    gp.TrustedMAC = mac
    gp.GatewayIP = ip
    gp.Locked = true
    gp.LockedAt = time.Now()
}

// ValidateGatewayMAC checks if gateway MAC matches trusted value
func (gp *GatewayProtection) ValidateGatewayMAC(mac net.HardwareAddr) bool {
    if !gp.Locked {
        return true  // Not locked yet
    }
    return bytes.Equal(gp.TrustedMAC, mac)
}
```

### 3.4 TLS Downgrade Detection

#### 3.4.1 Algorithm Overview

Detects attempts to downgrade TLS version or negotiate weak cipher suites.

#### 3.4.2 TLS Downgrade Detection Algorithm

```pseudocode
FUNCTION DetectTLSDowngrade(tls_packet):
    suspicious_score = 0

    IF tls_packet.handshake_type == CLIENT_HELLO:
        client_hello = tls_packet.client_hello

        // 1. Check TLS version
        IF client_hello.version < TLS_1_2:
            suspicious_score += 50
            TRIGGER_REASON = "Client using outdated TLS version"

        // 2. Check for weak cipher suites
        weak_ciphers = []
        FOR EACH suite IN client_hello.cipher_suites:
            IF IsWeakCipherSuite(suite):
                weak_ciphers.APPEND(suite)

        IF LENGTH(weak_ciphers) > 0:
            suspicious_score += 40
            TRIGGER_REASON = "Weak cipher suites offered: " + JOIN(weak_ciphers)

        // 3. Check for missing security extensions
        IF NOT HasExtension(client_hello, "supported_versions"):
            suspicious_score += 30
            TRIGGER_REASON = "Missing supported_versions extension"

    ELSE IF tls_packet.handshake_type == SERVER_HELLO:
        server_hello = tls_packet.server_hello

        // 4. Check selected TLS version
        IF server_hello.version < TLS_1_2:
            suspicious_score += 60
            TRIGGER_REASON = "Server selected outdated TLS version"

        // 5. Check selected cipher suite
        IF IsWeakCipherSuite(server_hello.cipher_suite):
            suspicious_score += 70
            TRIGGER_REASON = "Server selected weak cipher suite"

        // 6. Check for compression (CRIME attack vector)
        IF server_hello.compression_method != 0:
            suspicious_score += 55
            TRIGGER_REASON = "TLS compression enabled (CRIME vulnerability)"

    ELSE IF tls_packet.content_type == ALERT:
        alert = tls_packet.alert

        // 7. Check for suspicious alerts
        IF alert.description IN [40, 41, 42, 43]:  // Handshake failure alerts
            suspicious_score += 35
            TRIGGER_REASON = "TLS handshake failure alert"

    // Determine action
    IF suspicious_score >= 70:
        RETURN ATTACK_SUSPECTED, TRIGGER_REASON
    ELSE IF suspicious_score >= 40:
        RETURN INVESTIGATE, TRIGGER_REASON
    ELSE:
        RETURN BENIGN, ""
END FUNCTION
```

### 3.5 Baseline Learning

#### 3.5.1 Algorithm Overview

The system MUST learn normal network behavior during an initial baseline period (default: 24 hours).

#### 3.5.2 Baseline Metrics

```go
type NetworkBaseline struct {
    // DNS metrics
    TypicalNameservers  []net.IP
    CommonDomains       map[string]int  // Domain -> query count
    AverageResponseTime time.Duration

    // HTTP metrics
    HTTPSDomains        map[string]bool  // Domains that use HTTPS
    CommonUserAgents    []string

    // ARP metrics
    StableARPBindings   map[string]net.HardwareAddr  // IP -> MAC
    GatewayMAC          net.HardwareAddr

    // TLS metrics
    CommonCipherSuites  map[uint16]int
    TLSVersions         map[uint16]int

    // Timing
    BaselineStarted     time.Time
    BaselineCompleted   time.Time
    IsComplete          bool
}
```

#### 3.5.3 Baseline Learning Algorithm

```pseudocode
FUNCTION LearnBaseline(packet, baseline):
    IF NOT baseline.is_complete:
        elapsed = NOW() - baseline.baseline_started
        IF elapsed >= BASELINE_DURATION:
            CompleteBaseline(baseline)
            RETURN

    // Update baseline metrics
    SWITCH packet.type:
        CASE DNS:
            baseline.common_domains[packet.domain] += 1
            UpdateAverageResponseTime(baseline, packet.response_time)
            IF packet.nameserver NOT IN baseline.typical_nameservers:
                baseline.typical_nameservers.APPEND(packet.nameserver)

        CASE HTTP:
            IF packet.dest_port == 443:
                baseline.https_domains[packet.host] = TRUE
            IF packet.user_agent NOT IN baseline.common_user_agents:
                baseline.common_user_agents.APPEND(packet.user_agent)

        CASE ARP:
            IF packet.operation == ARP_REPLY:
                baseline.stable_arp_bindings[packet.sender_ip] = packet.sender_mac
                IF IsGatewayIP(packet.sender_ip):
                    baseline.gateway_mac = packet.sender_mac

        CASE TLS:
            IF packet.handshake_type == SERVER_HELLO:
                baseline.common_cipher_suites[packet.cipher_suite] += 1
                baseline.tls_versions[packet.version] += 1
END FUNCTION

FUNCTION CompleteBaseline(baseline):
    baseline.is_complete = TRUE
    baseline.baseline_completed = NOW()

    // Prune low-frequency entries
    FOR EACH domain, count IN baseline.common_domains:
        IF count < 3:
            DELETE baseline.common_domains[domain]

    // Lock gateway MAC
    IF baseline.gateway_mac IS SET:
        LockGatewayMAC(baseline.gateway_mac)

    LOG("Baseline learning complete", {
        domains: LENGTH(baseline.common_domains),
        https_domains: LENGTH(baseline.https_domains),
        arp_bindings: LENGTH(baseline.stable_arp_bindings)
    })
END FUNCTION
```

---

## 4. Performance Requirements

### 4.1 Packet Capture Performance

| Metric | Target | Acceptable | Maximum |
|--------|--------|------------|---------|
| **Packet Capture Rate** | 40,000 pkt/s | 25,000 pkt/s | 100,000 pkt/s |
| **Packet Loss Rate** | < 0.1% | < 0.5% | < 1.0% |
| **Capture Latency** | < 5ms | < 10ms | < 20ms |
| **CPU Usage (1 core)** | < 40% | < 60% | < 80% |
| **Memory Usage** | < 500 MB | < 1 GB | < 2 GB |

### 4.2 Detection Performance

| Metric | Target | Acceptable |
|--------|--------|------------|
| **DNS Detection Latency** | < 10ms | < 50ms |
| **HTTP Detection Latency** | < 20ms | < 100ms |
| **TLS Detection Latency** | < 15ms | < 75ms |
| **ARP Detection Latency** | < 5ms | < 25ms |
| **Detection Accuracy** | > 95% | > 90% |
| **False Positive Rate** | < 1% | < 3% |

### 4.3 Verification Performance

| Metric | Target | Acceptable |
|--------|--------|------------|
| **Verification Latency** | < 5s | < 10s |
| **VPN Connection Time** | < 30s | < 60s |
| **Multi-Path Query (10 paths)** | < 8s | < 15s |
| **Verification Success Rate** | > 95% | > 85% |

### 4.4 Deception Performance

| Metric | Target | Acceptable |
|--------|--------|------------|
| **Deception Activation Time** | < 100ms | < 500ms |
| **Fake Packet Generation Rate** | > 100 pkt/s | > 50 pkt/s |
| **Human Behavior Realism Score** | > 8/10 | > 6/10 |

### 4.5 System Resource Limits

```yaml
# Resource limits for Docker containers

verification-container:
  cpu: 2.0
  memory: 2GB
  network_bandwidth: 100 Mbps

monitor-go:
  cpu: 1.0
  memory: 512MB
  network_bandwidth: 1 Gbps

engine-python:
  cpu: 1.0
  memory: 1GB
  network_bandwidth: 100 Mbps

honeypot:
  cpu: 0.5
  memory: 256MB
  network_bandwidth: 10 Mbps

redis:
  cpu: 0.5
  memory: 256MB

postgres:
  cpu: 1.0
  memory: 512MB
```

### 4.6 Performance Testing Procedures

#### 4.6.1 Packet Capture Load Test

```bash
# Generate test traffic with tcpreplay
tcpreplay -i eth0 -M 10 test-traffic.pcap

# Monitor capture statistics
docker logs nlsn-monitor-go | grep "Capture stats"

# Expected output:
# Packets captured: 400000
# Packets dropped: 12 (0.003%)
# Capture duration: 10.2s
# Rate: 39,215 pkt/s
```

#### 4.6.2 Detection Accuracy Test

```python
# File: engine/tests/test_detection_accuracy.py

def test_dns_hijack_detection():
    """Test DNS hijacking detection accuracy"""
    test_cases = load_test_cases("dns_hijack_samples.json")

    true_positives = 0
    false_positives = 0
    true_negatives = 0
    false_negatives = 0

    for case in test_cases:
        result = detect_dns_hijack(case.packet)

        if case.is_attack and result.attack_detected:
            true_positives += 1
        elif case.is_attack and not result.attack_detected:
            false_negatives += 1
        elif not case.is_attack and result.attack_detected:
            false_positives += 1
        elif not case.is_attack and not result.attack_detected:
            true_negatives += 1

    accuracy = (true_positives + true_negatives) / len(test_cases)
    precision = true_positives / (true_positives + false_positives)
    recall = true_positives / (true_positives + false_negatives)

    assert accuracy >= 0.95, f"Detection accuracy {accuracy} below target 0.95"
    assert precision >= 0.93, f"Precision {precision} below target 0.93"
    assert recall >= 0.97, f"Recall {recall} below target 0.97"
```

---

## 5. Data Structure Specifications

### 5.1 In-Memory Data Structures (Go)

#### 5.1.1 Packet Queue

```go
// File: core/pkg/capture/queue.go

type PacketQueue struct {
    packets chan *CapturedPacket
    buffer  *ring.Ring
    mutex   sync.RWMutex
    stats   *QueueStats
}

type CapturedPacket struct {
    Data      []byte
    Timestamp time.Time
    Length    int
    CaptureInfo gopacket.CaptureInfo
}

type QueueStats struct {
    Enqueued  uint64
    Dequeued  uint64
    Dropped   uint64
    Current   int
    Peak      int
}

// NewPacketQueue creates a new packet queue with specified capacity
func NewPacketQueue(capacity int) *PacketQueue {
    return &PacketQueue{
        packets: make(chan *CapturedPacket, capacity),
        buffer:  ring.New(capacity),
        stats:   &QueueStats{},
    }
}

// Enqueue adds a packet to the queue
func (q *PacketQueue) Enqueue(packet *CapturedPacket) error {
    select {
    case q.packets <- packet:
        atomic.AddUint64(&q.stats.Enqueued, 1)
        return nil
    default:
        atomic.AddUint64(&q.stats.Dropped, 1)
        return ErrQueueFull
    }
}

// Dequeue retrieves a packet from the queue
func (q *PacketQueue) Dequeue() (*CapturedPacket, error) {
    select {
    case packet := <-q.packets:
        atomic.AddUint64(&q.stats.Dequeued, 1)
        return packet, nil
    case <-time.After(100 * time.Millisecond):
        return nil, ErrQueueEmpty
    }
}
```

#### 5.1.2 Detection State

```go
// File: core/pkg/detector/state.go

type DetectionState struct {
    dnsCache      *DNSCache
    httpTracker   *HTTPSTracker
    arpTable      *ARPTable
    tlsFingerprints *TLSFingerprintDB
    baseline      *NetworkBaseline
    mutex         sync.RWMutex
}

type DetectionContext struct {
    PacketID      string
    Timestamp     time.Time
    SourceIP      net.IP
    DestIP        net.IP
    Protocol      string
    SuspicionScore int
    TriggerReasons []string
    RelatedEvents  []string
}
```

#### 5.1.3 Connection Tracking

```go
// File: core/pkg/tracker/connection.go

type ConnectionTracker struct {
    connections map[string]*Connection
    mutex       sync.RWMutex
    maxAge      time.Duration
}

type Connection struct {
    Key           string  // "srcIP:srcPort->dstIP:dstPort"
    Protocol      string  // "TCP", "UDP"
    State         string  // "SYN_SENT", "ESTABLISHED", "CLOSED"
    BytesSent     uint64
    BytesReceived uint64
    PacketsSent   uint64
    PacketsReceived uint64
    FirstSeen     time.Time
    LastSeen      time.Time
    Suspicious    bool
    SuspicionReasons []string
}

func (ct *ConnectionTracker) Track(packet gopacket.Packet) *Connection {
    key := generateConnectionKey(packet)

    ct.mutex.Lock()
    defer ct.mutex.Unlock()

    conn, exists := ct.connections[key]
    if !exists {
        conn = &Connection{
            Key:       key,
            FirstSeen: time.Now(),
            State:     "NEW",
        }
        ct.connections[key] = conn
    }

    conn.LastSeen = time.Now()
    updateConnectionStats(conn, packet)

    return conn
}
```

### 5.2 Database Structures (PostgreSQL)

#### 5.2.1 Threats Table

```sql
-- File: shared/schema/threats.sql

CREATE TABLE threats (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL DEFAULT NOW(),
    attack_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    source_ip INET,
    dest_ip INET,
    protocol VARCHAR(20),
    description TEXT,
    evidence JSONB,
    verified BOOLEAN DEFAULT FALSE,
    verification_data JSONB,
    response_action VARCHAR(50),
    INDEX idx_threats_timestamp (timestamp),
    INDEX idx_threats_attack_type (attack_type),
    INDEX idx_threats_source_ip (source_ip),
    INDEX idx_threats_verified (verified)
);
```

**Field Specifications:**

- `id`: Auto-incrementing primary key
- `timestamp`: Time of attack detection (indexed for time-range queries)
- `attack_type`: Enum-like field: "dns_hijack", "ssl_strip", "arp_spoof", "tls_downgrade", "mitm_generic"
- `severity`: Enum-like field: "low", "medium", "high", "critical"
- `source_ip`: IP address of attacker (if known)
- `dest_ip`: IP address of target
- `protocol`: "DNS", "HTTP", "HTTPS", "ARP", "TLS"
- `description`: Human-readable description
- `evidence`: JSONB containing packet data, detection scores, etc.
- `verified`: Boolean flag indicating if verified through multi-path
- `verification_data`: JSONB containing verification results
- `response_action`: "logged", "deception_activated", "user_alerted"

#### 5.2.2 Verification Results Table

```sql
CREATE TABLE verification_results (
    id SERIAL PRIMARY KEY,
    threat_id INTEGER REFERENCES threats(id),
    timestamp TIMESTAMP NOT NULL DEFAULT NOW(),
    url TEXT NOT NULL,
    paths_checked INTEGER NOT NULL,
    paths_agreed INTEGER NOT NULL,
    confidence FLOAT NOT NULL,
    local_response JSONB,
    verified_response JSONB,
    compromised_paths TEXT[],
    verification_duration_ms INTEGER,
    INDEX idx_verification_threat (threat_id),
    INDEX idx_verification_timestamp (timestamp)
);
```

#### 5.2.3 Honeytokens Table

```sql
CREATE TABLE honeytokens (
    id SERIAL PRIMARY KEY,
    token VARCHAR(255) UNIQUE NOT NULL,
    token_type VARCHAR(50) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    domain VARCHAR(255),
    embedded_in TEXT,
    triggered BOOLEAN DEFAULT FALSE,
    trigger_count INTEGER DEFAULT 0,
    first_trigger TIMESTAMP,
    last_trigger TIMESTAMP,
    trigger_sources INET[],
    INDEX idx_honeytokens_token (token),
    INDEX idx_honeytokens_triggered (triggered)
);
```

#### 5.2.4 Deception Sessions Table

```sql
CREATE TABLE deception_sessions (
    id SERIAL PRIMARY KEY,
    threat_id INTEGER REFERENCES threats(id),
    started_at TIMESTAMP NOT NULL DEFAULT NOW(),
    ended_at TIMESTAMP,
    target_domain VARCHAR(255),
    attacker_ip INET,
    packets_sent INTEGER DEFAULT 0,
    bytes_sent BIGINT DEFAULT 0,
    behavior_profile VARCHAR(50),
    honeytokens_deployed TEXT[],
    status VARCHAR(20) DEFAULT 'active',
    INDEX idx_deception_threat (threat_id),
    INDEX idx_deception_status (status),
    INDEX idx_deception_started (started_at)
);
```

### 5.3 Redis Data Structures

#### 5.3.1 Event Channels

```
Channel naming convention: <category>:<subcategory>

packets:dns         - DNS packet events
packets:http        - HTTP packet events
packets:tls         - TLS packet events
packets:arp         - ARP packet events
attacks:detected    - Attack detection events
attacks:verified    - Verification results
deception:started   - Deception activation
deception:events    - Deception packet events
system:health       - System health metrics
```

#### 5.3.2 Event Message Format

```json
{
  "event_type": "attack_detected",
  "timestamp": "2025-11-10T14:32:15.123Z",
  "severity": "high",
  "data": {
    "attack_type": "dns_hijack",
    "source_ip": "192.168.1.1",
    "dest_ip": "192.168.1.50",
    "details": {
      "domain": "example.com",
      "local_ip": "192.0.2.1",
      "expected_ip": "93.184.216.34",
      "suspicious_score": 85
    }
  }
}
```

#### 5.3.3 Redis Keys

```
# Current system state
system:baseline:complete -> "true" | "false"
system:monitor:status -> "running" | "stopped"
system:threats:count -> integer

# Detection statistics (expire after 1 hour)
stats:dns:queries:1h -> integer (INCR, EXPIRE 3600)
stats:dns:hijacks:1h -> integer
stats:http:requests:1h -> integer
stats:attacks:total:24h -> integer

# Temporary data (expire after 30 seconds)
cache:dns:query:{transaction_id} -> JSON (SETEX 30)
cache:http:expectation:{domain} -> JSON (SETEX 3600)

# Rate limiting
ratelimit:verification:{domain} -> integer (INCR, EXPIRE 60)
```

---

## 6. Protocol Handling

### 6.1 TCP Stream Reassembly

#### 6.1.1 TCP State Machine

```go
// File: core/pkg/parser/tcp_stream.go

type TCPStream struct {
    Key           string
    ClientSeq     uint32
    ServerSeq     uint32
    ClientBuffer  *StreamBuffer
    ServerBuffer  *StreamBuffer
    State         TCPState
    LastActivity  time.Time
}

type TCPState int

const (
    StateClosed TCPState = iota
    StateSynSent
    StateSynReceived
    StateEstablished
    StateFinWait1
    StateFinWait2
    StateClosing
    StateTimeWait
    StateCloseWait
    StateLastAck
)

type StreamBuffer struct {
    Data     []byte
    Expected uint32  // Next expected sequence number
    Gaps     []Gap   // Missing sequence ranges
}

type Gap struct {
    Start uint32
    End   uint32
}
```

#### 6.1.2 Stream Reassembly Algorithm

```pseudocode
FUNCTION ReassembleTCPStream(packet):
    stream = GetOrCreateStream(packet.src_ip, packet.src_port, packet.dst_ip, packet.dst_port)

    // Update TCP state
    UpdateTCPState(stream, packet.tcp_flags)

    // Determine direction
    is_client_to_server = IsClientToServer(packet, stream)

    IF is_client_to_server:
        buffer = stream.client_buffer
        seq = packet.tcp_seq
    ELSE:
        buffer = stream.server_buffer
        seq = packet.tcp_seq

    // Check if this is the next expected packet
    IF seq == buffer.expected:
        // In-order packet
        buffer.data.APPEND(packet.payload)
        buffer.expected = seq + LENGTH(packet.payload)

        // Check if this fills any gaps
        FillGaps(buffer)

        // Try to parse protocol
        IF stream.state == StateEstablished:
            TryParseApplicationProtocol(buffer.data, stream)

    ELSE IF seq > buffer.expected:
        // Out-of-order packet - create gap
        buffer.gaps.APPEND(Gap{
            start: buffer.expected,
            end: seq
        })
        buffer.data.APPEND_AT_OFFSET(packet.payload, seq - buffer.expected)

    ELSE:
        // Retransmission or old packet - ignore
        RETURN

    stream.last_activity = NOW()
END FUNCTION
```

### 6.2 HTTP Protocol Handling

#### 6.2.1 HTTP Request/Response Matching

```go
type HTTPTransaction struct {
    Request       *HTTPPacket
    Response      *HTTPPacket
    StartTime     time.Time
    ResponseTime  time.Duration
    Complete      bool
}

type HTTPMatcher struct {
    pendingRequests map[string]*HTTPPacket  // Key: clientIP:port->serverIP:port
    transactions    []*HTTPTransaction
    mutex           sync.RWMutex
}

func (m *HTTPMatcher) MatchRequestResponse(packet *HTTPPacket) *HTTPTransaction {
    key := generateHTTPKey(packet)

    if packet.IsRequest {
        m.mutex.Lock()
        m.pendingRequests[key] = packet
        m.mutex.Unlock()
        return nil
    } else {
        m.mutex.Lock()
        defer m.mutex.Unlock()

        request, exists := m.pendingRequests[key]
        if !exists {
            return nil  // Response without request
        }

        transaction := &HTTPTransaction{
            Request:      request,
            Response:     packet,
            StartTime:    request.Timestamp,
            ResponseTime: packet.Timestamp.Sub(request.Timestamp),
            Complete:     true,
        }

        delete(m.pendingRequests, key)
        m.transactions = append(m.transactions, transaction)

        return transaction
    }
}
```

#### 6.2.2 HTTP Body Parsing

```go
func ParseHTTPBody(transaction *HTTPTransaction) ([]byte, error) {
    contentEncoding := transaction.Response.Headers["Content-Encoding"]
    contentLength := transaction.Response.Headers["Content-Length"]
    transferEncoding := transaction.Response.Headers["Transfer-Encoding"]

    body := transaction.Response.Body

    // Handle chunked encoding
    if strings.Contains(strings.ToLower(transferEncoding), "chunked") {
        body, err := parseChunkedBody(body)
        if err != nil {
            return nil, err
        }
    }

    // Handle compression
    switch strings.ToLower(contentEncoding) {
    case "gzip":
        return decompressGzip(body)
    case "deflate":
        return decompressDeflate(body)
    case "br":
        return decompressBrotli(body)
    }

    return body, nil
}
```

### 6.3 DNS Protocol Handling

#### 6.3.1 DNS Query/Response Correlation

```go
type DNSTransaction struct {
    Query         *DNSPacket
    Response      *DNSPacket
    QueryTime     time.Time
    ResponseTime  time.Duration
    Nameserver    net.IP
    Complete      bool
}

type DNSMatcher struct {
    pendingQueries map[uint16]*DNSPacket  // Key: transaction ID
    transactions   []*DNSTransaction
    mutex          sync.RWMutex
    timeout        time.Duration
}

func (m *DNSMatcher) Match(packet *DNSPacket) *DNSTransaction {
    m.mutex.Lock()
    defer m.mutex.Unlock()

    // Cleanup expired queries
    m.cleanupExpired()

    if !packet.IsResponse {
        // Store query
        m.pendingQueries[packet.TransactionID] = packet
        return nil
    } else {
        // Match response to query
        query, exists := m.pendingQueries[packet.TransactionID]
        if !exists {
            return nil  // Response without query
        }

        transaction := &DNSTransaction{
            Query:        query,
            Response:     packet,
            QueryTime:    query.Timestamp,
            ResponseTime: packet.Timestamp.Sub(query.Timestamp),
            Nameserver:   packet.SourceIP,
            Complete:     true,
        }

        delete(m.pendingQueries, packet.TransactionID)
        m.transactions = append(m.transactions, transaction)

        return transaction
    }
}

func (m *DNSMatcher) cleanupExpired() {
    cutoff := time.Now().Add(-m.timeout)
    for id, query := range m.pendingQueries {
        if query.Timestamp.Before(cutoff) {
            delete(m.pendingQueries, id)
        }
    }
}
```

### 6.4 TLS Protocol Handling

#### 6.4.1 TLS Handshake Tracking

```go
type TLSHandshake struct {
    ClientHello      *TLSPacket
    ServerHello      *TLSPacket
    ServerCertificate *TLSPacket
    ClientKeyExchange *TLSPacket
    State            TLSHandshakeState
    Complete         bool
    StartTime        time.Time
    Duration         time.Duration
}

type TLSHandshakeState int

const (
    TLSStateInit TLSHandshakeState = iota
    TLSStateClientHelloSent
    TLSStateServerHelloReceived
    TLSStateCertificateReceived
    TLSStateHandshakeComplete
)

type TLSTracker struct {
    handshakes map[string]*TLSHandshake  // Key: clientIP:port->serverIP:port
    mutex      sync.RWMutex
}

func (t *TLSTracker) Track(packet *TLSPacket) *TLSHandshake {
    key := generateTLSKey(packet)

    t.mutex.Lock()
    defer t.mutex.Unlock()

    handshake, exists := t.handshakes[key]
    if !exists {
        handshake = &TLSHandshake{
            State:     TLSStateInit,
            StartTime: time.Now(),
        }
        t.handshakes[key] = handshake
    }

    // Update handshake state
    switch packet.HandshakeType {
    case 1: // ClientHello
        handshake.ClientHello = packet
        handshake.State = TLSStateClientHelloSent

    case 2: // ServerHello
        handshake.ServerHello = packet
        handshake.State = TLSStateServerHelloReceived

    case 11: // Certificate
        handshake.ServerCertificate = packet
        handshake.State = TLSStateCertificateReceived

    case 16: // ClientKeyExchange
        handshake.ClientKeyExchange = packet
        handshake.State = TLSStateHandshakeComplete
        handshake.Complete = true
        handshake.Duration = time.Since(handshake.StartTime)
    }

    return handshake
}
```

---

## 7. Error Handling

### 7.1 Error Categories

```go
// File: core/pkg/errors/errors.go

type ErrorCategory string

const (
    ErrCategoryParsing     ErrorCategory = "parsing"
    ErrCategoryDetection   ErrorCategory = "detection"
    ErrCategoryVerification ErrorCategory = "verification"
    ErrCategoryDeception   ErrorCategory = "deception"
    ErrCategorySystem      ErrorCategory = "system"
)

type SystemError struct {
    Category    ErrorCategory
    Code        string
    Message     string
    Cause       error
    Timestamp   time.Time
    Context     map[string]interface{}
    Recoverable bool
}

func (e *SystemError) Error() string {
    return fmt.Sprintf("[%s:%s] %s: %v", e.Category, e.Code, e.Message, e.Cause)
}
```

### 7.2 Error Handling Policies

#### 7.2.1 Parsing Errors

**Policy**: Log and skip malformed packets, continue processing

```go
func HandleParsingError(err error, packet []byte) {
    sysErr := &SystemError{
        Category:    ErrCategoryParsing,
        Code:        "MALFORMED_PACKET",
        Message:     "Failed to parse packet",
        Cause:       err,
        Timestamp:   time.Now(),
        Recoverable: true,
        Context: map[string]interface{}{
            "packet_length": len(packet),
            "packet_preview": hex.EncodeToString(packet[:min(len(packet), 64)]),
        },
    }

    logger.Warn(sysErr.Error())
    metrics.IncrementCounter("parsing_errors_total")

    // Do NOT stop processing - continue with next packet
}
```

#### 7.2.2 Detection Errors

**Policy**: Log error, mark detection as uncertain, continue monitoring

```go
func HandleDetectionError(err error, packet *ParsedPacket) {
    sysErr := &SystemError{
        Category:    ErrCategoryDetection,
        Code:        "DETECTION_FAILED",
        Message:     "Detection algorithm encountered error",
        Cause:       err,
        Timestamp:   time.Now(),
        Recoverable: true,
        Context: map[string]interface{}{
            "packet_type": packet.Type,
            "source_ip":   packet.SourceIP.String(),
        },
    }

    logger.Error(sysErr.Error())
    metrics.IncrementCounter("detection_errors_total")

    // Mark as uncertain rather than benign
    packet.DetectionResult = DetectionUncertain
}
```

#### 7.2.3 Verification Errors

**Policy**: Retry with exponential backoff, fallback to partial verification

```go
func HandleVerificationError(err error, attempt int, maxAttempts int) error {
    if attempt >= maxAttempts {
        sysErr := &SystemError{
            Category:    ErrCategoryVerification,
            Code:        "VERIFICATION_EXHAUSTED",
            Message:     "Verification failed after max retries",
            Cause:       err,
            Timestamp:   time.Now(),
            Recoverable: false,
        }

        logger.Error(sysErr.Error())
        return sysErr
    }

    // Exponential backoff: 2^attempt seconds
    backoff := time.Duration(math.Pow(2, float64(attempt))) * time.Second
    time.Sleep(backoff)

    logger.Warn(fmt.Sprintf("Verification attempt %d/%d failed, retrying in %v",
        attempt, maxAttempts, backoff))

    return nil  // Retry
}
```

#### 7.2.4 System Errors

**Policy**: Alert user, attempt graceful degradation or shutdown

```go
func HandleSystemError(err error) {
    sysErr := &SystemError{
        Category:    ErrCategorySystem,
        Code:        "CRITICAL_FAILURE",
        Message:     "Critical system error",
        Cause:       err,
        Timestamp:   time.Now(),
        Recoverable: false,
    }

    logger.Fatal(sysErr.Error())

    // Attempt graceful shutdown
    shutdownSystem()

    os.Exit(1)
}
```

### 7.3 Error Recovery Strategies

```pseudocode
FUNCTION RecoverFromError(error, context):
    SWITCH error.category:
        CASE "parsing":
            // Skip packet, continue processing
            LOG_WARNING(error)
            RETURN CONTINUE

        CASE "detection":
            // Mark as uncertain, continue monitoring
            LOG_ERROR(error)
            context.detection_result = UNCERTAIN
            RETURN CONTINUE

        CASE "verification":
            // Retry with backoff
            IF context.retry_count < MAX_RETRIES:
                WAIT(EXPONENTIAL_BACKOFF(context.retry_count))
                context.retry_count += 1
                RETURN RETRY
            ELSE:
                // Fallback to partial verification
                LOG_ERROR("Verification exhausted, using partial results")
                context.use_partial_results = TRUE
                RETURN CONTINUE

        CASE "deception":
            // Stop deception for this target, alert
            LOG_ERROR(error)
            STOP_DECEPTION(context.target)
            ALERT_USER("Deception failed")
            RETURN STOP

        CASE "system":
            // Critical error - attempt graceful shutdown
            LOG_FATAL(error)
            GRACEFUL_SHUTDOWN()
            RETURN TERMINATE
END FUNCTION
```

---

## 8. State Management

### 8.1 Application State

```go
// File: core/pkg/state/manager.go

type StateManager struct {
    captureState    *CaptureState
    detectionState  *DetectionState
    verificationState *VerificationState
    deceptionState  *DeceptionState
    mutex           sync.RWMutex
}

type CaptureState struct {
    Active          bool
    Interface       string
    PacketsCaptured uint64
    PacketsDropped  uint64
    StartTime       time.Time
}

type DetectionState struct {
    BaselineComplete  bool
    ThreatsDetected   uint64
    ThreatsVerified   uint64
    ActiveInvestigations map[string]*Investigation
}

type VerificationState struct {
    VPNsConnected     int
    TotalPaths        int
    AvailablePaths    []string
    VerificationQueue []VerificationTask
}

type DeceptionState struct{
    ActiveSessions    map[string]*DeceptionSession
    TotalPacketsSent  uint64
    HoneytokensActive int
}
```

### 8.2 State Persistence

```go
// File: core/pkg/state/persistence.go

type StatePersister struct {
    stateFile string
    interval  time.Duration
}

func (sp *StatePersister) SaveState(state *StateManager) error {
    data, err := json.MarshalIndent(state, "", "  ")
    if err != nil {
        return err
    }

    // Write atomically with temp file + rename
    tempFile := sp.stateFile + ".tmp"
    if err := ioutil.WriteFile(tempFile, data, 0600); err != nil {
        return err
    }

    return os.Rename(tempFile, sp.stateFile)
}

func (sp *StatePersister) LoadState() (*StateManager, error) {
    data, err := ioutil.ReadFile(sp.stateFile)
    if err != nil {
        if os.IsNotExist(err) {
            return NewStateManager(), nil  // Fresh state
        }
        return nil, err
    }

    var state StateManager
    if err := json.Unmarshal(data, &state); err != nil {
        return nil, err
    }

    return &state, nil
}

// PeriodicSave saves state every interval
func (sp *StatePersister) PeriodicSave(ctx context.Context, state *StateManager) {
    ticker := time.NewTicker(sp.interval)
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            if err := sp.SaveState(state); err != nil {
                logger.Error("Failed to save state:", err)
            }
        case <-ctx.Done():
            // Final save before shutdown
            sp.SaveState(state)
            return
        }
    }
}
```

### 8.3 State Synchronization

```go
// File: core/pkg/state/sync.go

type StateSynchronizer struct {
    redis  *redis.Client
    pubsub *redis.PubSub
}

func (ss *StateSynchronizer) PublishStateChange(event string, data interface{}) error {
    payload, err := json.Marshal(data)
    if err != nil {
        return err
    }

    return ss.redis.Publish(context.Background(), "state:"+event, payload).Err()
}

func (ss *StateSynchronizer) SubscribeToStateChanges(handler func(event string, data []byte)) {
    ss.pubsub = ss.redis.PSubscribe(context.Background(), "state:*")

    go func() {
        for msg := range ss.pubsub.Channel() {
            event := strings.TrimPrefix(msg.Channel, "state:")
            handler(event, []byte(msg.Payload))
        }
    }()
}
```

---

## 9. Event Schemas

### 9.1 DNS Event Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "properties": {
    "event_type": {"const": "dns_packet"},
    "timestamp": {"type": "string", "format": "date-time"},
    "transaction_id": {"type": "integer"},
    "is_response": {"type": "boolean"},
    "query": {
      "type": "object",
      "properties": {
        "domain": {"type": "string"},
        "type": {"type": "string", "enum": ["A", "AAAA", "MX", "TXT", "NS", "CNAME"]},
        "class": {"type": "string"}
      },
      "required": ["domain", "type"]
    },
    "response": {
      "type": "object",
      "properties": {
        "rcode": {"type": "string", "enum": ["NOERROR", "NXDOMAIN", "SERVFAIL", "REFUSED"]},
        "answers": {
          "type": "array",
          "items": {
            "type": "object",
            "properties": {
              "name": {"type": "string"},
              "type": {"type": "string"},
              "ttl": {"type": "integer"},
              "data": {"type": "string"}
            }
          }
        }
      }
    },
    "source_ip": {"type": "string", "format": "ipv4"},
    "dest_ip": {"type": "string", "format": "ipv4"},
    "suspicious": {"type": "boolean"},
    "suspicion_score": {"type": "integer", "minimum": 0, "maximum": 100}
  },
  "required": ["event_type", "timestamp", "transaction_id", "is_response"]
}
```

### 9.2 Attack Detection Event Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "properties": {
    "event_type": {"const": "attack_detected"},
    "timestamp": {"type": "string", "format": "date-time"},
    "attack_type": {
      "type": "string",
      "enum": ["dns_hijack", "ssl_strip", "arp_spoof", "tls_downgrade", "mitm_generic"]
    },
    "severity": {
      "type": "string",
      "enum": ["low", "medium", "high", "critical"]
    },
    "confidence": {"type": "number", "minimum": 0, "maximum": 1},
    "source": {
      "type": "object",
      "properties": {
        "ip": {"type": "string", "format": "ipv4"},
        "mac": {"type": "string"},
        "hostname": {"type": "string"}
      }
    },
    "target": {
      "type": "object",
      "properties": {
        "ip": {"type": "string", "format": "ipv4"},
        "domain": {"type": "string"},
        "protocol": {"type": "string"}
      }
    },
    "evidence": {
      "type": "object",
      "additionalProperties": true
    },
    "verification_required": {"type": "boolean"},
    "response_action": {
      "type": "string",
      "enum": ["log_only", "verify", "activate_deception", "alert_user"]
    }
  },
  "required": ["event_type", "timestamp", "attack_type", "severity", "confidence"]
}
```

### 9.3 Verification Result Event Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "properties": {
    "event_type": {"const": "verification_complete"},
    "timestamp": {"type": "string", "format": "date-time"},
    "threat_id": {"type": "string"},
    "url": {"type": "string", "format": "uri"},
    "attack_confirmed": {"type": "boolean"},
    "confidence": {
      "type": "string",
      "enum": ["LOW", "MEDIUM", "HIGH", "VERY_HIGH"]
    },
    "paths_checked": {"type": "integer"},
    "paths_agreed": {"type": "integer"},
    "local_response": {
      "type": "object",
      "properties": {
        "status_code": {"type": "integer"},
        "content_hash": {"type": "string"},
        "headers": {"type": "object"}
      }
    },
    "verified_response": {
      "type": "object",
      "properties": {
        "status_code": {"type": "integer"},
        "content_hash": {"type": "string"},
        "headers": {"type": "object"}
      }
    },
    "compromised_paths": {
      "type": "array",
      "items": {"type": "string"}
    },
    "differences": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "field": {"type": "string"},
          "local_value": {"type": "string"},
          "verified_value": {"type": "string"}
        }
      }
    },
    "duration_ms": {"type": "integer"}
  },
  "required": ["event_type", "timestamp", "url", "attack_confirmed", "confidence"]
}
```

---

## 10. Database Schemas

### 10.1 Schema Versioning

```sql
-- File: shared/schema/version.sql

CREATE TABLE schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TIMESTAMP NOT NULL DEFAULT NOW(),
    description TEXT
);

INSERT INTO schema_version (version, description) VALUES
(1, 'Initial schema'),
(2, 'Add verification_results table'),
(3, 'Add honeytokens table'),
(4, 'Add deception_sessions table');
```

### 10.2 Indexes and Performance

```sql
-- File: shared/schema/indexes.sql

-- Threats table indexes
CREATE INDEX CONCURRENTLY idx_threats_timestamp_desc ON threats(timestamp DESC);
CREATE INDEX CONCURRENTLY idx_threats_attack_severity ON threats(attack_type, severity);
CREATE INDEX CONCURRENTLY idx_threats_source_ip_timestamp ON threats(source_ip, timestamp);
CREATE INDEX CONCURRENTLY idx_threats_verified_timestamp ON threats(verified, timestamp);

-- GIN index for JSONB evidence field
CREATE INDEX CONCURRENTLY idx_threats_evidence_gin ON threats USING GIN(evidence);

-- Verification results indexes
CREATE INDEX CONCURRENTLY idx_verification_threat_id ON verification_results(threat_id);
CREATE INDEX CONCURRENTLY idx_verification_timestamp_desc ON verification_results(timestamp DESC);
CREATE INDEX CONCURRENTLY idx_verification_confidence ON verification_results(confidence);

-- Honeytokens indexes
CREATE UNIQUE INDEX idx_honeytokens_token_unique ON honeytokens(token);
CREATE INDEX CONCURRENTLY idx_honeytokens_triggered_type ON honeytokens(triggered, token_type);
CREATE INDEX CONCURRENTLY idx_honeytokens_trigger_count ON honeytokens(trigger_count) WHERE triggered = true;

-- Deception sessions indexes
CREATE INDEX CONCURRENTLY idx_deception_status_started ON deception_sessions(status, started_at DESC);
CREATE INDEX CONCURRENTLY idx_deception_attacker_ip ON deception_sessions(attacker_ip);
```

### 10.3 Database Partitioning

```sql
-- File: shared/schema/partitioning.sql

-- Partition threats table by month for better performance
CREATE TABLE threats_partitioned (
    LIKE threats INCLUDING ALL
) PARTITION BY RANGE (timestamp);

-- Create partitions for the next 12 months
CREATE TABLE threats_2025_11 PARTITION OF threats_partitioned
    FOR VALUES FROM ('2025-11-01') TO ('2025-12-01');

CREATE TABLE threats_2025_12 PARTITION OF threats_partitioned
    FOR VALUES FROM ('2025-12-01') TO ('2026-01-01');

-- ... (create partitions for each month)

-- Automatic partition creation function
CREATE OR REPLACE FUNCTION create_monthly_partition()
RETURNS void AS $$
DECLARE
    partition_date date;
    partition_name text;
    start_date text;
    end_date text;
BEGIN
    partition_date := date_trunc('month', CURRENT_DATE + interval '1 month');
    partition_name := 'threats_' || to_char(partition_date, 'YYYY_MM');
    start_date := partition_date::text;
    end_date := (partition_date + interval '1 month')::text;

    EXECUTE format('CREATE TABLE IF NOT EXISTS %I PARTITION OF threats_partitioned FOR VALUES FROM (%L) TO (%L)',
        partition_name, start_date, end_date);
END;
$$ LANGUAGE plpgsql;
```

### 10.4 Database Functions

```sql
-- File: shared/schema/functions.sql

-- Function to get recent threats summary
CREATE OR REPLACE FUNCTION get_threats_summary(hours integer DEFAULT 24)
RETURNS TABLE (
    attack_type varchar,
    count bigint,
    critical_count bigint,
    verified_count bigint
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        t.attack_type,
        COUNT(*) as count,
        COUNT(*) FILTER (WHERE t.severity = 'critical') as critical_count,
        COUNT(*) FILTER (WHERE t.verified = true) as verified_count
    FROM threats t
    WHERE t.timestamp > NOW() - make_interval(hours => hours)
    GROUP BY t.attack_type
    ORDER BY count DESC;
END;
$$ LANGUAGE plpgsql;

-- Function to cleanup old verification results
CREATE OR REPLACE FUNCTION cleanup_old_verifications(retention_days integer DEFAULT 30)
RETURNS integer AS $$
DECLARE
    deleted_count integer;
BEGIN
    DELETE FROM verification_results
    WHERE timestamp < NOW() - make_interval(days => retention_days)
    AND threat_id NOT IN (
        SELECT id FROM threats WHERE severity IN ('high', 'critical')
    );

    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;
```

---

## 11. API Specifications

*See separate document: API_DESIGN.md (to be created)*

### 11.1 Verification Container API Endpoints

```
POST /verify
GET  /paths
GET  /health
GET  /stats
```

### 11.2 Engine API Endpoints

```
GET  /health
POST /verify
GET  /threats
GET  /threats/{id}
POST /deception/start
POST /deception/stop
GET  /honeytokens
POST /honeytokens/trigger
GET  /stats
```

---

## 12. Deception Specifications

### 12.1 Human Behavior Simulation

```python
# File: engine/deception/behavior_sim.py

class HumanBehaviorSimulator:
    """Simulates realistic human interaction patterns"""

    def __init__(self, profile: str = "average_user"):
        self.profile = self.load_profile(profile)
        self.typing_speed_wpm = random.uniform(40, 60)
        self.reading_speed_wpm = random.uniform(200, 300)
        self.attention_span_s = random.uniform(30, 180)

    def get_page_load_delay(self) -> float:
        """Random delay after page load before interaction"""
        # Normal distribution: mean=1.5s, std=0.5s
        return max(0.5, random.normalvariate(1.5, 0.5))

    def get_reading_time(self, text_length: int) -> float:
        """Calculate reading time based on text length"""
        words = text_length / 5  # Average word length
        minutes = words / self.reading_speed_wpm
        return minutes * 60 + random.uniform(-2, 5)

    def get_typing_interval(self, text_length: int) -> List[float]:
        """Generate realistic typing intervals"""
        chars_per_second = self.typing_speed_wpm * 5 / 60
        intervals = []

        for i in range(text_length):
            base_interval = 1.0 / chars_per_second
            # Add variability: mistakes, pauses
            if random.random() < 0.05:  # 5% mistakes
                intervals.append(base_interval * 3)  # Correction time
            elif random.random() < 0.10:  # 10% thinking pauses
                intervals.append(base_interval * random.uniform(2, 5))
            else:
                intervals.append(base_interval * random.uniform(0.8, 1.2))

        return intervals

    def get_mouse_movement_pattern(self) -> List[Tuple[int, int]]:
        """Generate realistic mouse movement coordinates"""
        # Bézier curve-based mouse movement
        start = (random.randint(0, 1920), random.randint(0, 1080))
        end = (random.randint(0, 1920), random.randint(0, 1080))
        control1 = (random.randint(0, 1920), random.randint(0, 1080))
        control2 = (random.randint(0, 1920), random.randint(0, 1080))

        return self.bezier_curve(start, control1, control2, end, steps=50)
```

### 12.2 Fake Credential Generation

```python
# File: engine/deception/fake_credentials.py

class FakeCredentialGenerator:
    """Generates realistic but fake credentials with honeytokens"""

    def generate_email(self, domain: str) -> str:
        """Generate fake email with honeytoken"""
        first_names = ["john", "jane", "michael", "sarah", "david", "emma"]
        last_names = ["smith", "johnson", "williams", "brown", "jones"]

        first = random.choice(first_names)
        last = random.choice(last_names)

        # Embed honeytoken in email
        token = self.generate_honeytoken()

        patterns = [
            f"{first}.{last}+{token}@{domain}",
            f"{first}{last[0]}+{token}@{domain}",
            f"{first[0]}{last}+{token}@{domain}",
        ]

        return random.choice(patterns)

    def generate_password(self, strength: str = "medium") -> str:
        """Generate realistic fake password"""
        if strength == "weak":
            # Common patterns
            patterns = [
                "Password123!",
                "Welcome2024!",
                "Spring2025!",
            ]
            return random.choice(patterns)

        elif strength == "medium":
            # More complex but still guessable
            words = ["correct", "horse", "battery", "staple"]
            numbers = str(random.randint(100, 999))
            symbol = random.choice(["!", "@", "#", "$"])
            return "".join(random.sample(words, 2)) + numbers + symbol

        else:  # strong
            # High entropy
            chars = string.ascii_letters + string.digits + string.punctuation
            return ''.join(random.choices(chars, k=16))

    def generate_credit_card(self) -> Dict[str, str]:
        """Generate fake credit card (fails Luhn check)"""
        # Intentionally invalid but looks real
        card_number = "4532" + "".join([str(random.randint(0, 9)) for _ in range(12)])

        return {
            "number": card_number,
            "expiry": f"{random.randint(1, 12):02d}/{random.randint(25, 30)}",
            "cvv": f"{random.randint(100, 999)}",
            "holder": "JOHN DOE"
        }

    def generate_honeytoken(self) -> str:
        """Generate unique tracking token"""
        return secrets.token_urlsafe(16)
```

### 12.3 Packet Forgery

```python
# File: engine/deception/packet_forge.py

from scapy.all import *

class PacketForger:
    """Forges network packets to simulate user traffic"""

    def forge_http_request(self, url: str, attacker_ip: str, our_ip: str) -> bytes:
        """Create fake HTTP request packet"""
        parsed = urlparse(url)

        # Build packet layers
        ip = IP(src=our_ip, dst=attacker_ip)
        tcp = TCP(sport=random.randint(49152, 65535), dport=80, flags="PA", seq=1000, ack=1)

        http_request = (
            f"GET {parsed.path or '/'} HTTP/1.1\r\n"
            f"Host: {parsed.netloc}\r\n"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
            f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
            f"Accept-Language: en-US,en;q=0.5\r\n"
            f"Accept-Encoding: gzip, deflate\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
        )

        packet = ip / tcp / Raw(load=http_request)
        return bytes(packet)

    def forge_dns_query(self, domain: str, attacker_dns: str, our_ip: str) -> bytes:
        """Create fake DNS query packet"""
        ip = IP(src=our_ip, dst=attacker_dns)
        udp = UDP(sport=random.randint(49152, 65535), dport=53)

        dns = DNS(
            id=random.randint(0, 65535),
            qr=0,  # Query
            opcode=0,  # Standard query
            rd=1,  # Recursion desired
            qd=DNSQR(qname=domain, qtype="A", qclass="IN")
        )

        packet = ip / udp / dns
        return bytes(packet)

    def forge_tls_client_hello(self, server_ip: str, sni: str, our_ip: str) -> bytes:
        """Create fake TLS ClientHello packet"""
        ip = IP(src=our_ip, dst=server_ip)
        tcp = TCP(sport=random.randint(49152, 65535), dport=443, flags="PA")

        # Build TLS ClientHello (simplified)
        tls_version = b"\x03\x03"  # TLS 1.2
        random_bytes = os.urandom(32)
        session_id_length = b"\x00"
        cipher_suites = b"\x00\x2e" + self.get_common_cipher_suites()
        compression = b"\x01\x00"

        # SNI extension
        sni_bytes = sni.encode()
        sni_extension = (
            b"\x00\x00"  # Extension type: server_name
            + struct.pack(">H", len(sni_bytes) + 5)  # Extension length
            + struct.pack(">H", len(sni_bytes) + 3)  # Server name list length
            + b"\x00"  # Server name type: host_name
            + struct.pack(">H", len(sni_bytes))  # Server name length
            + sni_bytes
        )

        handshake_data = (
            tls_version
            + random_bytes
            + session_id_length
            + cipher_suites
            + compression
            + struct.pack(">H", len(sni_extension))  # Extensions length
            + sni_extension
        )

        handshake_header = (
            b"\x01"  # Handshake type: ClientHello
            + struct.pack(">I", len(handshake_data))[1:]  # Length (3 bytes)
            + handshake_data
        )

        tls_record = (
            b"\x16"  # Content type: Handshake
            + tls_version
            + struct.pack(">H", len(handshake_header))
            + handshake_header
        )

        packet = ip / tcp / Raw(load=tls_record)
        return bytes(packet)
```

---

## 13. Verification Specifications

### 13.1 Path Selection Algorithm

```python
# File: verification-container/path_selector.py

class PathSelector:
    """Selects optimal verification paths based on availability and performance"""

    def __init__(self):
        self.paths = self.discover_paths()
        self.path_stats = {}  # path_id -> PathStats

    def select_paths(self, num_paths: int, strategy: str = "diverse") -> List[str]:
        """Select verification paths based on strategy"""

        if strategy == "diverse":
            # Maximize geographic and technical diversity
            return self._select_diverse_paths(num_paths)

        elif strategy == "fastest":
            # Select paths with lowest latency
            return self._select_fastest_paths(num_paths)

        elif strategy == "reliable":
            # Select paths with highest success rate
            return self._select_reliable_paths(num_paths)

        else:  # "balanced"
            # Balance between speed and reliability
            return self._select_balanced_paths(num_paths)

    def _select_diverse_paths(self, num_paths: int) -> List[str]:
        """Maximize diversity across VPNs and routing methods"""
        selected = []
        vpns_used = set()
        methods_used = {"direct": 0, "tor": 0, "proxy": 0, "tor+proxy": 0}

        available = [p for p in self.paths if self.is_path_available(p)]

        while len(selected) < num_paths and available:
            # Score each path by diversity contribution
            best_path = None
            best_score = -1

            for path in available:
                score = 0

                # Prefer unused VPNs
                if path.vpn_id not in vpns_used:
                    score += 10

                # Balance routing methods
                method_count = methods_used[path.method]
                score += (10 - method_count)

                if score > best_score:
                    best_score = score
                    best_path = path

            if best_path:
                selected.append(best_path.id)
                vpns_used.add(best_path.vpn_id)
                methods_used[best_path.method] += 1
                available.remove(best_path)

        return selected
```

### 13.2 Response Comparison Algorithm

```python
# File: verification-container/response_comparator.py

class ResponseComparator:
    """Compares HTTP responses to detect tampering"""

    def compare_responses(self, responses: List[Response]) -> ComparisonResult:
        """Compare multiple responses and determine consensus"""

        # 1. Group responses by content hash
        groups = self._group_by_content(responses)

        # 2. Find majority group
        majority_group = max(groups, key=lambda g: len(g.responses))
        majority_count = len(majority_group.responses)
        total_count = len(responses)
        confidence = majority_count / total_count

        # 3. Identify outliers
        outliers = []
        for group in groups:
            if group != majority_group:
                outliers.extend(group.responses)

        # 4. Detailed comparison of outliers
        differences = []
        if outliers:
            majority_response = majority_group.responses[0]
            for outlier in outliers:
                diffs = self._find_differences(majority_response, outlier)
                differences.append({
                    "path": outlier.path_id,
                    "differences": diffs
                })

        return ComparisonResult(
            consensus=majority_group.content,
            confidence=confidence,
            paths_agreed=majority_count,
            paths_total=total_count,
            outliers=[r.path_id for r in outliers],
            differences=differences
        )

    def _group_by_content(self, responses: List[Response]) -> List[ResponseGroup]:
        """Group responses by content similarity"""
        groups = []

        for response in responses:
            # Calculate content hash (ignore volatile headers)
            content_hash = self._calculate_content_hash(response)

            # Find matching group
            matched_group = None
            for group in groups:
                if group.content_hash == content_hash:
                    matched_group = group
                    break

            if matched_group:
                matched_group.responses.append(response)
            else:
                groups.append(ResponseGroup(
                    content_hash=content_hash,
                    content=response.content,
                    responses=[response]
                ))

        return groups

    def _calculate_content_hash(self, response: Response) -> str:
        """Calculate hash of response content, excluding volatile parts"""
        # Remove volatile headers
        stable_headers = {
            k: v for k, v in response.headers.items()
            if k.lower() not in ['date', 'set-cookie', 'expires', 'age']
        }

        # Hash body + stable headers
        hasher = hashlib.sha256()
        hasher.update(response.body)
        hasher.update(json.dumps(stable_headers, sort_keys=True).encode())

        return hasher.hexdigest()

    def _find_differences(self, response1: Response, response2: Response) -> List[Dict]:
        """Find specific differences between two responses"""
        differences = []

        # Status code difference
        if response1.status_code != response2.status_code:
            differences.append({
                "field": "status_code",
                "expected": response1.status_code,
                "actual": response2.status_code
            })

        # Header differences
        all_headers = set(response1.headers.keys()) | set(response2.headers.keys())
        for header in all_headers:
            val1 = response1.headers.get(header)
            val2 = response2.headers.get(header)

            if val1 != val2:
                differences.append({
                    "field": f"header.{header}",
                    "expected": val1,
                    "actual": val2
                })

        # Body differences
        if response1.body != response2.body:
            # Calculate similarity ratio
            similarity = difflib.SequenceMatcher(None, response1.body, response2.body).ratio()
            differences.append({
                "field": "body",
                "similarity": similarity,
                "length_expected": len(response1.body),
                "length_actual": len(response2.body)
            })

        return differences
```

---

## 14. Honeypot Specifications

### 14.1 SSH Tarpit Behavior

```python
# File: honeypot-container/services/ssh_tarpit.py

class SSHTarpit:
    """SSH honeypot with tarpit behavior"""

    def __init__(self, port: int = 22):
        self.port = port
        self.connections = {}

    async def handle_connection(self, reader, writer):
        """Handle SSH connection with intentional delays"""
        client_addr = writer.get_extra_info('peername')
        conn_id = f"{client_addr[0]}:{client_addr[1]}"

        logger.info(f"SSH connection from {client_addr}")

        try:
            # 1. Send banner (slowly)
            banner = b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"
            for byte in banner:
                writer.write(bytes([byte]))
                await writer.drain()
                await asyncio.sleep(random.uniform(0.05, 0.15))  # Slow drip

            # 2. Key exchange (with delays)
            await asyncio.sleep(random.uniform(2, 5))

            # 3. Authentication attempts (accept but delay)
            attempt = 0
            while attempt < 10000:  # Virtually infinite
                # Read auth attempt (with timeout)
                try:
                    data = await asyncio.wait_for(reader.read(1024), timeout=30)
                    if not data:
                        break
                except asyncio.TimeoutError:
                    break

                attempt += 1

                # Log attempt
                logger.info(f"SSH auth attempt #{attempt} from {client_addr}")

                # Delay before responding
                delay = min(attempt * 2, 60)  # Increasing delay up to 60s
                await asyncio.sleep(delay)

                # Send authentication failure
                writer.write(b"\x06")  # SSH_MSG_USERAUTH_FAILURE
                await writer.drain()

        except Exception as e:
            logger.error(f"SSH tarpit error: {e}")

        finally:
            writer.close()
            await writer.wait_closed()
            logger.info(f"SSH connection closed: {client_addr}, {attempt} attempts, duration: {time.time() - start}")
```

### 14.2 Fake Web Service

```python
# File: honeypot-container/services/fake_web.py

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
import asyncio

app = FastAPI()

@app.middleware("http")
async def slow_middleware(request: Request, call_next):
    """Add random delays to all responses"""
    await asyncio.sleep(random.uniform(0.5, 2.0))
    response = await call_next(request)
    return response

@app.get("/", response_class=HTMLResponse)
async def index():
    """Fake login page"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Company Portal Login</title>
    </head>
    <body>
        <h1>Employee Portal</h1>
        <form method="POST" action="/login">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
    </body>
    </html>
    """

@app.post("/login")
async def login(request: Request):
    """Accept credentials, log them, return fake error"""
    form_data = await request.form()
    username = form_data.get("username")
    password = form_data.get("password")

    # Log credentials
    logger.warning(f"Honeypot login attempt: {username}:{password} from {request.client.host}")

    # Create honeytoken
    honeytoken = create_honeytoken(username, password, request.client.host)

    # Delay before responding
    await asyncio.sleep(random.uniform(3, 8))

    # Return error (never succeed)
    return HTMLResponse("""
    <html>
    <body>
        <h1>Login Failed</h1>
        <p>Invalid credentials. Please try again.</p>
        <a href="/">Back to login</a>
    </body>
    </html>
    """, status_code=401)
```

---

## Conclusion

This technical specification document provides comprehensive implementation guidance for all components of the NLSN PCAP Monitor system. It defines:

- **Exact packet formats** and parsing requirements for DNS, HTTP, TLS, and ARP
- **Detection algorithms** with scoring systems and thresholds
- **Performance requirements** with measurable targets
- **Data structures** for in-memory and persistent storage
- **Protocol handling** including TCP stream reassembly
- **Error handling** policies and recovery strategies
- **Event schemas** in JSON format
- **Database schemas** with indexes and partitioning
- **Deception specifications** for realistic behavior simulation
- **Verification algorithms** for multi-path comparison
- **Honeypot behaviors** for tarpit techniques

These specifications serve as the authoritative reference for implementation in Phases 2-4.

---

**Document Version:** 1.0
**Total Word Count:** ~15,200 words
**Last Updated:** 2025-11-10
