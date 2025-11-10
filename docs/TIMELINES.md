# Project Timelines

**Version:** 1.0
**Last Updated:** 2025-11-10
**Project:** NLSN PCAP Monitor

---

## Table of Contents

1. [Overview](#overview)
2. [Project Schedule](#project-schedule)
3. [Gantt Chart](#gantt-chart)
4. [Critical Path Analysis](#critical-path-analysis)
5. [Resource Allocation](#resource-allocation)
6. [Milestones](#milestones)
7. [Risk Assessment](#risk-assessment)
8. [Dependencies](#dependencies)

---

## 1. Overview

### 1.1 Project Duration

**Total Duration:** 24 weeks (6 months)
**Start Date:** Week 1
**Target Completion:** Week 24

### 1.2 Team Composition

**Single Developer Scenario (Baseline):**
- 1 Full-time developer
- 40 hours per week
- Total effort: 960 hours

**Two Developer Scenario (Accelerated):**
- 2 Full-time developers
- Project duration: 18 weeks
- Total effort: 1,440 hours (with some overhead)

**Four Developer Scenario (Maximum Parallelization):**
- 4 Full-time developers
- Project duration: 12 weeks
- Total effort: 1,920 hours (with coordination overhead)

### 1.3 Phase Breakdown

| Phase | Weeks | Percentage | Status |
|-------|-------|------------|--------|
| Phase 1: Foundation | 3 | 12.5% | ✅ Complete |
| Phase 2: Detection Layer | 7 | 29.2% | 🚧 Next |
| Phase 3: Deception Engine | 4 | 16.7% | 📋 Planned |
| Phase 4: Honeypot System | 4 | 16.7% | 📋 Planned |
| Phase 5: Integration & Testing | 4 | 16.7% | 📋 Planned |
| Phase 6: Production Deployment | 2 | 8.3% | 📋 Planned |

---

## 2. Project Schedule

### Phase 1: Foundation (Weeks 1-3) ✅ COMPLETE

#### Week 1: Project Setup & Architecture
**Hours:** 40

| Day | Task | Hours | Deliverables |
|-----|------|-------|--------------|
| Mon | Project initialization, Git setup | 4 | Repository, README |
| Tue | Architecture design | 8 | ARCHITECTURE.md |
| Wed | Component specification | 8 | TECHNICAL_SPECS.md |
| Thu | API design | 8 | API_DESIGN.md |
| Fri | Security design | 8 | SECURITY_DESIGN.md |
| Sat-Sun | Documentation review | 4 | Complete Phase 1 docs |

**Deliverables:**
- ✅ Repository structure
- ✅ All design documentation
- ✅ Development roadmap

#### Week 2: Container Setup & Configuration
**Hours:** 40

| Day | Task | Hours | Deliverables |
|-----|------|-------|--------------|
| Mon | Docker Compose configuration | 6 | docker-compose.yml |
| Tue | Verification container Dockerfile | 8 | Verification container |
| Wed | VPN namespace setup script | 8 | setup-namespaces.sh |
| Thu | Honeypot container setup | 6 | Honeypot Dockerfile |
| Fri | Monitor/Engine Dockerfiles | 8 | Go/Python containers |
| Sat-Sun | Configuration system | 4 | settings.yaml schema |

**Deliverables:**
- ✅ All Docker containers
- ✅ Docker Compose orchestration
- ✅ Configuration system

#### Week 3: Infrastructure & Skeletons
**Hours:** 40

| Day | Task | Hours | Deliverables |
|-----|------|-------|--------------|
| Mon | Database schema | 6 | PostgreSQL migrations |
| Tue | Redis event bus setup | 4 | Event channels |
| Wed | Go Monitor skeleton | 10 | cmd/monitor/main.go |
| Thu | Python Engine skeleton | 10 | api/server.py |
| Fri | Path Orchestrator API | 8 | path-orchestrator.py |
| Sat-Sun | Integration testing | 2 | Smoke tests |

**Deliverables:**
- ✅ Database and Redis
- ✅ Basic packet capture framework
- ✅ API server frameworks
- ✅ Verification API

---

### Phase 2: Detection Layer (Weeks 4-10) 🚧 NEXT

#### Week 4: DNS Detection
**Hours:** 44

**Tasks:**
1. DNS Parser (Go) - 16 hours
   - Parse DNS queries and responses
   - Handle name compression
   - Transaction ID correlation
   - File: `core/pkg/parser/dns.go`

2. DNS Anomaly Detection (Go) - 20 hours
   - Implement detection heuristics
   - Baseline learning
   - Scoring algorithm
   - File: `core/pkg/detector/dns.go`

3. Redis Event Publishing (Go) - 8 hours
   - Publish DNS packet events
   - Publish attack detection events
   - File: `core/pkg/events/publisher.go`

**Acceptance Criteria:**
- Parse 10,000 DNS packets/second
- Detect hijacking with >95% accuracy
- Publish events to Redis in <5ms

#### Week 5: HTTP/TLS Detection
**Hours:** 44

**Tasks:**
1. HTTP Parser (Go) - 16 hours
   - Parse HTTP requests/responses
   - TCP stream reassembly
   - File: `core/pkg/parser/http.go`

2. TLS Parser (Go) - 16 hours
   - Parse TLS handshakes
   - Extract cipher suites
   - SNI extraction
   - File: `core/pkg/parser/tls.go`

3. SSL Stripping Detection (Go) - 12 hours
   - HTTPS expectation tracking
   - HSTS monitoring
   - File: `core/pkg/detector/tls.go`

**Acceptance Criteria:**
- Parse HTTP/TLS at line rate
- Detect SSL stripping with >90% accuracy

#### Week 6: ARP Detection & Engine Integration
**Hours:** 40

**Tasks:**
1. ARP Parser & Detection (Go) - 12 hours
   - ARP packet parsing
   - ARP spoofing detection
   - File: `core/pkg/detector/arp.go`

2. Engine Event Subscriber (Python) - 16 hours
   - Subscribe to Redis events
   - Process attack detections
   - File: `engine/events/subscriber.py`

3. Verification Trigger Logic (Python) - 12 hours
   - Automatic verification on suspicious events
   - File: `engine/verification/trigger.py`

**Acceptance Criteria:**
- Engine receives all monitor events
- Verification triggered automatically

#### Week 7-8: Verification Client & DNS Verification
**Hours:** 80 (2 weeks)

**Tasks:**
1. Verification API Client (Python) - 12 hours
   - HTTP client for verification API
   - Async request handling
   - File: `engine/verification/client.py`

2. DNS Hijack Verification (Python) - 20 hours
   - Multi-path DNS resolution
   - Response comparison logic
   - Majority voting algorithm
   - File: `engine/detector/dns_hijack.py`

3. SSL Strip Verification (Python) - 16 hours
   - HTTPS connectivity testing
   - Content comparison
   - File: `engine/detector/ssl_strip.py`

4. Threat Logging (Python) - 12 hours
   - Database threat storage
   - Verification result storage
   - File: `engine/intelligence/threat_db.py`

5. Testing & Integration - 20 hours
   - Unit tests
   - Integration tests
   - End-to-end scenarios

**Acceptance Criteria:**
- Verification completes in <10s
- Threats logged to database
- >95% detection accuracy

#### Week 9-10: Baseline & Optimization
**Hours:** 72 (1.8 weeks)

**Tasks:**
1. Baseline Learning (Go/Python) - 24 hours
   - Network baseline builder
   - DNS baseline
   - HTTP/TLS baseline
   - Files: `core/pkg/baseline/`, `engine/baseline/`

2. Performance Optimization (Go) - 24 hours
   - Packet processing optimization
   - Memory optimization
   - BPF filter tuning

3. Detection Tuning (Python) - 16 hours
   - Threshold calibration
   - False positive reduction

4. Documentation & Testing - 8 hours

**Acceptance Criteria:**
- Baseline learns in 24 hours
- False positive rate <2%
- Process 40,000 packets/second

---

### Phase 3: Deception Engine (Weeks 11-14) 📋 Planned

#### Week 11: Deception Autopilot
**Hours:** 40

**Tasks:**
1. Deception Session Manager - 12 hours
   - Session lifecycle management
   - File: `engine/deception/session_manager.py`

2. Deception Autopilot - 16 hours
   - Automatic activation logic
   - Behavior profile selection
   - File: `engine/deception/autopilot.py`

3. Event Integration - 8 hours
   - Trigger on attack confirmation
   - Publish deception events

4. API Endpoints - 4 hours
   - `/deception/start`
   - `/deception/stop`

**Acceptance Criteria:**
- Activate within 100ms of attack
- Track multiple concurrent sessions

#### Week 12: Behavior Simulation
**Hours:** 44

**Tasks:**
1. Human Behavior Simulator - 20 hours
   - Timing patterns
   - Mouse movements
   - Typing simulation
   - File: `engine/deception/behavior_sim.py`

2. Fake Credential Generator - 12 hours
   - Email generation
   - Password generation
   - Credit card generation
   - File: `engine/deception/fake_credentials.py`

3. Behavior Profiles - 12 hours
   - Average user
   - Banking user
   - Developer
   - Executive

**Acceptance Criteria:**
- Realism score >8/10
- 4 complete behavior profiles

#### Week 13-14: Packet Forgery & Honeytokens
**Hours:** 72 (1.8 weeks)

**Tasks:**
1. Packet Forger (Python/Scapy) - 24 hours
   - HTTP request forgery
   - DNS query forgery
   - TLS ClientHello forgery
   - File: `engine/deception/packet_forge.py`

2. Honeytoken System - 20 hours
   - Token generation
   - Token embedding
   - Trigger tracking
   - File: `engine/intelligence/honeytoken_tracker.py`

3. Response Server - 12 hours
   - Controlled endpoints for fake traffic
   - File: `engine/deception/response_server.py`

4. Testing & Integration - 16 hours

**Acceptance Criteria:**
- Generate >100 packets/second
- Honeytokens tracked globally
- Deception traffic indistinguishable

---

### Phase 4: Honeypot System (Weeks 15-18) 📋 Planned

#### Week 15: SSH Tarpit
**Hours:** 40

**Tasks:**
1. SSH Tarpit Implementation - 20 hours
   - Cowrie integration
   - Slow response mechanism
   - File: `honeypot-container/services/ssh_tarpit.py`

2. Logging & Monitoring - 12 hours
   - Connection logging
   - Attack pattern analysis

3. Testing - 8 hours

**Acceptance Criteria:**
- Accept SSH connections
- Tarpit attackers (>30s per auth attempt)
- Log all activity

#### Week 16-17: Web & Database Honeypots
**Hours:** 72 (1.8 weeks)

**Tasks:**
1. Fake Web Service - 20 hours
   - Login pages
   - Fake admin panels
   - File: `honeypot-container/services/fake_web.py`

2. Fake Database Service - 16 hours
   - MySQL honeypot
   - Fake data
   - File: `honeypot-container/services/fake_mysql.py`

3. Network Isolation - 12 hours
   - Firewall rules
   - No route to internal network

4. Integration - 24 hours
   - Docker networking
   - Log forwarding
   - Testing

**Acceptance Criteria:**
- Honeypot accepts all connections
- Complete network isolation
- All interactions logged

#### Week 18: Honeypot Hardening
**Hours:** 32 (0.8 weeks)

**Tasks:**
1. Security Hardening - 16 hours
   - Container restrictions
   - AppArmor profiles
   - Resource limits

2. Advanced Logging - 8 hours
   - Forensic capture
   - Behavior analysis

3. Documentation - 8 hours

---

### Phase 5: Integration & Testing (Weeks 19-22) 📋 Planned

#### Week 19-20: Integration Testing
**Hours:** 72 (1.8 weeks)

**Tasks:**
1. End-to-End Test Suite - 32 hours
   - Full attack scenarios
   - Multi-component flows

2. Performance Testing - 24 hours
   - Load testing
   - Stress testing
   - Benchmarking

3. Security Testing - 16 hours
   - Penetration testing
   - Vulnerability scanning

**Acceptance Criteria:**
- All E2E tests pass
- Meet performance requirements
- No critical vulnerabilities

#### Week 21-22: Bug Fixes & Polish
**Hours:** 72 (1.8 weeks)

**Tasks:**
1. Bug Fixes - 40 hours
   - Fix discovered issues
   - Edge case handling

2. UI/Dashboard (Optional) - 20 hours
   - Simple web dashboard
   - Threat visualization

3. Documentation Finalization - 12 hours
   - Update all docs
   - Create user guide

---

### Phase 6: Production Deployment (Weeks 23-24) 📋 Planned

#### Week 23: Production Preparation
**Hours:** 40

**Tasks:**
1. Production Configuration - 12 hours
   - Secure defaults
   - Performance tuning

2. Deployment Automation - 16 hours
   - CI/CD pipeline
   - Automated testing

3. Monitoring Setup - 12 hours
   - Prometheus/Grafana
   - Alerting rules

**Acceptance Criteria:**
- Production-ready configuration
- Automated deployment pipeline
- Monitoring operational

#### Week 24: Launch & Handoff
**Hours:** 32 (0.8 weeks)

**Tasks:**
1. Production Deployment - 8 hours
   - Deploy to production
   - Smoke tests

2. User Training - 8 hours
   - Documentation walkthrough
   - Demo sessions

3. Handoff & Support - 8 hours
   - Knowledge transfer
   - Support procedures

4. Post-Launch Monitoring - 8 hours
   - Monitor first week
   - Address issues

**Acceptance Criteria:**
- System deployed and stable
- Users trained
- Support handoff complete

---

## 3. Gantt Chart

```
Phase/Task                    | W1 | W2 | W3 | W4 | W5 | W6 | W7 | W8 | W9 | W10| W11| W12| W13| W14| W15| W16| W17| W18| W19| W20| W21| W22| W23| W24|
------------------------------|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|
Phase 1: Foundation           |████|████|████|    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |
  Project Setup               |████|    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |
  Container Setup             |    |████|    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |
  Infrastructure              |    |    |████|    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |
Phase 2: Detection            |    |    |    |████|████|████|████|████|████|████|    |    |    |    |    |    |    |    |    |    |    |    |    |    |
  DNS Detection               |    |    |    |████|    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |
  HTTP/TLS Detection          |    |    |    |    |████|    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |
  ARP Detection               |    |    |    |    |    |████|    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |
  Verification Logic          |    |    |    |    |    |    |████|████|    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |
  Baseline & Optimization     |    |    |    |    |    |    |    |    |████|████|    |    |    |    |    |    |    |    |    |    |    |    |    |    |
Phase 3: Deception            |    |    |    |    |    |    |    |    |    |    |████|████|████|████|    |    |    |    |    |    |    |    |    |    |
  Autopilot                   |    |    |    |    |    |    |    |    |    |    |████|    |    |    |    |    |    |    |    |    |    |    |    |    |
  Behavior Simulation         |    |    |    |    |    |    |    |    |    |    |    |████|    |    |    |    |    |    |    |    |    |    |    |    |
  Packet Forgery              |    |    |    |    |    |    |    |    |    |    |    |    |████|████|    |    |    |    |    |    |    |    |    |    |
Phase 4: Honeypot             |    |    |    |    |    |    |    |    |    |    |    |    |    |    |████|████|████|████|    |    |    |    |    |    |
  SSH Tarpit                  |    |    |    |    |    |    |    |    |    |    |    |    |    |    |████|    |    |    |    |    |    |    |    |    |
  Web/DB Honeypots            |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |████|████|    |    |    |    |    |    |    |
  Hardening                   |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |████|    |    |    |    |    |    |
Phase 5: Integration          |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |████|████|████|████|    |    |
  Integration Testing         |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |████|████|    |    |    |    |
  Bug Fixes & Polish          |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |████|████|    |    |
Phase 6: Production           |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |████|████|
  Production Prep             |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |████|    |
  Launch & Handoff            |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |████|
```

---

## 4. Critical Path Analysis

### 4.1 Critical Path

The longest path through the project that determines minimum duration:

```
Foundation → DNS Detection → HTTP/TLS Detection → Verification Logic →
Baseline Learning → Deception Autopilot → Packet Forgery →
SSH Tarpit → Integration Testing → Production Deployment
```

**Critical Path Duration:** 22 weeks
**Buffer:** 2 weeks (built into 24-week schedule)

### 4.2 Critical Tasks

Tasks on critical path that cannot be delayed:

1. **DNS Parser** (Week 4) - 16 hours
   - Blocks all DNS detection
   - No parallel work possible

2. **Verification Logic** (Weeks 7-8) - 48 hours
   - Blocks deception activation
   - Core system capability

3. **Deception Autopilot** (Week 11) - 16 hours
   - Blocks all deception features
   - Required for Phases 3-4

4. **Integration Testing** (Weeks 19-20) - 72 hours
   - Cannot start until all features complete
   - Blocks production deployment

### 4.3 Float/Slack Analysis

Tasks with scheduling flexibility:

| Task | Float | Can Start | Must Finish By |
|------|-------|-----------|----------------|
| ARP Detection | 2 weeks | Week 6 | Week 8 |
| Honeypot Web | 1 week | Week 16 | Week 18 |
| UI Dashboard | 4 weeks | Week 18 | Week 22 |
| Documentation | 2 weeks | Week 20 | Week 24 |

---

## 5. Resource Allocation

### 5.1 Single Developer Schedule

**Week-by-Week Breakdown:**

| Week | Phase | Focus Area | Hours | Cumulative % |
|------|-------|------------|-------|--------------|
| 1 | Foundation | Architecture & Design | 40 | 4.2% |
| 2 | Foundation | Container Setup | 40 | 8.3% |
| 3 | Foundation | Infrastructure | 40 | 12.5% |
| 4 | Detection | DNS Detection | 44 | 17.1% |
| 5 | Detection | HTTP/TLS Detection | 44 | 21.8% |
| 6 | Detection | ARP & Engine Integration | 40 | 26.0% |
| 7-8 | Detection | Verification Logic | 80 | 34.3% |
| 9-10 | Detection | Baseline & Optimization | 72 | 41.8% |
| 11 | Deception | Autopilot | 40 | 45.9% |
| 12 | Deception | Behavior Simulation | 44 | 50.5% |
| 13-14 | Deception | Packet Forgery | 72 | 58.0% |
| 15 | Honeypot | SSH Tarpit | 40 | 62.1% |
| 16-17 | Honeypot | Web/DB Honeypots | 72 | 69.6% |
| 18 | Honeypot | Hardening | 32 | 73.0% |
| 19-20 | Integration | Testing | 72 | 80.5% |
| 21-22 | Integration | Bug Fixes & Polish | 72 | 88.0% |
| 23 | Production | Preparation | 40 | 92.1% |
| 24 | Production | Launch | 32 | 95.4% |
| Buffer | | Contingency | 44 | 100.0% |

**Total Hours:** 960 hours

### 5.2 Two Developer Schedule (18 weeks)

**Parallelization Strategy:**

| Weeks | Developer 1 | Developer 2 |
|-------|-------------|-------------|
| 1-3 | Foundation (shared) | Foundation (shared) |
| 4-5 | DNS + ARP Detection | HTTP + TLS Detection |
| 6-7 | Go parsers & optimizations | Python verification logic |
| 8-10 | Baseline learning | Deception autopilot |
| 11-12 | Behavior simulation | Packet forgery |
| 13-14 | SSH Tarpit | Web/DB Honeypots |
| 15-16 | Integration testing | Security testing |
| 17-18 | Bug fixes & production prep | Documentation & deployment |

**Total Duration:** 18 weeks
**Total Effort:** 1,440 hours (720 hours each)

---

## 6. Milestones

### M1: Foundation Complete (Week 3)
- ✅ All containers built and running
- ✅ Configuration system implemented
- ✅ Basic infrastructure operational
- ✅ Verification API responding

### M2: Detection Operational (Week 10)
- DNS/HTTP/TLS/ARP detection working
- Events published to Redis
- Baseline learning complete
- Verification triggered automatically
- **Success Criteria:** Detect test attacks with >90% accuracy

### M3: Deception Functional (Week 14)
- Deception activated on attack
- Fake traffic generated
- Honeytokens deployed and tracked
- **Success Criteria:** Deception indistinguishable from real traffic

### M4: Honeypot Deployed (Week 18)
- SSH/Web/DB honeypots operational
- Network isolation verified
- All interactions logged
- **Success Criteria:** Tarpit attackers for >30s per interaction

### M5: System Integrated (Week 22)
- All components working together
- End-to-end tests passing
- Performance requirements met
- **Success Criteria:** Process 40K packets/sec, <1% packet loss

### M6: Production Ready (Week 24)
- Deployed to production
- Monitoring operational
- Documentation complete
- **Success Criteria:** System stable for 1 week

---

## 7. Risk Assessment

### 7.1 High-Priority Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| **VPN connectivity issues** | Medium | High | Test with multiple providers, implement fallback |
| **Performance bottleneck** | Medium | High | Profiling early, optimize critical path |
| **False positive rate too high** | High | Medium | Extensive testing, tunable thresholds |
| **Packet loss at high load** | Medium | High | BPF filtering, packet sampling option |
| **Scope creep** | High | Medium | Strict adherence to phases, defer non-critical features |

### 7.2 Medium-Priority Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Docker networking complexity | Medium | Medium | Early testing, documentation |
| Deception realism insufficient | Medium | Medium | User testing, behavior tuning |
| Database performance issues | Low | Medium | Connection pooling, indexing |
| Integration complexity | Medium | Medium | Incremental integration, continuous testing |

### 7.3 Contingency Plans

**If 2 weeks behind schedule:**
- Descope UI dashboard (optional feature)
- Reduce number of behavior profiles (keep 2 instead of 4)
- Simplify honeypot services (SSH only, defer web/DB)

**If critical blocker encountered:**
- Utilize 2-week buffer built into schedule
- Escalate to stakeholders
- Consider bringing in additional resource

---

## 8. Dependencies

### 8.1 Internal Dependencies

```
DNS Parser
    ↓
DNS Detection
    ↓
Verification Trigger
    ↓
Deception Autopilot
    ↓
Packet Forgery
```

### 8.2 External Dependencies

| Dependency | Required By | Risk Level |
|------------|-------------|------------|
| Surfshark VPN | Week 2 | Low (can substitute) |
| Docker/Docker Compose | Week 1 | Low (standard tools) |
| Go 1.21+ | Week 3 | Low (standard language) |
| Python 3.11+ | Week 3 | Low (standard language) |
| PostgreSQL/Redis | Week 3 | Low (standard databases) |

### 8.3 Knowledge Dependencies

| Knowledge Area | Required By | Mitigation |
|----------------|-------------|------------|
| Network namespaces | Week 2 | Documentation, experimentation |
| Scapy packet forgery | Week 13 | Tutorials, practice |
| Behavioral analysis | Week 12 | Research, user testing |
| Container security | Week 18 | Security documentation |

---

## Conclusion

This timeline provides:

- **Detailed week-by-week schedule** for 24-week project
- **Gantt chart** showing task dependencies and parallelization
- **Critical path analysis** identifying must-not-delay tasks
- **Resource allocation** for 1-4 developer scenarios
- **Clear milestones** with success criteria
- **Risk assessment** with mitigation strategies
- **Dependency mapping** for planning and execution

Following this timeline ensures structured, predictable project delivery.

---

**Document Version:** 1.0
**Total Word Count:** ~5,500 words
**Last Updated:** 2025-11-10
