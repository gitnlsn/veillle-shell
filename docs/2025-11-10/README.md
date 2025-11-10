# NLSN PCAP Monitor - CLI Architecture Documentation (2025-11-10)

This directory contains the **revised architecture documentation** for NLSN PCAP Monitor, representing a shift from microservices to a CLI-first design.

## Documentation Files

### 1. [ARCHITECTURE-CLI.md](./ARCHITECTURE-CLI.md)
**Complete architectural overview of the CLI-first design**

- Design philosophy (Unix principles, user control, simplicity)
- Layer-by-layer architecture (5 layers: CLI → Detection → Parsers → Capture → Network)
- Component specifications (CLI binary, config system, storage, parsers, detectors)
- Data flow diagrams
- Performance targets and optimization strategies
- Security model
- Comparison with original microservices design

**Start here for:** Understanding the overall system architecture

---

### 2. [IMPLEMENTATION-PLAN.md](./IMPLEMENTATION-PLAN.md)
**Complete 20-week implementation roadmap**

- **Phase 1** (Weeks 1-4): Foundation - Packet capture & DNS detection
- **Phase 2** (Weeks 5-8): HTTP/TLS parsing & SSL stripping detection
- **Phase 3** (Weeks 9-12): Multi-path verification (sequential)
- **Phase 4** (Weeks 13-16): Deception & automation
- **Phase 5** (Weeks 17-20): Polish & advanced features

Each week broken down into:
- Specific tasks with hour estimates
- Deliverables and checkpoints
- Test criteria
- Code examples

**Start here for:** Planning the implementation timeline

---

### 3. [PHASE1-BASICS.md](./PHASE1-BASICS.md)
**Detailed Week 1-4 implementation guide**

Week-by-week, day-by-day breakdown of Phase 1:

**Week 1: CLI Framework & Packet Capture**
- Day 1-2: Project setup (Go modules, dependencies, directory structure)
- Day 3-4: CLI framework (Cobra commands, config loading, flags)
- Day 5-7: Packet capture engine (interface detection, libpcap, BPF filters)

**Week 2: DNS Parser & Storage**
- DNS protocol parsing
- SQLite database setup
- Unit tests

**Week 3: DNS Hijacking Detection**
- Detection engine framework
- DNS hijack detector implementation
- Real-time alerting

**Week 4: Testing & Polish**
- Integration testing
- Configuration system
- Documentation
- v0.1.0 release

Includes:
- Complete code examples
- Prerequisites and setup instructions
- Troubleshooting guide
- Quick reference commands

**Start here for:** Beginning implementation (copy-paste ready code)

---

### 4. [TECHNICAL-DECISIONS.md](./TECHNICAL-DECISIONS.md)
**Rationale for CLI vs microservices architecture choice**

Comprehensive analysis covering:
- Decision criteria and scoring
- Detailed trade-off analysis (10 categories)
- What we gain (simplicity, control, integration, efficiency)
- What we lose (continuous monitoring, automated response, speed)
- Alternative approaches considered (hybrid, CLI wrapper)
- Lessons learned
- Conclusion and recommendations

**Start here for:** Understanding why this approach was chosen

---

### 5. [MIGRATION-NOTES.md](./MIGRATION-NOTES.md)
**Transition guide from microservices to CLI**

- Current state analysis (what exists, what's missing)
- Migration strategy (fresh start vs refactor)
- What to reuse (verification container, algorithms, schemas)
- What NOT to reuse (Python code, Docker config, Redis)
- Code migration examples (before/after)
- File-by-file migration plan
- Verification container handling options
- Timeline and risks

**Start here for:** Transitioning from the old architecture

---

## Quick Start Guide

### For New Developers

1. **Read:** [ARCHITECTURE-CLI.md](./ARCHITECTURE-CLI.md) - Understand the system
2. **Read:** [PHASE1-BASICS.md](./PHASE1-BASICS.md) - Get started coding
3. **Follow:** Week 1 Day 1-2 tasks - Set up your environment
4. **Build:** The CLI framework step-by-step

### For Reviewers

1. **Read:** [TECHNICAL-DECISIONS.md](./TECHNICAL-DECISIONS.md) - Understand the "why"
2. **Review:** [ARCHITECTURE-CLI.md](./ARCHITECTURE-CLI.md) - Evaluate the design
3. **Check:** [IMPLEMENTATION-PLAN.md](./IMPLEMENTATION-PLAN.md) - Assess feasibility

### For Project Managers

1. **Read:** [IMPLEMENTATION-PLAN.md](./IMPLEMENTATION-PLAN.md) - Understand timeline
2. **Review:** Milestones and deliverables
3. **Track:** Weekly progress against plan

---

## Key Changes from Original Design

### Architecture

| Aspect | Original (Microservices) | New (CLI) |
|--------|-------------------------|-----------|
| Deployment | 6 Docker containers | Single Go binary |
| Languages | Go + Python | Go only |
| Storage | PostgreSQL + Redis | SQLite |
| Operation | Always-on (24/7) | On-demand (user-controlled) |
| Config | `./shared/config/` | `~/.config/nlsn-pcap/` |
| Verification | 40 parallel paths (~10s) | Sequential or optional API (~50s) |

### What Stays the Same

- Detection algorithms (DNS hijacking, SSL stripping, weak crypto)
- Multi-path verification concept (simplified implementation)
- Threat intelligence database (adapted for SQLite)
- Security model and detection patterns

---

## Timeline Overview

```
Phase 1: Foundation (Weeks 1-4)
├─ Week 1: CLI framework + packet capture
├─ Week 2: DNS parser + storage
├─ Week 3: DNS detection
└─ Week 4: Testing + v0.1.0 release

Phase 2: Protocol Coverage (Weeks 5-8)
├─ Week 5: HTTP parser
├─ Week 6: TLS parser
├─ Week 7: SSL stripping detection
└─ Week 8: Multi-protocol integration

Phase 3: Verification (Weeks 9-12)
├─ Week 9: VPN management
├─ Week 10: Sequential verification
├─ Week 11: Optimization
└─ Week 12: Testing + documentation

Phase 4: Automation (Weeks 13-16)
└─ Deception engine (optional)

Phase 5: Production (Weeks 17-20)
├─ Terminal UI
├─ Export formats
├─ Testing
└─ v1.0 release
```

---

## Getting Started

### Prerequisites

- Go 1.21+
- libpcap development libraries
- Root/CAP_NET_RAW for packet capture

### Installation (Future)

```bash
# After implementation
curl -sSL https://nlsn-monitor.dev/install.sh | bash

# Or
brew install nlsn-monitor

# Or
go install github.com/YOUR_USERNAME/nlsn-monitor@latest
```

### Usage (Future)

```bash
# Start monitoring
sudo nlsn-monitor start --interface en0

# Query threats
nlsn-monitor threats list --severity high

# Verify URL
nlsn-monitor verify https://bank.com

# Export data
nlsn-monitor threats export --format json > threats.json
```

---

## Document Status

| Document | Status | Last Updated |
|----------|--------|--------------|
| ARCHITECTURE-CLI.md | ✅ Complete | 2025-11-10 |
| IMPLEMENTATION-PLAN.md | ✅ Complete | 2025-11-10 |
| PHASE1-BASICS.md | ✅ Complete | 2025-11-10 |
| TECHNICAL-DECISIONS.md | ✅ Complete | 2025-11-10 |
| MIGRATION-NOTES.md | ✅ Complete | 2025-11-10 |

---

## Related Documentation

### Original Architecture (Archive)

The original microservices design documentation is located in:
- `docs/ARCHITECTURE.md` - Original architecture
- `docs/PHASES.md` - Original 24-week plan
- `docs/TECHNICAL_SPECS.md` - Detailed specifications

**Note:** These documents describe the microservices approach and are kept for reference and algorithm specifications.

### Current Implementation

The existing (partially implemented) code is in:
- `core/` - Go monitor (basic capture only)
- `engine/` - Python engine (skeleton only)
- `verification-container/` - Fully functional verification service
- `docker-compose.yml` - Container orchestration

**Status:** ~15% complete, being superseded by CLI approach

---

## Contributing

### Documentation Updates

- Keep docs in sync with implementation
- Update status as milestones are completed
- Add examples and diagrams as needed
- Clarify ambiguities based on feedback

### Code Implementation

Follow the plan in:
1. IMPLEMENTATION-PLAN.md (overall roadmap)
2. PHASE1-BASICS.md (Week 1-4 details)
3. Create similar detailed guides for Phases 2-5 as needed

---

## Questions?

For questions about:
- **Architecture design** → See ARCHITECTURE-CLI.md
- **Why this approach** → See TECHNICAL-DECISIONS.md
- **Implementation tasks** → See IMPLEMENTATION-PLAN.md
- **Getting started** → See PHASE1-BASICS.md
- **Migration strategy** → See MIGRATION-NOTES.md

---

## Version History

- **2025-11-10** - Initial CLI architecture documentation created
  - Complete redesign from microservices to CLI
  - 5 comprehensive documents
  - 20-week implementation plan
  - Ready to begin Phase 1

---

**Status:** Documentation complete, ready for implementation phase! 🚀
