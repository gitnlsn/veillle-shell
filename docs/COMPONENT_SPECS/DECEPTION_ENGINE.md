# Deception Engine Component Specification

**Version:** 1.0
**Last Updated:** 2025-11-10
**Component:** Python Engine / Deception Module

---

## Overview

The Deception Engine generates fake but realistic network traffic to deceive attackers when a MITM attack is detected.

## Responsibilities

1. **Automated Activation**: Start deception when attack confirmed
2. **Behavior Simulation**: Mimic realistic human behavior
3. **Fake Credential Generation**: Create convincing fake credentials with honeytokens
4. **Packet Forgery**: Generate fake network packets using Scapy
5. **Session Management**: Track active deception sessions

## Implementation

**File:** `engine/deception/autopilot.py`

### Data Structures

```python
class DeceptionSession:
    session_id: str
    threat_id: str
    target_domain: str
    attacker_ip: str
    behavior_profile: str
    started_at: datetime
    ended_at: Optional[datetime]
    packets_sent: int
    honeytokens: List[str]
    status: str  # 'active', 'stopped', 'error'

class BehaviorProfile:
    name: str
    typing_speed_wpm: float
    reading_speed_wpm: float
    page_load_delay: Tuple[float, float]
    interaction_patterns: List[str]
```

### Core Algorithm

```python
class DeceptionAutopilot:
    async def activate(self, threat: Threat) -> DeceptionSession:
        """Activate deception for detected attack"""
        # 1. Create session
        session = await self._create_session(threat)

        # 2. Generate honeytokens
        honeytokens = await self._generate_honeytokens(threat.target_domain)

        # 3. Start behavior simulation task
        asyncio.create_task(self._simulate_behavior(session))

        # 4. Publish activation event
        await self.publish_event('deception:started', session.to_dict())

        return session

    async def _simulate_behavior(self, session: DeceptionSession):
        """Simulate realistic user behavior"""
        profile = self._load_profile(session.behavior_profile)

        while session.status == 'active':
            # Select random action from profile
            action = profile.get_random_action()

            if action == 'page_load':
                await self._simulate_page_load(session, profile)
            elif action == 'form_submission':
                await self._simulate_form_submission(session, profile)
            elif action == 'api_request':
                await self._simulate_api_request(session, profile)

            # Wait before next action
            await asyncio.sleep(profile.get_next_action_delay())

    async def _simulate_form_submission(self, session: DeceptionSession,
                                       profile: BehaviorProfile):
        """Simulate form submission with fake credentials"""
        # Generate fake credentials
        fake_email = self.fake_cred_gen.generate_email(session.target_domain)
        fake_password = self.fake_cred_gen.generate_password('medium')

        # Simulate typing delays
        typing_intervals = profile.get_typing_intervals(len(fake_email))

        # Forge HTTP POST request
        http_packet = self.packet_forger.forge_http_request(
            method='POST',
            url=f'https://{session.target_domain}/login',
            data={'email': fake_email, 'password': fake_password},
            attacker_ip=session.attacker_ip
        )

        # Send packet
        await self._send_packet(http_packet)

        session.packets_sent += 1
```

## Performance Requirements

- **Activation Time**: < 100ms after attack confirmation
- **Packet Generation Rate**: > 100 packets/second
- **Behavior Realism Score**: > 8/10 (evaluated by security researchers)
- **Memory per Session**: < 50MB
- **Maximum Concurrent Sessions**: 10

## Configuration

```yaml
deception:
  auto_activate: true
  default_behavior_profile: average_user
  default_duration_minutes: 30
  max_concurrent_sessions: 10
  fake_credentials:
    password_strength: medium
    email_domain_variation: true
  packet_forgery:
    realistic_timing: true
    tcp_state_management: true
```

## Behavior Profiles

**Average User:**
- Typing: 40-60 WPM
- Reading: 200-300 WPM
- Page load delay: 1.5s ± 0.5s
- Actions: page load, form submission, navigation

**Banking User:**
- More deliberate (slower typing)
- Longer reading times
- Actions: login, balance check, transfer

**Developer:**
- Faster typing (60-80 WPM)
- API-heavy interactions
- Actions: API requests, git operations, documentation

## Testing

See `engine/deception/test_autopilot.py` for:
- Behavior realism tests
- Packet forgery tests
- Session management tests
- Performance benchmarks

## Dependencies

- `engine/deception/behavior_sim.py`: Behavior simulation
- `engine/deception/fake_credentials.py`: Fake credential generation
- `engine/deception/packet_forge.py`: Packet forgery with Scapy
- `engine/intelligence/honeytoken_tracker.py`: Honeytoken management

---

**Document Version:** 1.0
**Total Word Count:** ~500 words
