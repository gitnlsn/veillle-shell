# VPN Orchestrator Component Specification

**Version:** 1.0
**Last Updated:** 2025-11-10
**Component:** Verification Container / VPN Management

---

## Overview

The VPN Orchestrator manages multiple VPN connections in isolated network namespaces, providing 40 independent verification paths.

## Responsibilities

1. **VPN Connection Management**: Establish and maintain 10 VPN connections
2. **Network Namespace Isolation**: Create isolated network environments for each VPN
3. **Tor Integration**: Run Tor in each namespace for additional routing layer
4. **Proxy Management**: Manage HTTP/SOCKS proxies in each namespace
5. **Path Health Monitoring**: Track status and performance of all verification paths

## Architecture

```
┌─────────────────────────────────────────────────────┐
│ Host Network Namespace                              │
│                                                     │
│  ┌─────────────────┐  ┌─────────────────┐         │
│  │ vpn-ns-0        │  │ vpn-ns-1        │  ...    │
│  │                 │  │                 │         │
│  │ ┌─────────┐     │  │ ┌─────────┐     │         │
│  │ │ OpenVPN │     │  │ │ OpenVPN │     │         │
│  │ │ (tun0)  │     │  │ │ (tun0)  │     │         │
│  │ └─────────┘     │  │ └─────────┘     │         │
│  │                 │  │                 │         │
│  │ ┌─────┐ ┌─────┐│  │ ┌─────┐ ┌─────┐│         │
│  │ │ Tor │ │Proxy││  │ │ Tor │ │Proxy││         │
│  │ │:9050│ │:8080││  │ │:9051│ │:8081││         │
│  │ └─────┘ └─────┘│  │ └─────┘ └─────┘│         │
│  └─────────────────┘  └─────────────────┘         │
└─────────────────────────────────────────────────────┘
```

## Implementation

**File:** `verification-container/setup-namespaces.sh`

### VPN Setup Script

```bash
#!/bin/bash

VPN_LOCATIONS=(
    "us-nyc" "us-lax" "uk-lon" "de-fra" "jp-tok"
    "au-syd" "ca-tor" "nl-ams" "sg-sin" "br-sao"
)

for i in {0..9}; do
    NAMESPACE="vpn-ns-$i"
    VPN_CONFIG="/etc/openvpn/${VPN_LOCATIONS[$i]}.ovpn"

    # Create network namespace
    ip netns add $NAMESPACE

    # Create veth pair
    ip link add veth-host-$i type veth peer name veth-ns-$i

    # Move one end to namespace
    ip link set veth-ns-$i netns $NAMESPACE

    # Configure interfaces
    ip addr add 10.200.$i.1/24 dev veth-host-$i
    ip link set veth-host-$i up

    ip netns exec $NAMESPACE ip addr add 10.200.$i.2/24 dev veth-ns-$i
    ip netns exec $NAMESPACE ip link set veth-ns-$i up
    ip netns exec $NAMESPACE ip link set lo up

    # Add default route
    ip netns exec $NAMESPACE ip route add default via 10.200.$i.1

    # Start OpenVPN in namespace
    ip netns exec $NAMESPACE openvpn \
        --config $VPN_CONFIG \
        --auth-user-pass /etc/openvpn/credentials.txt \
        --log /var/log/openvpn/ns-$i.log \
        --daemon

    # Start Tor in namespace (port 9050+i)
    ip netns exec $NAMESPACE tor -f /etc/tor/torrc-$i &

    # Start Privoxy in namespace (port 8080+i)
    ip netns exec $NAMESPACE privoxy /etc/privoxy/config-$i &

    echo "Initialized $NAMESPACE with VPN location ${VPN_LOCATIONS[$i]}"
done

echo "Waiting for VPN connections to establish..."
sleep 30

# Verify connections
for i in {0..9}; do
    NAMESPACE="vpn-ns-$i"
    IP=$(ip netns exec $NAMESPACE curl -s --max-time 5 https://ipinfo.io/ip)
    echo "VPN $i ($NAMESPACE): IP = $IP"
done
```

### Path Orchestrator

**File:** `verification-container/path-orchestrator.py`

```python
class PathOrchestrator:
    def __init__(self):
        self.namespaces = [f"vpn-ns-{i}" for i in range(10)]
        self.paths = self._generate_all_paths()
        self.path_stats = {}

    def _generate_all_paths(self) -> List[VerificationPath]:
        """Generate 40 verification paths (10 VPNs × 4 methods)"""
        paths = []
        for ns_id, namespace in enumerate(self.namespaces):
            # Direct VPN path
            paths.append(VerificationPath(
                id=f"vpn-{ns_id}-direct",
                namespace=namespace,
                method="direct",
                proxy=None
            ))

            # Tor path
            paths.append(VerificationPath(
                id=f"vpn-{ns_id}-tor",
                namespace=namespace,
                method="tor",
                proxy=f"socks5://127.0.0.1:{9050 + ns_id}"
            ))

            # HTTP proxy path
            paths.append(VerificationPath(
                id=f"vpn-{ns_id}-proxy",
                namespace=namespace,
                method="http_proxy",
                proxy=f"http://127.0.0.1:{8080 + ns_id}"
            ))

            # Tor + proxy path
            paths.append(VerificationPath(
                id=f"vpn-{ns_id}-tor+proxy",
                namespace=namespace,
                method="tor+proxy",
                proxy=f"socks5://127.0.0.1:{9050 + ns_id}"
            ))

        return paths

    async def verify_through_path(self, url: str, path: VerificationPath,
                                  timeout: int = 15) -> VerificationResult:
        """Execute request through specific verification path"""
        start_time = time.time()

        try:
            # Execute curl in network namespace
            cmd = [
                "ip", "netns", "exec", path.namespace,
                "curl", "-s", "-L",
                "--max-time", str(timeout),
                "--write-out", "%{http_code}",
            ]

            if path.proxy:
                cmd.extend(["--proxy", path.proxy])

            cmd.append(url)

            # Execute command
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                latency = time.time() - start_time
                content = stdout.decode()
                content_hash = hashlib.sha256(content.encode()).hexdigest()

                return VerificationResult(
                    path_id=path.id,
                    status="success",
                    status_code=200,
                    content_hash=content_hash,
                    latency_ms=int(latency * 1000)
                )
            else:
                return VerificationResult(
                    path_id=path.id,
                    status="failed",
                    error=stderr.decode()
                )

        except asyncio.TimeoutError:
            return VerificationResult(
                path_id=path.id,
                status="timeout",
                error=f"Request exceeded {timeout}s timeout"
            )
```

## Performance Requirements

- **VPN Connection Time**: < 30 seconds per VPN
- **Path Availability**: > 90% (36/40 paths available)
- **Verification Latency**: < 10 seconds for 10-path verification
- **Path Success Rate**: > 95% per path
- **Memory Usage**: < 2GB total (all namespaces + VPNs)

## Configuration

```yaml
verification:
  vpn:
    provider: surfshark
    locations:
      - us-nyc
      - us-lax
      - uk-lon
      - de-fra
      - jp-tok
      - au-syd
      - ca-tor
      - nl-ams
      - sg-sin
      - br-sao

    connection_timeout: 30
    reconnect_on_failure: true
    killswitch: true

  tor:
    control_port_base: 9050
    socks_port_base: 9050
    circuit_lifetime: 600  # 10 minutes

  proxy:
    http_port_base: 8080
    enable_caching: false
```

## Health Monitoring

```python
class PathHealthMonitor:
    async def check_path_health(self, path: VerificationPath) -> PathHealth:
        """Check health of verification path"""
        # Test connectivity
        test_url = "https://ipinfo.io/ip"

        result = await self.orchestrator.verify_through_path(test_url, path, timeout=5)

        if result.status == "success":
            return PathHealth(
                path_id=path.id,
                status="available",
                last_success=datetime.now(),
                latency_ms=result.latency_ms
            )
        else:
            return PathHealth(
                path_id=path.id,
                status="unavailable",
                error=result.error
            )

    async def monitor_all_paths(self):
        """Continuously monitor all paths"""
        while True:
            tasks = [self.check_path_health(path) for path in self.paths]
            health_results = await asyncio.gather(*tasks)

            # Update path statistics
            for health in health_results:
                self.path_stats[health.path_id] = health

            # Log availability
            available_count = sum(1 for h in health_results if h.status == "available")
            logger.info(f"Path availability: {available_count}/40")

            await asyncio.sleep(60)  # Check every minute
```

## Testing

See `verification-container/tests/` for:
- VPN connection tests
- Network namespace isolation tests
- Path selection algorithm tests
- Multi-path verification tests

## Dependencies

- **System**: OpenVPN, Tor, Privoxy
- **Python**: asyncio, aiohttp
- **Linux**: Network namespaces, iproute2

---

**Document Version:** 1.0
**Total Word Count:** ~800 words
