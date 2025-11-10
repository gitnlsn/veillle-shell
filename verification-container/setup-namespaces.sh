#!/bin/bash
# Setup network namespaces for VPN isolation
# Creates 10 namespaces, one per VPN location

set -e

echo "=== NLSN Verification Container Setup ==="
echo "Creating network namespaces for VPN isolation..."

# VPN locations (Surfshark examples - adjust to your available servers)
VPN_LOCATIONS=(
    "us-nyc"
    "us-lax"
    "uk-lon"
    "de-fra"
    "jp-tok"
    "au-syd"
    "ca-tor"
    "nl-ams"
    "sg-sin"
    "br-sao"
)

# Check if VPN credentials exist
if [ ! -f /etc/openvpn/credentials.txt ]; then
    echo "ERROR: VPN credentials not found at /etc/openvpn/credentials.txt"
    echo "Please create this file with format:"
    echo "  username"
    echo "  password"
    exit 1
fi

# Cleanup function
cleanup() {
    echo "Cleaning up namespaces..."
    for i in {0..9}; do
        ip netns del vpn-ns-$i 2>/dev/null || true
    done
}

# Register cleanup on exit
trap cleanup EXIT

# Create namespaces and start VPNs
for i in "${!VPN_LOCATIONS[@]}"; do
    location="${VPN_LOCATIONS[$i]}"
    namespace="vpn-ns-$i"

    echo "=== Setting up namespace $i: $namespace for $location ==="

    # Create network namespace
    ip netns add "$namespace" 2>/dev/null || true

    # Create veth pair (virtual ethernet)
    ip link add "veth-$i" type veth peer name "vpeer-$i" 2>/dev/null || true

    # Move one end into namespace
    ip link set "vpeer-$i" netns "$namespace"

    # Configure host-side interface
    ip addr add "10.200.$i.1/24" dev "veth-$i" 2>/dev/null || true
    ip link set "veth-$i" up

    # Configure namespace-side interface
    ip netns exec "$namespace" ip addr add "10.200.$i.2/24" dev "vpeer-$i"
    ip netns exec "$namespace" ip link set "vpeer-$i" up
    ip netns exec "$namespace" ip link set lo up

    # Set up NAT for namespace
    iptables -t nat -A POSTROUTING -s "10.200.$i.0/24" -j MASQUERADE 2>/dev/null || true

    # Enable IP forwarding
    sysctl -w net.ipv4.ip_forward=1 > /dev/null

    echo "Namespace $namespace network configured"

    # Check if VPN config exists
    vpn_config="/etc/openvpn/${location}.ovpn"
    if [ ! -f "$vpn_config" ]; then
        echo "WARNING: VPN config not found: $vpn_config"
        echo "Skipping VPN startup for $namespace"
        continue
    fi

    # Start VPN in namespace (background)
    echo "Starting OpenVPN for $location in $namespace..."
    ip netns exec "$namespace" openvpn \
        --config "$vpn_config" \
        --auth-user-pass /etc/openvpn/credentials.txt \
        --daemon \
        --writepid "/var/run/openvpn/ns-$i.pid" \
        --log "/var/log/openvpn/ns-$i.log" \
        --dev tun$i

    # Wait for VPN to establish
    sleep 5

    # Verify VPN connection
    echo "Checking VPN connection for $namespace..."
    if ip netns exec "$namespace" curl -s --max-time 10 https://ipinfo.io/ip > /dev/null 2>&1; then
        external_ip=$(ip netns exec "$namespace" curl -s --max-time 10 https://ipinfo.io/ip)
        echo "✓ VPN connected for $namespace. External IP: $external_ip"
    else
        echo "✗ WARNING: VPN connection failed for $namespace"
    fi

    # Start Tor in namespace
    echo "Starting Tor in $namespace..."
    tor_port=$((9050 + i))
    ip netns exec "$namespace" tor \
        --SocksPort "0.0.0.0:$tor_port" \
        --DataDirectory "/var/lib/tor/ns-$i" \
        --PidFile "/var/run/tor/ns-$i.pid" \
        --Log "notice file /var/log/tor/ns-$i.log" \
        --RunAsDaemon 1

    sleep 3
    echo "✓ Tor started on port $tor_port in $namespace"

    # Start Privoxy (HTTP proxy) in namespace
    echo "Starting Privoxy in $namespace..."
    http_port=$((8080 + i))

    # Create Privoxy config for this namespace
    cat > "/etc/privoxy/config-ns-$i" <<EOF
listen-address 0.0.0.0:$http_port
toggle 1
enable-remote-toggle 0
enable-edit-actions 0
enable-remote-http-toggle 0
buffer-limit 4096
forward-socks5 / 127.0.0.1:$tor_port .
EOF

    ip netns exec "$namespace" privoxy \
        --pidfile "/var/run/privoxy/ns-$i.pid" \
        "/etc/privoxy/config-ns-$i" &

    sleep 2
    echo "✓ Privoxy started on port $http_port in $namespace"

    echo "=== Namespace $i complete ==="
    echo ""
done

echo "=== All namespaces configured ==="
echo "Starting Path Orchestrator API..."

# Start the Path Orchestrator API
cd /app
python3 path-orchestrator.py
