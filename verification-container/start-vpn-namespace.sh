#!/bin/bash
# Helper script to start VPN in a specific namespace
# Called by setup-namespaces.sh

location=$1
namespace_id=$2

echo "Starting OpenVPN for location: $location (namespace: $namespace_id)"

# VPN config path
vpn_config="/etc/openvpn/${location}.ovpn"

if [ ! -f "$vpn_config" ]; then
    echo "ERROR: VPN config not found: $vpn_config"
    exit 1
fi

# Start OpenVPN
openvpn \
    --config "$vpn_config" \
    --auth-user-pass /etc/openvpn/credentials.txt \
    --daemon \
    --writepid "/var/run/openvpn/ns-${namespace_id}.pid" \
    --log "/var/log/openvpn/ns-${namespace_id}.log"

# Wait for connection
echo "Waiting for VPN connection to establish..."
sleep 10

# Verify connection
if curl -s --max-time 5 https://ipinfo.io/ip > /dev/null 2>&1; then
    external_ip=$(curl -s --max-time 5 https://ipinfo.io/ip)
    echo "VPN connected. External IP: $external_ip"
    exit 0
else
    echo "ERROR: VPN connection failed"
    exit 1
fi
