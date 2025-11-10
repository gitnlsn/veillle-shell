# Verification Container: Multi-path verification via VPNs/Tor/Proxies
# Supports 10 VPNs × 4 paths (Direct, Tor, HTTP Proxy, Tor+Proxy) = 40 paths

FROM ubuntu:22.04

# Prevent interactive prompts during build
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && apt-get install -y \
    openvpn \
    tor \
    privoxy \
    dante-server \
    iproute2 \
    iptables \
    curl \
    wget \
    python3 \
    python3-pip \
    python3-venv \
    supervisor \
    net-tools \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip3 install --no-cache-dir \
    fastapi==0.109.0 \
    uvicorn[standard]==0.27.0 \
    httpx==0.26.0 \
    aiohttp==3.9.1 \
    PySocks==1.7.1 \
    requests[socks]==2.31.0

# Create directories
RUN mkdir -p /etc/openvpn \
    /var/log/openvpn \
    /var/log/tor \
    /var/log/privoxy \
    /var/lib/tor \
    /app

# Copy scripts
COPY setup-namespaces.sh /usr/local/bin/
COPY start-vpn-namespace.sh /usr/local/bin/
COPY path-orchestrator.py /app/
COPY supervisord.conf /etc/supervisor/conf.d/

# Make scripts executable
RUN chmod +x /usr/local/bin/setup-namespaces.sh \
    /usr/local/bin/start-vpn-namespace.sh

# Expose API port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Start supervisor which manages all services
CMD ["/usr/local/bin/setup-namespaces.sh"]
