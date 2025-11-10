#!/bin/bash
# simulate_dns_hijack.sh - Simulate DNS hijacking attacks for testing
# WARNING: For testing purposes only! Use on your own test network.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "🧪 DNS Hijacking Attack Simulation Script"
echo "=========================================="
echo ""
echo "⚠️  WARNING: This script simulates DNS hijacking attacks."
echo "   Only use on YOUR OWN test network with proper authorization."
echo ""

# Colors
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Error: This script must be run as root (sudo)${NC}"
   exit 1
fi

# Test scenarios
echo -e "${CYAN}Available Test Scenarios:${NC}"
echo "1. Unknown DNS Server - Use local resolver (192.168.1.1)"
echo "2. IP Mismatch - Modify /etc/hosts to return wrong IP"
echo "3. Low TTL Response - Craft DNS response with TTL < 60s"
echo "4. Private IP for Public Domain - Point public domain to 10.0.0.1"
echo "5. Multiple Indicators - Combine multiple attack indicators"
echo "6. All Scenarios - Run all tests sequentially"
echo ""

read -p "Select scenario (1-6): " SCENARIO

case $SCENARIO in
    1)
        echo -e "${YELLOW}Scenario 1: Unknown DNS Server${NC}"
        echo "This will temporarily change your DNS to 192.168.1.1"
        echo "Original DNS will be restored after test."
        echo ""
        read -p "Continue? (y/n): " CONFIRM
        if [[ "$CONFIRM" != "y" ]]; then
            echo "Aborted."
            exit 0
        fi

        # Save current DNS
        ORIGINAL_DNS=$(cat /etc/resolv.conf | grep nameserver | head -1 | awk '{print $2}')
        echo "Original DNS: $ORIGINAL_DNS"

        # Set to local router (likely not a known DNS server)
        echo "nameserver 192.168.1.1" > /etc/resolv.conf
        echo -e "${GREEN}DNS changed to 192.168.1.1${NC}"
        echo "Now run nlsn-monitor and perform DNS queries."
        echo ""
        read -p "Press Enter to restore original DNS..."

        # Restore
        echo "nameserver $ORIGINAL_DNS" > /etc/resolv.conf
        echo -e "${GREEN}DNS restored to $ORIGINAL_DNS${NC}"
        ;;

    2)
        echo -e "${YELLOW}Scenario 2: IP Mismatch (Hosts File Poisoning)${NC}"
        echo "This will add fake entries to /etc/hosts"
        echo ""
        read -p "Continue? (y/n): " CONFIRM
        if [[ "$CONFIRM" != "y" ]]; then
            echo "Aborted."
            exit 0
        fi

        # Backup hosts file
        cp /etc/hosts /etc/hosts.backup

        # Add fake entries
        cat >> /etc/hosts << EOF

# DNS Hijacking Test Entries (added by simulate_dns_hijack.sh)
10.0.0.53 google.com www.google.com
10.0.0.53 github.com www.github.com
10.0.0.53 bank.example.com
EOF

        echo -e "${GREEN}Added fake DNS entries to /etc/hosts${NC}"
        echo "Domains affected: google.com, github.com, bank.example.com"
        echo "All point to: 10.0.0.53 (private IP)"
        echo ""
        echo "Now run nlsn-monitor and query these domains:"
        echo "  dig google.com"
        echo "  dig github.com"
        echo ""
        read -p "Press Enter to restore /etc/hosts..."

        # Restore
        mv /etc/hosts.backup /etc/hosts
        echo -e "${GREEN}/etc/hosts restored${NC}"
        ;;

    3)
        echo -e "${YELLOW}Scenario 3: Low TTL Response${NC}"
        echo "This requires dnsmasq or similar to craft low TTL responses."
        echo ""
        echo "Manual steps:"
        echo "1. Install dnsmasq: brew install dnsmasq"
        echo "2. Add to /usr/local/etc/dnsmasq.conf:"
        echo "   address=/test.local/192.168.1.100"
        echo "   local-ttl=5"
        echo "3. Start dnsmasq: sudo brew services start dnsmasq"
        echo "4. Set DNS to 127.0.0.1"
        echo "5. Query test.local - should have 5s TTL"
        echo ""
        echo -e "${RED}This scenario requires manual setup.${NC}"
        ;;

    4)
        echo -e "${YELLOW}Scenario 4: Private IP for Public Domain${NC}"
        echo "Similar to Scenario 2, but more targeted."
        echo ""
        read -p "Continue? (y/n): " CONFIRM
        if [[ "$CONFIRM" != "y" ]]; then
            echo "Aborted."
            exit 0
        fi

        # Backup
        cp /etc/hosts /etc/hosts.backup

        # Add entries for common banking/financial sites
        cat >> /etc/hosts << EOF

# Private IP Attack Simulation (added by simulate_dns_hijack.sh)
192.168.1.53 paypal.com www.paypal.com
192.168.1.53 chase.com www.chase.com
192.168.1.53 wellsfargo.com www.wellsfargo.com
10.0.0.100 bankofamerica.com www.bankofamerica.com
EOF

        echo -e "${GREEN}Added malicious entries to /etc/hosts${NC}"
        echo "Public domains now point to private IPs:"
        echo "  paypal.com -> 192.168.1.53"
        echo "  chase.com -> 192.168.1.53"
        echo "  bankofamerica.com -> 10.0.0.100"
        echo ""
        echo "This should trigger HIGH confidence alerts!"
        echo ""
        read -p "Press Enter to restore /etc/hosts..."

        mv /etc/hosts.backup /etc/hosts
        echo -e "${GREEN}/etc/hosts restored${NC}"
        ;;

    5)
        echo -e "${YELLOW}Scenario 5: Multiple Indicators (High Confidence)${NC}"
        echo "Combines: Unknown DNS + Private IP + hosts poisoning"
        echo ""
        read -p "Continue? (y/n): " CONFIRM
        if [[ "$CONFIRM" != "y" ]]; then
            echo "Aborted."
            exit 0
        fi

        # Save DNS
        ORIGINAL_DNS=$(cat /etc/resolv.conf | grep nameserver | head -1 | awk '{print $2}')

        # Backup hosts
        cp /etc/hosts /etc/hosts.backup

        # Change DNS to unknown server
        echo "nameserver 192.168.1.1" > /etc/resolv.conf

        # Poison hosts with private IPs
        cat >> /etc/hosts << EOF

# Multi-Indicator Attack (added by simulate_dns_hijack.sh)
10.0.0.66 google.com www.google.com
192.168.1.66 amazon.com www.amazon.com
172.16.0.66 facebook.com www.facebook.com
EOF

        echo -e "${RED}CRITICAL ATTACK SIMULATION ACTIVE${NC}"
        echo "Multiple indicators:"
        echo "  ✗ Unknown DNS server (192.168.1.1)"
        echo "  ✗ Private IPs for public domains"
        echo "  ✗ Hosts file poisoning"
        echo ""
        echo -e "${CYAN}Expected Alert Level: CRITICAL (90+ confidence)${NC}"
        echo ""
        echo "Query domains to trigger alerts:"
        echo "  dig google.com"
        echo "  dig amazon.com"
        echo ""
        read -p "Press Enter to restore system..."

        # Restore everything
        echo "nameserver $ORIGINAL_DNS" > /etc/resolv.conf
        mv /etc/hosts.backup /etc/hosts
        echo -e "${GREEN}System restored${NC}"
        ;;

    6)
        echo -e "${YELLOW}Running all scenarios...${NC}"
        echo "This will run scenarios 1, 2, 4, and 5 sequentially."
        echo ""
        read -p "Continue? (y/n): " CONFIRM
        if [[ "$CONFIRM" != "y" ]]; then
            echo "Aborted."
            exit 0
        fi

        # Run each scenario with automatic cleanup
        for i in 1 2 4 5; do
            echo ""
            echo -e "${CYAN}===== Running Scenario $i =====${NC}"
            echo ""
            bash "$0" <<< "$i
y
"
            sleep 2
        done

        echo ""
        echo -e "${GREEN}All scenarios completed!${NC}"
        ;;

    *)
        echo -e "${RED}Invalid selection${NC}"
        exit 1
        ;;
esac

echo ""
echo -e "${GREEN}Test complete!${NC}"
echo ""
echo "💡 Tips:"
echo "- Run nlsn-monitor in another terminal: sudo ./nlsn-monitor start -v"
echo "- Generate DNS queries: dig <domain>, nslookup <domain>"
echo "- Check database: sqlite3 ~/.local/share/nlsn-pcap/nlsn.db"
echo "- View threats: SELECT * FROM threats;"
