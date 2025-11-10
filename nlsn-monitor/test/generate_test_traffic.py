#!/usr/bin/env python3
"""
generate_test_traffic.py - Generate realistic DNS traffic for testing nlsn-monitor

Requires: pip install scapy
Usage: sudo python3 generate_test_traffic.py
"""

import sys
import time
import random
from datetime import datetime

try:
    from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, send, sr1
except ImportError:
    print("Error: scapy not installed")
    print("Install with: pip3 install scapy")
    sys.exit(1)


class DNSTrafficGenerator:
    """Generate various types of DNS traffic patterns"""

    def __init__(self, target_dns="8.8.8.8", source_ip=None):
        self.target_dns = target_dns
        self.source_ip = source_ip or self._get_local_ip()

    def _get_local_ip(self):
        """Get local IP address"""
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        except Exception:
            ip = "127.0.0.1"
        finally:
            s.close()
        return ip

    def log(self, message, level="INFO"):
        """Print log message with timestamp"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        colors = {
            "INFO": "\033[0;36m",  # Cyan
            "WARN": "\033[1;33m",  # Yellow
            "ERROR": "\033[0;31m", # Red
            "SUCCESS": "\033[0;32m" # Green
        }
        reset = "\033[0m"
        color = colors.get(level, "")
        print(f"[{timestamp}] {color}{level:7}{reset} {message}")

    def normal_query(self, domain):
        """Send normal DNS query"""
        self.log(f"Normal query: {domain}")
        pkt = IP(dst=self.target_dns) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain))
        response = sr1(pkt, timeout=2, verbose=0)
        if response:
            self.log(f"Response: {response[DNS].an.rdata if response.haslayer(DNS) else 'No answer'}", "SUCCESS")
        return response

    def generate_normal_traffic(self, count=10):
        """Generate normal DNS traffic"""
        self.log(f"Generating {count} normal DNS queries", "INFO")

        domains = [
            "google.com",
            "github.com",
            "stackoverflow.com",
            "reddit.com",
            "wikipedia.org",
            "youtube.com",
            "twitter.com",
            "amazon.com",
            "cloudflare.com",
            "microsoft.com"
        ]

        for i in range(count):
            domain = random.choice(domains)
            self.normal_query(domain)
            time.sleep(random.uniform(0.5, 2.0))

    def simulate_low_ttl_response(self, domain, fake_ip, ttl=5):
        """
        Simulate DNS response with suspiciously low TTL
        NOTE: This sends fake DNS responses for testing
        """
        self.log(f"Simulating low TTL response: {domain} -> {fake_ip} (TTL: {ttl}s)", "WARN")

        # This would require spoofing DNS responses
        # For testing, we can't easily create this without running our own DNS server
        # Instead, document the pattern
        self.log("Low TTL simulation requires running local DNS server (dnsmasq)", "WARN")
        self.log("See simulate_dns_hijack.sh scenario 3 for setup", "INFO")

    def simulate_multiple_a_records(self, domain):
        """Query domain that returns many A records"""
        self.log(f"Querying domain with multiple A records: {domain}")

        # Use well-known domains that have multiple A records
        multi_ip_domains = [
            "google.com",      # Usually has 1-2, but can vary
            "facebook.com",    # Often has 2-3
            "netflix.com",     # CDN, multiple IPs
        ]

        for d in multi_ip_domains:
            self.log(f"Checking: {d}")
            response = self.normal_query(d)
            if response and response.haslayer(DNS):
                an_count = response[DNS].ancount
                self.log(f"  Answer count: {an_count}")

    def test_baseline_learning(self):
        """Test baseline learning by querying same domain multiple times"""
        self.log("Testing baseline learning", "INFO")
        domain = "example.com"

        for i in range(5):
            self.log(f"Query {i+1}/5: {domain}")
            self.normal_query(domain)
            time.sleep(1)

        self.log("Baseline should be established for example.com", "SUCCESS")

    def generate_stress_test(self, duration=10):
        """Generate high-volume DNS traffic for performance testing"""
        self.log(f"Stress test: {duration} seconds of rapid queries", "WARN")

        domains = ["test%d.example.com" % i for i in range(100)]
        end_time = time.time() + duration
        count = 0

        start = time.time()
        while time.time() < end_time:
            domain = random.choice(domains)
            pkt = IP(dst=self.target_dns) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain))
            send(pkt, verbose=0)
            count += 1

        elapsed = time.time() - start
        rate = count / elapsed
        self.log(f"Sent {count} queries in {elapsed:.1f}s ({rate:.0f} qps)", "SUCCESS")

    def display_menu(self):
        """Display interactive menu"""
        print("\n" + "="*60)
        print("🧪 DNS Traffic Generator for nlsn-monitor Testing")
        print("="*60)
        print("\nTest Scenarios:")
        print("  1. Normal Traffic - 10 legitimate DNS queries")
        print("  2. Baseline Learning - Query same domain 5 times")
        print("  3. Multiple A Records - Query domains with many IPs")
        print("  4. Stress Test - High volume queries (10s)")
        print("  5. Mixed Traffic - Combination of scenarios")
        print("  6. Exit")
        print()

    def run_interactive(self):
        """Run interactive mode"""
        while True:
            self.display_menu()
            choice = input("Select scenario (1-6): ").strip()

            if choice == "1":
                print()
                self.generate_normal_traffic(10)
            elif choice == "2":
                print()
                self.test_baseline_learning()
            elif choice == "3":
                print()
                self.simulate_multiple_a_records("google.com")
            elif choice == "4":
                print()
                confirm = input("This will generate high traffic. Continue? (y/n): ")
                if confirm.lower() == 'y':
                    self.generate_stress_test(10)
            elif choice == "5":
                print()
                self.log("Running mixed traffic scenario", "INFO")
                self.generate_normal_traffic(5)
                time.sleep(2)
                self.test_baseline_learning()
                time.sleep(2)
                self.simulate_multiple_a_records("google.com")
                self.log("Mixed traffic complete", "SUCCESS")
            elif choice == "6":
                print("\n👋 Goodbye!\n")
                break
            else:
                print("\n❌ Invalid choice\n")

            input("\nPress Enter to continue...")


def main():
    import os
    if os.geteuid() != 0:
        print("⚠️  Warning: This script may require root privileges for packet injection")
        print("   If you see permission errors, run with: sudo python3 generate_test_traffic.py")
        print()

    print("🔍 nlsn-monitor DNS Traffic Generator")
    print("="*60)
    print()

    # Check if nlsn-monitor is likely running
    print("💡 Make sure nlsn-monitor is running in another terminal:")
    print("   sudo ./nlsn-monitor start --interface en0 -v")
    print()

    # Get DNS server
    dns = input("DNS server to query [8.8.8.8]: ").strip() or "8.8.8.8"

    generator = DNSTrafficGenerator(target_dns=dns)

    try:
        generator.run_interactive()
    except KeyboardInterrupt:
        print("\n\n🛑 Interrupted by user\n")
        sys.exit(0)


if __name__ == "__main__":
    main()
