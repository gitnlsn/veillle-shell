package detector

import (
	"net"
	"testing"
	"time"

	"github.com/nlsn-pcap-monitor/nlsn-monitor/pkg/types"
)

func TestNewDNSHijackDetector(t *testing.T) {
	config := DetectorConfig{
		MinConfidence: 50,
		Enabled:       true,
	}

	detector := NewDNSHijackDetector(config)

	if detector == nil {
		t.Fatal("NewDNSHijackDetector() returned nil")
	}

	if detector.config.MinConfidence != 50 {
		t.Errorf("MinConfidence = %v, want 50", detector.config.MinConfidence)
	}

	// Check known servers are loaded
	if len(detector.knownServers) == 0 {
		t.Error("No known DNS servers loaded")
	}

	// Verify common DNS servers are known
	if !detector.isKnownServer(net.ParseIP("8.8.8.8")) {
		t.Error("Google DNS 8.8.8.8 not in known servers")
	}
	if !detector.isKnownServer(net.ParseIP("1.1.1.1")) {
		t.Error("Cloudflare DNS 1.1.1.1 not in known servers")
	}
}

func TestIsKnownServer(t *testing.T) {
	detector := NewDNSHijackDetector(DetectorConfig{})

	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{"Google DNS 8.8.8.8", "8.8.8.8", true},
		{"Google DNS 8.8.4.4", "8.8.4.4", true},
		{"Cloudflare DNS 1.1.1.1", "1.1.1.1", true},
		{"Cloudflare DNS 1.0.0.1", "1.0.0.1", true},
		{"Quad9 DNS", "9.9.9.9", true},
		{"OpenDNS", "208.67.222.222", true},
		{"Unknown server", "192.168.1.1", false},
		{"Random IP", "10.0.0.1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			result := detector.isKnownServer(ip)
			if result != tt.expected {
				t.Errorf("isKnownServer(%s) = %v, want %v", tt.ip, result, tt.expected)
			}
		})
	}

	// Test nil IP
	if detector.isKnownServer(nil) {
		t.Error("isKnownServer(nil) should return false")
	}
}

func TestBaselineLearning(t *testing.T) {
	detector := NewDNSHijackDetector(DetectorConfig{})

	domain := "example.com"
	ip1 := net.ParseIP("93.184.216.34")
	ip2 := net.ParseIP("93.184.216.35")

	// Initially no baseline
	if detector.hasBaseline(domain) {
		t.Error("Should not have baseline for new domain")
	}

	// Add first IP
	detector.updateBaseline(domain, ip1)

	if !detector.hasBaseline(domain) {
		t.Error("Should have baseline after update")
	}

	if !detector.matchesBaseline(domain, ip1) {
		t.Error("IP1 should match baseline")
	}

	if detector.matchesBaseline(domain, ip2) {
		t.Error("IP2 should not match baseline yet")
	}

	// Add second IP
	detector.updateBaseline(domain, ip2)

	if !detector.matchesBaseline(domain, ip2) {
		t.Error("IP2 should match baseline after update")
	}

	// Verify both IPs are in baseline
	ips := detector.getBaselineIPs(domain)
	if len(ips) != 2 {
		t.Errorf("Expected 2 baseline IPs, got %d", len(ips))
	}
}

func TestBaselineLimit(t *testing.T) {
	detector := NewDNSHijackDetector(DetectorConfig{})

	domain := "cdn.example.com"

	// Add 6 different IPs (limit is 5)
	for i := 1; i <= 6; i++ {
		ip := net.IPv4(10, 0, 0, byte(i))
		detector.updateBaseline(domain, ip)
	}

	ips := detector.getBaselineIPs(domain)
	if len(ips) > 5 {
		t.Errorf("Baseline should be limited to 5 IPs, got %d", len(ips))
	}
}

func TestIsPrivateIP(t *testing.T) {
	detector := NewDNSHijackDetector(DetectorConfig{})

	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		// Private ranges
		{"10.x.x.x range", "10.0.0.1", true},
		{"10.x.x.x range 2", "10.255.255.254", true},
		{"172.16-31 range start", "172.16.0.1", true},
		{"172.16-31 range mid", "172.20.0.1", true},
		{"172.16-31 range end", "172.31.255.254", true},
		{"192.168.x.x range", "192.168.1.1", true},
		{"192.168.x.x range 2", "192.168.255.254", true},
		{"Localhost", "127.0.0.1", true},
		{"Localhost 2", "127.255.255.254", true},

		// Public IPs
		{"Google DNS", "8.8.8.8", false},
		{"Cloudflare", "1.1.1.1", false},
		{"Example.com", "93.184.216.34", false},
		{"172.15.x.x (public)", "172.15.0.1", false},
		{"172.32.x.x (public)", "172.32.0.1", false},
		{"Random public", "45.67.89.123", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			result := detector.isPrivateIP(ip)
			if result != tt.expected {
				t.Errorf("isPrivateIP(%s) = %v, want %v", tt.ip, result, tt.expected)
			}
		})
	}

	// Test nil IP
	if detector.isPrivateIP(nil) {
		t.Error("isPrivateIP(nil) should return false")
	}
}

func TestIsPublicDomain(t *testing.T) {
	detector := NewDNSHijackDetector(DetectorConfig{})

	tests := []struct {
		domain   string
		expected bool
	}{
		// Public domains
		{"example.com", true},
		{"google.com", true},
		{"github.io", true},
		{"wikipedia.org", true},
		{"mit.edu", true},
		{"whitehouse.gov", true},
		{"example.co", true},
		{"api.example.net", true},

		// Local/private domains
		{"localhost", false},
		{"router.local", false},
		{"server.lan", false},
		{"mydevice.home", false},
		{"internal", false},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			result := detector.isPublicDomain(tt.domain)
			if result != tt.expected {
				t.Errorf("isPublicDomain(%s) = %v, want %v", tt.domain, result, tt.expected)
			}
		})
	}
}

func TestDetect_NoThreat(t *testing.T) {
	detector := NewDNSHijackDetector(DetectorConfig{
		MinConfidence: 50,
		Enabled:       true,
	})

	// Valid DNS response from known server
	pkt := &types.DNSPacket{
		TransactionID: 0x1234,
		Timestamp:     time.Now(),
		IsResponse:    true,
		QueryDomain:   "google.com",
		QueryType:     types.DNSTypeA,
		ResponseCode:  types.DNSRCodeNoError,
		ResponseIPs:   []net.IP{net.ParseIP("142.250.185.46")},
		TTL:           300,
		ServerIP:      net.ParseIP("8.8.8.8"), // Known DNS server
		ClientIP:      net.ParseIP("192.168.1.100"),
	}

	threat, err := detector.Detect(pkt)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}

	if threat != nil {
		t.Errorf("Expected no threat for valid response, got threat with confidence %d", threat.Confidence)
	}
}

func TestDetect_UnknownServer(t *testing.T) {
	detector := NewDNSHijackDetector(DetectorConfig{
		MinConfidence: 50,
		Enabled:       true,
	})

	// Response from unknown DNS server (50 points)
	pkt := &types.DNSPacket{
		TransactionID: 0x1234,
		Timestamp:     time.Now(),
		IsResponse:    true,
		QueryDomain:   "google.com",
		QueryType:     types.DNSTypeA,
		ResponseCode:  types.DNSRCodeNoError,
		ResponseIPs:   []net.IP{net.ParseIP("142.250.185.46")},
		TTL:           300,
		ServerIP:      net.ParseIP("192.168.1.1"), // Unknown server
		ClientIP:      net.ParseIP("192.168.1.100"),
	}

	threat, err := detector.Detect(pkt)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}

	if threat == nil {
		t.Fatal("Expected threat for unknown DNS server")
	}

	if threat.Confidence < 50 {
		t.Errorf("Confidence = %d, should be >= 50", threat.Confidence)
	}

	if threat.Type != types.ThreatTypeDNSHijack {
		t.Errorf("Type = %s, want %s", threat.Type, types.ThreatTypeDNSHijack)
	}

	if _, ok := threat.Details["unexpected_server"]; !ok {
		t.Error("Expected 'unexpected_server' in threat details")
	}
}

func TestDetect_LowTTL(t *testing.T) {
	detector := NewDNSHijackDetector(DetectorConfig{
		MinConfidence: 30, // Lower threshold to catch low TTL alone
		Enabled:       true,
	})

	// Response with low TTL (30 points)
	pkt := &types.DNSPacket{
		TransactionID: 0x1234,
		Timestamp:     time.Now(),
		IsResponse:    true,
		QueryDomain:   "suspicious.com",
		QueryType:     types.DNSTypeA,
		ResponseCode:  types.DNSRCodeNoError,
		ResponseIPs:   []net.IP{net.ParseIP("45.67.89.123")},
		TTL:           10, // Very low TTL
		ServerIP:      net.ParseIP("8.8.8.8"),
		ClientIP:      net.ParseIP("192.168.1.100"),
	}

	threat, err := detector.Detect(pkt)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}

	if threat == nil {
		t.Fatal("Expected threat for low TTL")
	}

	if _, ok := threat.Details["low_ttl"]; !ok {
		t.Error("Expected 'low_ttl' in threat details")
	}
}

func TestDetect_PrivateIPForPublicDomain(t *testing.T) {
	detector := NewDNSHijackDetector(DetectorConfig{
		MinConfidence: 40,
		Enabled:       true,
	})

	// Public domain resolving to private IP (40 points)
	pkt := &types.DNSPacket{
		TransactionID: 0x1234,
		Timestamp:     time.Now(),
		IsResponse:    true,
		QueryDomain:   "bank.com", // Public domain
		QueryType:     types.DNSTypeA,
		ResponseCode:  types.DNSRCodeNoError,
		ResponseIPs:   []net.IP{net.ParseIP("192.168.1.53")}, // Private IP
		TTL:           300,
		ServerIP:      net.ParseIP("8.8.8.8"),
		ClientIP:      net.ParseIP("192.168.1.100"),
	}

	threat, err := detector.Detect(pkt)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}

	if threat == nil {
		t.Fatal("Expected threat for private IP on public domain")
	}

	if _, ok := threat.Details["private_ip_for_public_domain"]; !ok {
		t.Error("Expected 'private_ip_for_public_domain' in threat details")
	}
}

func TestDetect_IPMismatch(t *testing.T) {
	detector := NewDNSHijackDetector(DetectorConfig{
		MinConfidence: 50,
		Enabled:       true,
	})

	domain := "trusted.com"
	legitIP := net.ParseIP("93.184.216.34")
	fakeIP := net.ParseIP("10.0.0.53")

	// First, establish baseline with legit IP
	pkt1 := &types.DNSPacket{
		TransactionID: 0x1234,
		Timestamp:     time.Now(),
		IsResponse:    true,
		QueryDomain:   domain,
		QueryType:     types.DNSTypeA,
		ResponseCode:  types.DNSRCodeNoError,
		ResponseIPs:   []net.IP{legitIP},
		TTL:           300,
		ServerIP:      net.ParseIP("8.8.8.8"),
		ClientIP:      net.ParseIP("192.168.1.100"),
	}

	threat1, _ := detector.Detect(pkt1)
	if threat1 != nil {
		t.Error("First response should not trigger threat (baseline learning)")
	}

	// Now respond with different IP (50 points for mismatch)
	pkt2 := &types.DNSPacket{
		TransactionID: 0x1235,
		Timestamp:     time.Now(),
		IsResponse:    true,
		QueryDomain:   domain,
		QueryType:     types.DNSTypeA,
		ResponseCode:  types.DNSRCodeNoError,
		ResponseIPs:   []net.IP{fakeIP},
		TTL:           300,
		ServerIP:      net.ParseIP("8.8.8.8"),
		ClientIP:      net.ParseIP("192.168.1.100"),
	}

	threat2, err := detector.Detect(pkt2)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}

	if threat2 == nil {
		t.Fatal("Expected threat for IP mismatch")
	}

	if _, ok := threat2.Details["unexpected_ip"]; !ok {
		t.Error("Expected 'unexpected_ip' in threat details")
	}

	if _, ok := threat2.Details["expected_ips"]; !ok {
		t.Error("Expected 'expected_ips' in threat details")
	}
}

func TestDetect_MultipleIndicators(t *testing.T) {
	detector := NewDNSHijackDetector(DetectorConfig{
		MinConfidence: 50,
		Enabled:       true,
	})

	// Multiple red flags:
	// - Unknown server (50)
	// - Private IP for public domain (40)
	// - Low TTL (30)
	// Total: 120 points (critical severity)
	pkt := &types.DNSPacket{
		TransactionID: 0x1234,
		Timestamp:     time.Now(),
		IsResponse:    true,
		QueryDomain:   "paypal.com", // Public domain
		QueryType:     types.DNSTypeA,
		ResponseCode:  types.DNSRCodeNoError,
		ResponseIPs:   []net.IP{net.ParseIP("10.0.0.53")}, // Private IP
		TTL:           5,                                   // Very low TTL
		ServerIP:      net.ParseIP("192.168.1.1"),         // Unknown server
		ClientIP:      net.ParseIP("192.168.1.100"),
	}

	threat, err := detector.Detect(pkt)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}

	if threat == nil {
		t.Fatal("Expected threat for multiple indicators")
	}

	if threat.Confidence < 100 {
		t.Errorf("Confidence = %d, expected >= 100 for multiple indicators", threat.Confidence)
	}

	if threat.Severity != types.SeverityCritical {
		t.Errorf("Severity = %s, want %s", threat.Severity, types.SeverityCritical)
	}

	// Check all indicators are in details
	if _, ok := threat.Details["unexpected_server"]; !ok {
		t.Error("Missing 'unexpected_server' in details")
	}
	if _, ok := threat.Details["private_ip_for_public_domain"]; !ok {
		t.Error("Missing 'private_ip_for_public_domain' in details")
	}
	if _, ok := threat.Details["low_ttl"]; !ok {
		t.Error("Missing 'low_ttl' in details")
	}
}

func TestDetect_QueryIgnored(t *testing.T) {
	detector := NewDNSHijackDetector(DetectorConfig{
		MinConfidence: 50,
		Enabled:       true,
	})

	// DNS query (not response) should be ignored
	pkt := &types.DNSPacket{
		TransactionID: 0x1234,
		Timestamp:     time.Now(),
		IsQuery:       true,
		IsResponse:    false,
		QueryDomain:   "google.com",
		QueryType:     types.DNSTypeA,
		ServerIP:      net.ParseIP("8.8.8.8"),
		ClientIP:      net.ParseIP("192.168.1.100"),
	}

	threat, err := detector.Detect(pkt)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}

	if threat != nil {
		t.Error("Queries should not trigger threats")
	}
}

func TestDetect_ErrorResponseIgnored(t *testing.T) {
	detector := NewDNSHijackDetector(DetectorConfig{
		MinConfidence: 50,
		Enabled:       true,
	})

	// NXDOMAIN response should be ignored
	pkt := &types.DNSPacket{
		TransactionID: 0x1234,
		Timestamp:     time.Now(),
		IsResponse:    true,
		QueryDomain:   "notexist.com",
		QueryType:     types.DNSTypeA,
		ResponseCode:  types.DNSRCodeNXDomain,
		ServerIP:      net.ParseIP("8.8.8.8"),
		ClientIP:      net.ParseIP("192.168.1.100"),
	}

	threat, err := detector.Detect(pkt)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}

	if threat != nil {
		t.Error("Error responses should not trigger threats")
	}
}

func TestGetStats(t *testing.T) {
	detector := NewDNSHijackDetector(DetectorConfig{
		MinConfidence: 50,
		Enabled:       true,
	})

	// Process some packets
	pkt1 := &types.DNSPacket{
		TransactionID: 0x1234,
		Timestamp:     time.Now(),
		IsResponse:    true,
		QueryDomain:   "google.com",
		QueryType:     types.DNSTypeA,
		ResponseCode:  types.DNSRCodeNoError,
		ResponseIPs:   []net.IP{net.ParseIP("142.250.185.46")},
		TTL:           300,
		ServerIP:      net.ParseIP("8.8.8.8"),
		ClientIP:      net.ParseIP("192.168.1.100"),
	}

	detector.Detect(pkt1)
	detector.Detect(pkt1) // Process twice

	stats := detector.GetStats()

	if queries, ok := stats["queries_processed"].(uint64); !ok || queries != 2 {
		t.Errorf("queries_processed = %v, want 2", stats["queries_processed"])
	}

	if servers, ok := stats["known_servers"].(int); !ok || servers == 0 {
		t.Error("known_servers should be > 0")
	}
}
