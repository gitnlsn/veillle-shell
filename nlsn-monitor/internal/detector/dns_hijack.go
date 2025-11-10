package detector

import (
	"fmt"
	"net"
	"sync"

	"github.com/google/uuid"
	"github.com/nlsn-pcap-monitor/nlsn-monitor/pkg/types"
	"github.com/rs/zerolog/log"
)

// DNSHijackDetector detects DNS hijacking attacks
type DNSHijackDetector struct {
	config DetectorConfig

	// Baseline tracking
	knownServers   map[string]bool    // Known DNS servers
	domainBaseline map[string][]net.IP // Expected IPs for domains
	mu             sync.RWMutex

	// Statistics
	queriesProcessed uint64
	threatsDetected  uint64
}

// NewDNSHijackDetector creates a new DNS hijack detector
func NewDNSHijackDetector(config DetectorConfig) *DNSHijackDetector {
	d := &DNSHijackDetector{
		config:         config,
		knownServers:   make(map[string]bool),
		domainBaseline: make(map[string][]net.IP),
	}

	// Add common DNS servers
	d.addKnownServers([]string{
		"8.8.8.8",         // Google DNS
		"8.8.4.4",         // Google DNS
		"1.1.1.1",         // Cloudflare DNS
		"1.0.0.1",         // Cloudflare DNS
		"9.9.9.9",         // Quad9 DNS
		"208.67.222.222",  // OpenDNS
		"208.67.220.220",  // OpenDNS
		"64.6.64.6",       // Verisign DNS
		"64.6.65.6",       // Verisign DNS
	})

	log.Info().Msg("DNS hijack detector initialized")
	return d
}

// Name returns the detector name
func (d *DNSHijackDetector) Name() string {
	return "DNS Hijacking Detector"
}

// Type returns the detector type
func (d *DNSHijackDetector) Type() string {
	return types.ThreatTypeDNSHijack
}

// Detect checks a DNS packet for hijacking indicators
func (d *DNSHijackDetector) Detect(packet interface{}) (*types.Threat, error) {
	dnsPkt, ok := packet.(*types.DNSPacket)
	if !ok {
		return nil, fmt.Errorf("invalid packet type")
	}

	// Only check responses with answers
	if !dnsPkt.IsResponse || len(dnsPkt.ResponseIPs) == 0 {
		return nil, nil
	}

	// Skip error responses
	if dnsPkt.ResponseCode != types.DNSRCodeNoError {
		return nil, nil
	}

	d.queriesProcessed++

	score := 0
	details := make(map[string]interface{})

	// Check 1: Unexpected DNS server (50 points)
	if !d.isKnownServer(dnsPkt.ServerIP) {
		score += 50
		details["unexpected_server"] = dnsPkt.ServerIP.String()
		log.Debug().
			Str("server", dnsPkt.ServerIP.String()).
			Str("domain", dnsPkt.QueryDomain).
			Msg("Unexpected DNS server")
	}

	// Check 2: IP address mismatch (50 points)
	if d.hasBaseline(dnsPkt.QueryDomain) {
		if !d.matchesBaseline(dnsPkt.QueryDomain, dnsPkt.ResponseIPs[0]) {
			score += 50
			details["unexpected_ip"] = dnsPkt.ResponseIPs[0].String()
			details["expected_ips"] = d.getBaselineIPs(dnsPkt.QueryDomain)
			log.Debug().
				Str("domain", dnsPkt.QueryDomain).
				Str("got_ip", dnsPkt.ResponseIPs[0].String()).
				Msg("IP mismatch with baseline")
		}
	} else {
		// Learn baseline for this domain
		d.updateBaseline(dnsPkt.QueryDomain, dnsPkt.ResponseIPs[0])
	}

	// Check 3: Suspiciously low TTL (<60s) (30 points)
	if dnsPkt.TTL < 60 {
		score += 30
		details["low_ttl"] = dnsPkt.TTL
		log.Debug().
			Str("domain", dnsPkt.QueryDomain).
			Uint32("ttl", dnsPkt.TTL).
			Msg("Suspiciously low TTL")
	}

	// Check 4: Multiple A records (can indicate poisoning) (20 points)
	if len(dnsPkt.ResponseIPs) > 3 {
		score += 20
		details["multiple_ips"] = len(dnsPkt.ResponseIPs)
		log.Debug().
			Str("domain", dnsPkt.QueryDomain).
			Int("count", len(dnsPkt.ResponseIPs)).
			Msg("Unusually many A records")
	}

	// Check 5: Private IP in response (suspicious for public domains) (40 points)
	if d.isPublicDomain(dnsPkt.QueryDomain) && d.isPrivateIP(dnsPkt.ResponseIPs[0]) {
		score += 40
		details["private_ip_for_public_domain"] = true
		log.Debug().
			Str("domain", dnsPkt.QueryDomain).
			Str("ip", dnsPkt.ResponseIPs[0].String()).
			Msg("Private IP for public domain")
	}

	// If score exceeds threshold, create threat
	if score >= d.config.MinConfidence {
		d.threatsDetected++

		threat := &types.Threat{
			ID:          uuid.New().String(),
			Timestamp:   dnsPkt.Timestamp,
			Type:        types.ThreatTypeDNSHijack,
			Severity:    types.SeverityFromScore(score),
			Confidence:  score,
			Source:      dnsPkt.ServerIP,
			Target:      dnsPkt.QueryDomain,
			Description: fmt.Sprintf("Possible DNS hijacking for %s", dnsPkt.QueryDomain),
			Details:     details,
			Verified:    false,
		}

		// Add response IPs to details
		ips := make([]string, len(dnsPkt.ResponseIPs))
		for i, ip := range dnsPkt.ResponseIPs {
			ips[i] = ip.String()
		}
		details["response_ips"] = ips
		details["ttl"] = dnsPkt.TTL
		details["server_ip"] = dnsPkt.ServerIP.String()

		return threat, nil
	}

	return nil, nil
}

// addKnownServers adds servers to the known list
func (d *DNSHijackDetector) addKnownServers(servers []string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, server := range servers {
		d.knownServers[server] = true
	}
}

// isKnownServer checks if a DNS server is in the known list
func (d *DNSHijackDetector) isKnownServer(ip net.IP) bool {
	if ip == nil {
		return false
	}

	d.mu.RLock()
	defer d.mu.RUnlock()

	return d.knownServers[ip.String()]
}

// hasBaseline checks if we have a baseline for a domain
func (d *DNSHijackDetector) hasBaseline(domain string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()

	ips, exists := d.domainBaseline[domain]
	return exists && len(ips) > 0
}

// matchesBaseline checks if an IP matches the baseline
func (d *DNSHijackDetector) matchesBaseline(domain string, ip net.IP) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()

	ips, exists := d.domainBaseline[domain]
	if !exists {
		return false
	}

	for _, baselineIP := range ips {
		if baselineIP.Equal(ip) {
			return true
		}
	}

	return false
}

// getBaselineIPs returns the baseline IPs for a domain
func (d *DNSHijackDetector) getBaselineIPs(domain string) []string {
	d.mu.RLock()
	defer d.mu.RUnlock()

	ips, exists := d.domainBaseline[domain]
	if !exists {
		return nil
	}

	result := make([]string, len(ips))
	for i, ip := range ips {
		result[i] = ip.String()
	}
	return result
}

// updateBaseline adds an IP to the baseline for a domain
func (d *DNSHijackDetector) updateBaseline(domain string, ip net.IP) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if _, exists := d.domainBaseline[domain]; !exists {
		d.domainBaseline[domain] = make([]net.IP, 0, 3)
	}

	// Check if IP already in baseline
	for _, existingIP := range d.domainBaseline[domain] {
		if existingIP.Equal(ip) {
			return
		}
	}

	// Add IP (limit to 5 per domain)
	if len(d.domainBaseline[domain]) < 5 {
		d.domainBaseline[domain] = append(d.domainBaseline[domain], ip)
		log.Debug().
			Str("domain", domain).
			Str("ip", ip.String()).
			Msg("Added IP to baseline")
	}
}

// isPublicDomain checks if a domain appears to be public (heuristic)
func (d *DNSHijackDetector) isPublicDomain(domain string) bool {
	// Simple heuristic: domains with common TLDs are public
	// This is not perfect but good enough for basic detection
	publicTLDs := []string{".com", ".net", ".org", ".edu", ".gov", ".io", ".co"}

	for _, tld := range publicTLDs {
		if len(domain) > len(tld) && domain[len(domain)-len(tld):] == tld {
			return true
		}
	}

	return false
}

// isPrivateIP checks if an IP is in private ranges
func (d *DNSHijackDetector) isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}

	// Check if IPv4
	ip = ip.To4()
	if ip == nil {
		return false // IPv6 or invalid
	}

	// Private ranges:
	// 10.0.0.0/8
	// 172.16.0.0/12
	// 192.168.0.0/16
	// 127.0.0.0/8 (localhost)

	if ip[0] == 10 {
		return true
	}
	if ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31 {
		return true
	}
	if ip[0] == 192 && ip[1] == 168 {
		return true
	}
	if ip[0] == 127 {
		return true
	}

	return false
}

// GetStats returns detector statistics
func (d *DNSHijackDetector) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"queries_processed": d.queriesProcessed,
		"threats_detected":  d.threatsDetected,
		"known_servers":     len(d.knownServers),
		"domain_baselines":  len(d.domainBaseline),
	}
}
