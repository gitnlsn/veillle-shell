package types

import (
	"net"
	"time"
)

// Threat represents a detected security threat
type Threat struct {
	ID          string
	Timestamp   time.Time
	Type        string
	Severity    string
	Confidence  int // 0-100
	Source      net.IP
	Target      string
	Description string
	Details     map[string]interface{}
	Verified    bool
}

// Threat types
const (
	ThreatTypeDNSHijack    = "dns_hijack"
	ThreatTypeSSLStrip     = "ssl_strip"
	ThreatTypeWeakCrypto   = "weak_crypto"
	ThreatTypeARPSpoof     = "arp_spoof"
	ThreatTypeMITM         = "mitm"
)

// Severity levels
const (
	SeverityCritical = "critical" // 90-100
	SeverityHigh     = "high"     // 70-89
	SeverityMedium   = "medium"   // 50-69
	SeverityLow      = "low"      // 0-49
)

// SeverityFromScore converts confidence score to severity level
func SeverityFromScore(score int) string {
	switch {
	case score >= 90:
		return SeverityCritical
	case score >= 70:
		return SeverityHigh
	case score >= 50:
		return SeverityMedium
	default:
		return SeverityLow
	}
}

// SeverityColor returns ANSI color code for severity
func SeverityColor(severity string) string {
	switch severity {
	case SeverityCritical:
		return "\033[1;31m" // Bright red
	case SeverityHigh:
		return "\033[0;31m" // Red
	case SeverityMedium:
		return "\033[0;33m" // Yellow
	case SeverityLow:
		return "\033[0;36m" // Cyan
	default:
		return "\033[0m" // Reset
	}
}

// ColorReset returns ANSI reset code
func ColorReset() string {
	return "\033[0m"
}
