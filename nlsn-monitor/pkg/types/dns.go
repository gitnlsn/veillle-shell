package types

import (
	"net"
	"time"
)

// DNSPacket represents a parsed DNS packet
type DNSPacket struct {
	TransactionID uint16
	IsQuery       bool
	IsResponse    bool
	Opcode        uint8
	Authoritative bool
	Truncated     bool

	// Query information
	QueryDomain string
	QueryType   uint16
	QueryClass  uint16

	// Response information
	ResponseCode uint8
	ResponseIPs  []net.IP
	ResponseCNAME string
	TTL          uint32

	// Metadata
	ServerIP   net.IP
	ClientIP   net.IP
	Timestamp  time.Time
}

// DNS Record Types
const (
	DNSTypeA     uint16 = 1   // IPv4 address
	DNSTypeNS    uint16 = 2   // Name server
	DNSTypeCNAME uint16 = 5   // Canonical name
	DNSTypeSOA   uint16 = 6   // Start of authority
	DNSTypePTR   uint16 = 12  // Pointer record
	DNSTypeMX    uint16 = 15  // Mail exchange
	DNSTypeTXT   uint16 = 16  // Text record
	DNSTypeAAAA  uint16 = 28  // IPv6 address
)

// DNS Response Codes
const (
	DNSRCodeNoError  uint8 = 0  // No error
	DNSRCodeFormErr  uint8 = 1  // Format error
	DNSRCodeServFail uint8 = 2  // Server failure
	DNSRCodeNXDomain uint8 = 3  // Non-existent domain
	DNSRCodeNotImpl  uint8 = 4  // Not implemented
	DNSRCodeRefused  uint8 = 5  // Query refused
)

// DNS Classes
const (
	DNSClassIN uint16 = 1  // Internet
)

// TypeString returns human-readable DNS type
func (p *DNSPacket) TypeString() string {
	switch p.QueryType {
	case DNSTypeA:
		return "A"
	case DNSTypeAAAA:
		return "AAAA"
	case DNSTypeCNAME:
		return "CNAME"
	case DNSTypeMX:
		return "MX"
	case DNSTypeNS:
		return "NS"
	case DNSTypeTXT:
		return "TXT"
	case DNSTypePTR:
		return "PTR"
	default:
		return "UNKNOWN"
	}
}

// RCodeString returns human-readable response code
func (p *DNSPacket) RCodeString() string {
	switch p.ResponseCode {
	case DNSRCodeNoError:
		return "NOERROR"
	case DNSRCodeFormErr:
		return "FORMERR"
	case DNSRCodeServFail:
		return "SERVFAIL"
	case DNSRCodeNXDomain:
		return "NXDOMAIN"
	case DNSRCodeNotImpl:
		return "NOTIMPL"
	case DNSRCodeRefused:
		return "REFUSED"
	default:
		return "UNKNOWN"
	}
}
