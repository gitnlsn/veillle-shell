package parser

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/nlsn-pcap-monitor/nlsn-monitor/pkg/types"
)

// DNSParser parses DNS packets
type DNSParser struct{}

// NewDNSParser creates a new DNS parser
func NewDNSParser() *DNSParser {
	return &DNSParser{}
}

// Parse extracts DNS information from a packet
func (p *DNSParser) Parse(packet gopacket.Packet) (*types.DNSPacket, error) {
	// Get DNS layer
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return nil, fmt.Errorf("no DNS layer found")
	}

	dns, ok := dnsLayer.(*layers.DNS)
	if !ok {
		return nil, fmt.Errorf("failed to cast to DNS layer")
	}

	// Get IP layer for source/dest
	var srcIP, dstIP net.IP
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		srcIP = ip.SrcIP
		dstIP = ip.DstIP
	} else if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv6)
		srcIP = ip.SrcIP
		dstIP = ip.DstIP
	}

	dnsPkt := &types.DNSPacket{
		TransactionID: dns.ID,
		Opcode:        uint8(dns.OpCode),
		Authoritative: dns.AA,
		Truncated:     dns.TC,
		ResponseCode:  uint8(dns.ResponseCode),
		Timestamp:     packet.Metadata().Timestamp,
	}

	// Determine if query or response
	if dns.QR {
		dnsPkt.IsResponse = true
		dnsPkt.ServerIP = srcIP
		dnsPkt.ClientIP = dstIP
	} else {
		dnsPkt.IsQuery = true
		dnsPkt.ClientIP = srcIP
		dnsPkt.ServerIP = dstIP
	}

	// Parse questions (queries)
	if len(dns.Questions) > 0 {
		q := dns.Questions[0]
		dnsPkt.QueryDomain = string(q.Name)
		dnsPkt.QueryType = uint16(q.Type)
		dnsPkt.QueryClass = uint16(q.Class)
	}

	// Parse answers (responses)
	if len(dns.Answers) > 0 {
		dnsPkt.ResponseIPs = make([]net.IP, 0)

		for _, answer := range dns.Answers {
			// Get TTL from first answer
			if dnsPkt.TTL == 0 {
				dnsPkt.TTL = answer.TTL
			}

			// Parse based on type
			switch answer.Type {
			case layers.DNSTypeA:
				if len(answer.IP) > 0 {
					dnsPkt.ResponseIPs = append(dnsPkt.ResponseIPs, answer.IP)
				}
			case layers.DNSTypeAAAA:
				if len(answer.IP) > 0 {
					dnsPkt.ResponseIPs = append(dnsPkt.ResponseIPs, answer.IP)
				}
			case layers.DNSTypeCNAME:
				dnsPkt.ResponseCNAME = string(answer.CNAME)
			}
		}
	}

	return dnsPkt, nil
}

// ParseRaw parses DNS from raw bytes (alternative method)
func (p *DNSParser) ParseRaw(data []byte) (*types.DNSPacket, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("DNS packet too short: %d bytes", len(data))
	}

	dnsPkt := &types.DNSPacket{
		Timestamp: time.Now(),
	}

	// Parse header
	dnsPkt.TransactionID = binary.BigEndian.Uint16(data[0:2])

	flags := binary.BigEndian.Uint16(data[2:4])
	dnsPkt.IsResponse = (flags & 0x8000) != 0
	dnsPkt.IsQuery = !dnsPkt.IsResponse
	dnsPkt.Opcode = uint8((flags >> 11) & 0x0F)
	dnsPkt.Authoritative = (flags & 0x0400) != 0
	dnsPkt.Truncated = (flags & 0x0200) != 0
	dnsPkt.ResponseCode = uint8(flags & 0x000F)

	qdCount := binary.BigEndian.Uint16(data[4:6])
	anCount := binary.BigEndian.Uint16(data[6:8])

	offset := 12

	// Parse question section
	if qdCount > 0 {
		domain, newOffset, err := parseDomainName(data, offset)
		if err != nil {
			return nil, fmt.Errorf("failed to parse domain: %w", err)
		}
		dnsPkt.QueryDomain = domain
		offset = newOffset

		if offset+4 <= len(data) {
			dnsPkt.QueryType = binary.BigEndian.Uint16(data[offset : offset+2])
			dnsPkt.QueryClass = binary.BigEndian.Uint16(data[offset+2 : offset+4])
			offset += 4
		}
	}

	// Parse answer section
	if anCount > 0 && dnsPkt.IsResponse {
		dnsPkt.ResponseIPs = make([]net.IP, 0)

		for i := 0; i < int(anCount) && offset < len(data); i++ {
			// Skip name (compressed pointer or full name)
			if offset >= len(data) {
				break
			}

			// Check for compression pointer
			if data[offset]&0xC0 == 0xC0 {
				offset += 2
			} else {
				_, newOffset, err := parseDomainName(data, offset)
				if err != nil {
					break
				}
				offset = newOffset
			}

			if offset+10 > len(data) {
				break
			}

			answerType := binary.BigEndian.Uint16(data[offset : offset+2])
			// class := binary.BigEndian.Uint16(data[offset+2 : offset+4])
			ttl := binary.BigEndian.Uint32(data[offset+4 : offset+8])
			rdLength := binary.BigEndian.Uint16(data[offset+8 : offset+10])
			offset += 10

			if dnsPkt.TTL == 0 {
				dnsPkt.TTL = ttl
			}

			if offset+int(rdLength) > len(data) {
				break
			}

			switch answerType {
			case uint16(types.DNSTypeA):
				if rdLength == 4 {
					ip := net.IP(data[offset : offset+4])
					dnsPkt.ResponseIPs = append(dnsPkt.ResponseIPs, ip)
				}
			case uint16(types.DNSTypeAAAA):
				if rdLength == 16 {
					ip := net.IP(data[offset : offset+16])
					dnsPkt.ResponseIPs = append(dnsPkt.ResponseIPs, ip)
				}
			case uint16(types.DNSTypeCNAME):
				cname, _, err := parseDomainName(data, offset)
				if err == nil {
					dnsPkt.ResponseCNAME = cname
				}
			}

			offset += int(rdLength)
		}
	}

	return dnsPkt, nil
}

// parseDomainName parses a DNS domain name from the packet
func parseDomainName(data []byte, offset int) (string, int, error) {
	if offset >= len(data) {
		return "", offset, fmt.Errorf("offset out of bounds")
	}

	var domain string
	jumped := false
	jumpOffset := offset
	maxJumps := 10
	jumps := 0

	for {
		if offset >= len(data) {
			return "", jumpOffset, fmt.Errorf("unexpected end of data")
		}

		length := int(data[offset])

		// End of domain name
		if length == 0 {
			offset++
			break
		}

		// Compression pointer (starts with 11)
		if length&0xC0 == 0xC0 {
			if offset+1 >= len(data) {
				return "", jumpOffset, fmt.Errorf("invalid compression pointer")
			}

			// Prevent infinite loops
			jumps++
			if jumps > maxJumps {
				return "", jumpOffset, fmt.Errorf("too many compression jumps")
			}

			// Calculate pointer offset
			pointer := int(binary.BigEndian.Uint16(data[offset:offset+2]) & 0x3FFF)

			if !jumped {
				jumpOffset = offset + 2
				jumped = true
			}

			offset = pointer
			continue
		}

		// Regular label
		offset++
		if offset+length > len(data) {
			return "", jumpOffset, fmt.Errorf("label length exceeds data")
		}

		if domain != "" {
			domain += "."
		}
		domain += string(data[offset : offset+length])
		offset += length
	}

	if !jumped {
		jumpOffset = offset
	}

	return domain, jumpOffset, nil
}
