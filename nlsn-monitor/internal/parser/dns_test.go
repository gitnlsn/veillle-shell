package parser

import (
	"net"
	"testing"

	"github.com/nlsn-pcap-monitor/nlsn-monitor/pkg/types"
)

func TestParseDomainName(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		offset   int
		expected string
		wantErr  bool
	}{
		{
			name:     "simple domain",
			data:     []byte{6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', 0},
			offset:   0,
			expected: "google.com",
			wantErr:  false,
		},
		{
			name:     "subdomain",
			data:     []byte{3, 'w', 'w', 'w', 6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', 0},
			offset:   0,
			expected: "www.google.com",
			wantErr:  false,
		},
		{
			name:     "single label",
			data:     []byte{9, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0},
			offset:   0,
			expected: "localhost",
			wantErr:  false,
		},
		{
			name:     "empty domain",
			data:     []byte{0},
			offset:   0,
			expected: "",
			wantErr:  false,
		},
		{
			name:     "out of bounds",
			data:     []byte{10, 'x'},
			offset:   0,
			expected: "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _, err := parseDomainName(tt.data, tt.offset)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseDomainName() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && result != tt.expected {
				t.Errorf("parseDomainName() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestParseRaw(t *testing.T) {
	parser := NewDNSParser()

	t.Run("valid A query", func(t *testing.T) {
		// Minimal DNS query for "test.com" A record
		data := []byte{
			0x12, 0x34, // Transaction ID
			0x01, 0x00, // Flags: standard query
			0x00, 0x01, // Questions: 1
			0x00, 0x00, // Answers: 0
			0x00, 0x00, // Authority: 0
			0x00, 0x00, // Additional: 0
			// Question
			4, 't', 'e', 's', 't', 3, 'c', 'o', 'm', 0, // test.com
			0x00, 0x01, // Type A
			0x00, 0x01, // Class IN
		}

		pkt, err := parser.ParseRaw(data)
		if err != nil {
			t.Fatalf("ParseRaw() error = %v", err)
		}

		if pkt.TransactionID != 0x1234 {
			t.Errorf("TransactionID = %v, want %v", pkt.TransactionID, 0x1234)
		}
		if pkt.IsResponse {
			t.Errorf("IsResponse = true, want false")
		}
		if pkt.QueryDomain != "test.com" {
			t.Errorf("QueryDomain = %v, want test.com", pkt.QueryDomain)
		}
		if pkt.QueryType != types.DNSTypeA {
			t.Errorf("QueryType = %v, want %v", pkt.QueryType, types.DNSTypeA)
		}
	})

	t.Run("valid A response", func(t *testing.T) {
		// DNS response for "test.com" -> 1.2.3.4
		data := []byte{
			0x12, 0x34, // Transaction ID
			0x81, 0x80, // Flags: response, no error
			0x00, 0x01, // Questions: 1
			0x00, 0x01, // Answers: 1
			0x00, 0x00, // Authority: 0
			0x00, 0x00, // Additional: 0
			// Question
			4, 't', 'e', 's', 't', 3, 'c', 'o', 'm', 0,
			0x00, 0x01, // Type A
			0x00, 0x01, // Class IN
			// Answer
			0xc0, 0x0c, // Pointer to name (compression)
			0x00, 0x01, // Type A
			0x00, 0x01, // Class IN
			0x00, 0x00, 0x00, 0x3c, // TTL: 60 seconds
			0x00, 0x04, // Data length: 4
			1, 2, 3, 4, // IP: 1.2.3.4
		}

		pkt, err := parser.ParseRaw(data)
		if err != nil {
			t.Fatalf("ParseRaw() error = %v", err)
		}

		if !pkt.IsResponse {
			t.Errorf("IsResponse = false, want true")
		}
		if pkt.QueryDomain != "test.com" {
			t.Errorf("QueryDomain = %v, want test.com", pkt.QueryDomain)
		}
		if pkt.TTL != 60 {
			t.Errorf("TTL = %v, want 60", pkt.TTL)
		}
		if len(pkt.ResponseIPs) != 1 {
			t.Fatalf("ResponseIPs length = %v, want 1", len(pkt.ResponseIPs))
		}
		expectedIP := net.IPv4(1, 2, 3, 4)
		if !pkt.ResponseIPs[0].Equal(expectedIP) {
			t.Errorf("ResponseIP = %v, want %v", pkt.ResponseIPs[0], expectedIP)
		}
	})

	t.Run("packet too short", func(t *testing.T) {
		data := []byte{0x12, 0x34, 0x01} // Only 3 bytes
		_, err := parser.ParseRaw(data)
		if err == nil {
			t.Errorf("ParseRaw() expected error for short packet")
		}
	})

	t.Run("NXDOMAIN response", func(t *testing.T) {
		data := []byte{
			0x12, 0x34, // Transaction ID
			0x81, 0x83, // Flags: response, NXDOMAIN (0x0003)
			0x00, 0x01, // Questions: 1
			0x00, 0x00, // Answers: 0
			0x00, 0x00, // Authority: 0
			0x00, 0x00, // Additional: 0
			// Question
			8, 'n', 'o', 't', 'e', 'x', 'i', 's', 't', 3, 'c', 'o', 'm', 0,
			0x00, 0x01, // Type A
			0x00, 0x01, // Class IN
		}

		pkt, err := parser.ParseRaw(data)
		if err != nil {
			t.Fatalf("ParseRaw() error = %v", err)
		}

		if pkt.ResponseCode != types.DNSRCodeNXDomain {
			t.Errorf("ResponseCode = %v, want %v (NXDOMAIN)", pkt.ResponseCode, types.DNSRCodeNXDomain)
		}
	})
}

func TestDNSPacket_TypeString(t *testing.T) {
	tests := []struct {
		queryType uint16
		expected  string
	}{
		{types.DNSTypeA, "A"},
		{types.DNSTypeAAAA, "AAAA"},
		{types.DNSTypeCNAME, "CNAME"},
		{types.DNSTypeMX, "MX"},
		{types.DNSTypeNS, "NS"},
		{999, "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			pkt := &types.DNSPacket{QueryType: tt.queryType}
			result := pkt.TypeString()
			if result != tt.expected {
				t.Errorf("TypeString() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestDNSPacket_RCodeString(t *testing.T) {
	tests := []struct {
		rcode    uint8
		expected string
	}{
		{types.DNSRCodeNoError, "NOERROR"},
		{types.DNSRCodeFormErr, "FORMERR"},
		{types.DNSRCodeServFail, "SERVFAIL"},
		{types.DNSRCodeNXDomain, "NXDOMAIN"},
		{types.DNSRCodeNotImpl, "NOTIMPL"},
		{types.DNSRCodeRefused, "REFUSED"},
		{99, "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			pkt := &types.DNSPacket{ResponseCode: tt.rcode}
			result := pkt.RCodeString()
			if result != tt.expected {
				t.Errorf("RCodeString() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestParseRaw_MultipleAnswers(t *testing.T) {
	parser := NewDNSParser()

	// DNS response with 2 A records
	data := []byte{
		0x12, 0x34, // Transaction ID
		0x81, 0x80, // Flags: response
		0x00, 0x01, // Questions: 1
		0x00, 0x02, // Answers: 2
		0x00, 0x00, // Authority: 0
		0x00, 0x00, // Additional: 0
		// Question
		4, 't', 'e', 's', 't', 3, 'c', 'o', 'm', 0,
		0x00, 0x01, // Type A
		0x00, 0x01, // Class IN
		// Answer 1
		0xc0, 0x0c, // Pointer to name
		0x00, 0x01, // Type A
		0x00, 0x01, // Class IN
		0x00, 0x00, 0x00, 0x3c, // TTL: 60
		0x00, 0x04, // Data length: 4
		1, 2, 3, 4, // IP: 1.2.3.4
		// Answer 2
		0xc0, 0x0c, // Pointer to name
		0x00, 0x01, // Type A
		0x00, 0x01, // Class IN
		0x00, 0x00, 0x00, 0x3c, // TTL: 60
		0x00, 0x04, // Data length: 4
		5, 6, 7, 8, // IP: 5.6.7.8
	}

	pkt, err := parser.ParseRaw(data)
	if err != nil {
		t.Fatalf("ParseRaw() error = %v", err)
	}

	if len(pkt.ResponseIPs) != 2 {
		t.Errorf("ResponseIPs length = %v, want 2", len(pkt.ResponseIPs))
	}

	ip1 := net.IPv4(1, 2, 3, 4)
	ip2 := net.IPv4(5, 6, 7, 8)

	if !pkt.ResponseIPs[0].Equal(ip1) {
		t.Errorf("ResponseIP[0] = %v, want %v", pkt.ResponseIPs[0], ip1)
	}
	if !pkt.ResponseIPs[1].Equal(ip2) {
		t.Errorf("ResponseIP[1] = %v, want %v", pkt.ResponseIPs[1], ip2)
	}
}

func BenchmarkParseRaw(b *testing.B) {
	parser := NewDNSParser()

	// Sample DNS response
	data := []byte{
		0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		4, 't', 'e', 's', 't', 3, 'c', 'o', 'm', 0,
		0x00, 0x01, 0x00, 0x01,
		0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x3c, 0x00, 0x04,
		1, 2, 3, 4,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parser.ParseRaw(data)
	}
}
