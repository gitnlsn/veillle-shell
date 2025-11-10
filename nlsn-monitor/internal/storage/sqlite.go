package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/nlsn-pcap-monitor/nlsn-monitor/pkg/types"
	"github.com/rs/zerolog/log"
)

// Store handles database operations
type Store struct {
	db *sql.DB
}

// New creates a new storage instance
func New(path string) (*Store, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Set connection pool settings
	db.SetMaxOpenConns(1) // SQLite works best with single connection
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	// Enable WAL mode for better concurrency
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		return nil, fmt.Errorf("failed to enable WAL mode: %w", err)
	}

	store := &Store{db: db}

	// Initialize schema
	if err := store.initSchema(); err != nil {
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	log.Info().Str("path", path).Msg("Database initialized")

	return store, nil
}

// initSchema creates database tables
func (s *Store) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS packets (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME NOT NULL,
		protocol TEXT NOT NULL,
		src_ip TEXT NOT NULL,
		dst_ip TEXT NOT NULL,
		src_port INTEGER,
		dst_port INTEGER,
		size INTEGER,
		metadata TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS dns_packets (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		transaction_id INTEGER NOT NULL,
		timestamp DATETIME NOT NULL,
		is_query BOOLEAN NOT NULL,
		is_response BOOLEAN NOT NULL,
		query_domain TEXT,
		query_type INTEGER,
		response_code INTEGER,
		response_ips TEXT,
		response_cname TEXT,
		ttl INTEGER,
		server_ip TEXT,
		client_ip TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS threats (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME NOT NULL,
		type TEXT NOT NULL,
		severity TEXT NOT NULL,
		confidence INTEGER NOT NULL,
		source_ip TEXT,
		target TEXT,
		details TEXT,
		verified BOOLEAN DEFAULT FALSE,
		verification_data TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS stats (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME NOT NULL,
		packets_captured INTEGER,
		packets_analyzed INTEGER,
		threats_detected INTEGER,
		verifications_run INTEGER,
		uptime_seconds INTEGER,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets(timestamp);
	CREATE INDEX IF NOT EXISTS idx_packets_protocol ON packets(protocol);
	CREATE INDEX IF NOT EXISTS idx_dns_timestamp ON dns_packets(timestamp);
	CREATE INDEX IF NOT EXISTS idx_dns_domain ON dns_packets(query_domain);
	CREATE INDEX IF NOT EXISTS idx_threats_timestamp ON threats(timestamp);
	CREATE INDEX IF NOT EXISTS idx_threats_type ON threats(type);
	CREATE INDEX IF NOT EXISTS idx_threats_severity ON threats(severity);
	`

	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("failed to create schema: %w", err)
	}

	return nil
}

// SaveDNSPacket saves a DNS packet to the database
func (s *Store) SaveDNSPacket(pkt *types.DNSPacket) error {
	// Convert response IPs to JSON
	ipsJSON, err := json.Marshal(pkt.ResponseIPs)
	if err != nil {
		return fmt.Errorf("failed to marshal IPs: %w", err)
	}

	query := `
		INSERT INTO dns_packets (
			transaction_id, timestamp, is_query, is_response,
			query_domain, query_type, response_code,
			response_ips, response_cname, ttl,
			server_ip, client_ip
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err = s.db.Exec(query,
		pkt.TransactionID,
		pkt.Timestamp,
		pkt.IsQuery,
		pkt.IsResponse,
		pkt.QueryDomain,
		pkt.QueryType,
		pkt.ResponseCode,
		string(ipsJSON),
		pkt.ResponseCNAME,
		pkt.TTL,
		pkt.ServerIP.String(),
		pkt.ClientIP.String(),
	)

	if err != nil {
		return fmt.Errorf("failed to insert DNS packet: %w", err)
	}

	return nil
}

// GetRecentDNSPackets retrieves recent DNS packets
func (s *Store) GetRecentDNSPackets(limit int) ([]*types.DNSPacket, error) {
	query := `
		SELECT transaction_id, timestamp, is_query, is_response,
			   query_domain, query_type, response_code,
			   response_ips, response_cname, ttl,
			   server_ip, client_ip
		FROM dns_packets
		ORDER BY timestamp DESC
		LIMIT ?
	`

	rows, err := s.db.Query(query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query DNS packets: %w", err)
	}
	defer rows.Close()

	var packets []*types.DNSPacket

	for rows.Next() {
		var pkt types.DNSPacket
		var ipsJSON, serverIPStr, clientIPStr string

		err := rows.Scan(
			&pkt.TransactionID,
			&pkt.Timestamp,
			&pkt.IsQuery,
			&pkt.IsResponse,
			&pkt.QueryDomain,
			&pkt.QueryType,
			&pkt.ResponseCode,
			&ipsJSON,
			&pkt.ResponseCNAME,
			&pkt.TTL,
			&serverIPStr,
			&clientIPStr,
		)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to scan DNS packet")
			continue
		}

		// Parse IPs
		if ipsJSON != "" && ipsJSON != "null" {
			json.Unmarshal([]byte(ipsJSON), &pkt.ResponseIPs)
		}

		// Parse IP addresses
		pkt.ServerIP = parseIP(serverIPStr)
		pkt.ClientIP = parseIP(clientIPStr)

		packets = append(packets, &pkt)
	}

	return packets, nil
}

// GetDNSPacketsByDomain retrieves DNS packets for a specific domain
func (s *Store) GetDNSPacketsByDomain(domain string, limit int) ([]*types.DNSPacket, error) {
	query := `
		SELECT transaction_id, timestamp, is_query, is_response,
			   query_domain, query_type, response_code,
			   response_ips, response_cname, ttl,
			   server_ip, client_ip
		FROM dns_packets
		WHERE query_domain = ?
		ORDER BY timestamp DESC
		LIMIT ?
	`

	rows, err := s.db.Query(query, domain, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query DNS packets: %w", err)
	}
	defer rows.Close()

	var packets []*types.DNSPacket

	for rows.Next() {
		var pkt types.DNSPacket
		var ipsJSON, serverIPStr, clientIPStr string

		err := rows.Scan(
			&pkt.TransactionID,
			&pkt.Timestamp,
			&pkt.IsQuery,
			&pkt.IsResponse,
			&pkt.QueryDomain,
			&pkt.QueryType,
			&pkt.ResponseCode,
			&ipsJSON,
			&pkt.ResponseCNAME,
			&pkt.TTL,
			&serverIPStr,
			&clientIPStr,
		)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to scan DNS packet")
			continue
		}

		// Parse IPs
		if ipsJSON != "" && ipsJSON != "null" {
			json.Unmarshal([]byte(ipsJSON), &pkt.ResponseIPs)
		}

		pkt.ServerIP = parseIP(serverIPStr)
		pkt.ClientIP = parseIP(clientIPStr)

		packets = append(packets, &pkt)
	}

	return packets, nil
}

// GetStats retrieves statistics from database
func (s *Store) GetStats() (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Count DNS packets
	var dnsCount int
	err := s.db.QueryRow("SELECT COUNT(*) FROM dns_packets").Scan(&dnsCount)
	if err != nil {
		return nil, fmt.Errorf("failed to count DNS packets: %w", err)
	}
	stats["dns_packets"] = dnsCount

	// Count threats
	var threatCount int
	err = s.db.QueryRow("SELECT COUNT(*) FROM threats").Scan(&threatCount)
	if err != nil {
		return nil, fmt.Errorf("failed to count threats: %w", err)
	}
	stats["threats"] = threatCount

	// Get date range
	var oldest, newest time.Time
	err = s.db.QueryRow("SELECT MIN(timestamp), MAX(timestamp) FROM dns_packets").Scan(&oldest, &newest)
	if err == nil {
		stats["oldest_packet"] = oldest
		stats["newest_packet"] = newest
	}

	return stats, nil
}

// SaveThreat saves a threat to the database
func (s *Store) SaveThreat(threat *types.Threat) error {
	// Convert details to JSON
	detailsJSON, err := json.Marshal(threat.Details)
	if err != nil {
		return fmt.Errorf("failed to marshal details: %w", err)
	}

	query := `
		INSERT INTO threats (
			timestamp, type, severity, confidence,
			source_ip, target, details, verified
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err = s.db.Exec(query,
		threat.Timestamp,
		threat.Type,
		threat.Severity,
		threat.Confidence,
		threat.Source.String(),
		threat.Target,
		string(detailsJSON),
		threat.Verified,
	)

	if err != nil {
		return fmt.Errorf("failed to insert threat: %w", err)
	}

	return nil
}

// GetRecentThreats retrieves recent threats
func (s *Store) GetRecentThreats(limit int) ([]*types.Threat, error) {
	query := `
		SELECT id, timestamp, type, severity, confidence,
			   source_ip, target, details, verified
		FROM threats
		ORDER BY timestamp DESC
		LIMIT ?
	`

	rows, err := s.db.Query(query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query threats: %w", err)
	}
	defer rows.Close()

	var threats []*types.Threat

	for rows.Next() {
		var threat types.Threat
		var id int
		var sourceIPStr, detailsJSON string

		err := rows.Scan(
			&id,
			&threat.Timestamp,
			&threat.Type,
			&threat.Severity,
			&threat.Confidence,
			&sourceIPStr,
			&threat.Target,
			&detailsJSON,
			&threat.Verified,
		)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to scan threat")
			continue
		}

		threat.Source = parseIP(sourceIPStr)

		// Parse details
		if detailsJSON != "" && detailsJSON != "null" {
			json.Unmarshal([]byte(detailsJSON), &threat.Details)
		}

		threats = append(threats, &threat)
	}

	return threats, nil
}

// GetThreatsByType retrieves threats of a specific type
func (s *Store) GetThreatsByType(threatType string, limit int) ([]*types.Threat, error) {
	query := `
		SELECT id, timestamp, type, severity, confidence,
			   source_ip, target, details, verified
		FROM threats
		WHERE type = ?
		ORDER BY timestamp DESC
		LIMIT ?
	`

	rows, err := s.db.Query(query, threatType, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query threats: %w", err)
	}
	defer rows.Close()

	var threats []*types.Threat

	for rows.Next() {
		var threat types.Threat
		var id int
		var sourceIPStr, detailsJSON string

		err := rows.Scan(
			&id,
			&threat.Timestamp,
			&threat.Type,
			&threat.Severity,
			&threat.Confidence,
			&sourceIPStr,
			&threat.Target,
			&detailsJSON,
			&threat.Verified,
		)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to scan threat")
			continue
		}

		threat.Source = parseIP(sourceIPStr)

		if detailsJSON != "" && detailsJSON != "null" {
			json.Unmarshal([]byte(detailsJSON), &threat.Details)
		}

		threats = append(threats, &threat)
	}

	return threats, nil
}

// Close closes the database connection
func (s *Store) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// parseIP safely parses an IP address string
func parseIP(ipStr string) net.IP {
	if ipStr == "" || ipStr == "<nil>" {
		return nil
	}
	return net.ParseIP(ipStr)
}
