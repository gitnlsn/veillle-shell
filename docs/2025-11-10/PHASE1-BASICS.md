# Phase 1: Foundation - Packet Capture & Basic DNS Detection

**Duration:** 4 weeks (96 hours)
**Goal:** Working CLI tool that captures packets and detects DNS hijacking
**Start Date:** 2025-11-10

---

## Overview

Phase 1 builds the foundation: a command-line tool that can capture network packets, parse DNS traffic, and detect basic DNS hijacking attacks. At the end of this phase, you'll have a working security tool.

### What You'll Build

```bash
# Start monitoring
$ sudo nlsn-monitor start --interface en0

🔍 NLSN Monitor v0.1.0 - Network Security Monitor
📡 Capturing on interface: en0
🎯 Filters: DNS (port 53)
📊 Storage: ~/.local/share/nlsn-pcap/nlsn.db

[14:23:45] DNS Query: google.com → 8.8.8.8
[14:23:45] DNS Response: google.com = 142.250.185.46 (TTL: 300s)
[14:24:10] ⚠️  DNS HIJACK DETECTED
           Domain: bank.com
           Unexpected IP: 192.168.1.100
           Expected: 104.16.x.x (Cloudflare)
           Confidence: 85/100
           Threat ID: thr_abc123

^C
📊 Session Statistics:
   Packets captured: 1,234
   DNS queries: 456
   Threats detected: 1
   Duration: 5m 32s
```

---

## Prerequisites

### System Requirements

- **OS**: Linux or macOS (Windows with WSL2)
- **Go**: 1.21 or higher
- **libpcap**: Development libraries
- **Root access**: For packet capture

### Install Dependencies

#### macOS
```bash
# Install Go (if not already installed)
brew install go

# Install libpcap (usually pre-installed)
brew install libpcap

# Install development tools
xcode-select --install
```

#### Linux (Ubuntu/Debian)
```bash
# Install Go
sudo apt update
sudo apt install golang-go

# Install libpcap
sudo apt install libpcap-dev

# Install build tools
sudo apt install build-essential
```

### Development Tools (Recommended)

```bash
# Install linter
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Install test coverage tool
go install github.com/axw/gocov/gocov@latest

# Install air for live reload (optional)
go install github.com/cosmtrek/air@latest
```

---

## Week 1: CLI Framework & Packet Capture

### Day 1-2: Project Setup (8 hours)

#### 1. Create Project Structure

```bash
# Create project directory
mkdir -p ~/dev/nlsn-monitor
cd ~/dev/nlsn-monitor

# Initialize Go module
go mod init github.com/YOUR_USERNAME/nlsn-monitor

# Create directory structure
mkdir -p cmd/nlsn-monitor
mkdir -p internal/{capture,parser,detector,storage,config}
mkdir -p pkg/types
mkdir -p configs
mkdir -p test/testdata

# Create initial files
touch cmd/nlsn-monitor/main.go
touch internal/capture/capture.go
touch internal/config/config.go
touch configs/config.example.yaml
touch README.md
touch Makefile
touch .gitignore
```

#### 2. Add Dependencies

```bash
# Add required packages
go get github.com/google/gopacket
go get github.com/google/gopacket/pcap
go get github.com/spf13/cobra
go get github.com/spf13/viper
go get github.com/rs/zerolog
go get github.com/mattn/go-sqlite3
```

Create `go.mod`:
```go
module github.com/YOUR_USERNAME/nlsn-monitor

go 1.21

require (
    github.com/google/gopacket v1.1.19
    github.com/spf13/cobra v1.8.0
    github.com/spf13/viper v1.18.2
    github.com/rs/zerolog v1.31.0
    github.com/mattn/go-sqlite3 v1.14.18
)
```

#### 3. Setup Git

```bash
# Initialize git
git init

# Create .gitignore
cat > .gitignore <<EOF
# Binaries
/nlsn-monitor
*.exe
*.dll
*.so
*.dylib

# Test files
*.test
*.out
/test/testdata/*.db
/test/testdata/*.pcap

# Go
go.work

# IDE
.vscode/
.idea/
*.swp
*.swo

# Data
*.db
*.log
/data/

# Config (don't commit credentials)
/configs/config.yaml
!configs/config.example.yaml
EOF

# Initial commit
git add .
git commit -m "Initial project structure"
```

#### 4. Create Makefile

```makefile
# Makefile for nlsn-monitor

.PHONY: build test clean install lint run

# Variables
BINARY_NAME=nlsn-monitor
INSTALL_PATH=/usr/local/bin
GO=go
GOFLAGS=-v

# Build binary
build:
	$(GO) build $(GOFLAGS) -o $(BINARY_NAME) ./cmd/nlsn-monitor

# Build for multiple platforms
build-all:
	GOOS=linux GOARCH=amd64 $(GO) build -o $(BINARY_NAME)-linux-amd64 ./cmd/nlsn-monitor
	GOOS=darwin GOARCH=amd64 $(GO) build -o $(BINARY_NAME)-darwin-amd64 ./cmd/nlsn-monitor
	GOOS=darwin GOARCH=arm64 $(GO) build -o $(BINARY_NAME)-darwin-arm64 ./cmd/nlsn-monitor

# Run tests
test:
	$(GO) test -v -race -coverprofile=coverage.out ./...

# Test coverage
coverage: test
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# Install binary
install: build
	sudo install -m 755 $(BINARY_NAME) $(INSTALL_PATH)
	sudo setcap cap_net_raw=eip $(INSTALL_PATH)/$(BINARY_NAME)

# Clean build artifacts
clean:
	rm -f $(BINARY_NAME)
	rm -f $(BINARY_NAME)-*
	rm -f coverage.out coverage.html
	rm -f *.log *.db

# Lint code
lint:
	golangci-lint run ./...

# Format code
fmt:
	$(GO) fmt ./...

# Run directly (requires sudo for packet capture)
run: build
	sudo ./$(BINARY_NAME) start

# Development mode (with air for live reload)
dev:
	air

# Help
help:
	@echo "Available targets:"
	@echo "  build       - Build binary"
	@echo "  build-all   - Build for all platforms"
	@echo "  test        - Run tests"
	@echo "  coverage    - Generate test coverage report"
	@echo "  install     - Install binary to $(INSTALL_PATH)"
	@echo "  clean       - Remove build artifacts"
	@echo "  lint        - Run linter"
	@echo "  fmt         - Format code"
	@echo "  run         - Build and run (requires sudo)"
	@echo "  dev         - Run in development mode with live reload"
```

**Checkpoint:** Project structure created, dependencies installed
```bash
make test  # Should pass (no tests yet)
make build # Should create nlsn-monitor binary
```

---

### Day 3-4: CLI Framework (16 hours)

#### 1. Main Command Structure

Create `cmd/nlsn-monitor/main.go`:

```go
package main

import (
	"fmt"
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	version = "0.1.0"
	cfgFile string
	verbose bool
)

var rootCmd = &cobra.Command{
	Use:   "nlsn-monitor",
	Short: "Network security monitoring tool",
	Long: `NLSN Monitor - Advanced network security monitoring with MITM detection.

Captures network packets, detects anomalies, and verifies threats through
multiple independent network paths.`,
	Version: version,
}

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start monitoring network traffic",
	Long:  "Start capturing and analyzing network packets in real-time",
	RunE:  runStart,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("nlsn-monitor version %s\n", version)
	},
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "",
		"config file (default: ~/.config/nlsn-pcap/config.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false,
		"verbose output")

	// Start command flags
	startCmd.Flags().StringP("interface", "i", "auto",
		"network interface to capture on")
	startCmd.Flags().IntP("snaplen", "s", 65535,
		"snapshot length (bytes per packet)")
	startCmd.Flags().BoolP("promisc", "p", true,
		"enable promiscuous mode")
	startCmd.Flags().StringP("filter", "f", "port 53",
		"BPF filter expression")

	// Bind flags to viper
	viper.BindPFlag("interface", startCmd.Flags().Lookup("interface"))
	viper.BindPFlag("snaplen", startCmd.Flags().Lookup("snaplen"))
	viper.BindPFlag("promisc", startCmd.Flags().Lookup("promisc"))
	viper.BindPFlag("filter", startCmd.Flags().Lookup("filter"))

	// Add commands
	rootCmd.AddCommand(startCmd)
	rootCmd.AddCommand(versionCmd)
}

func initConfig() {
	// Setup logging
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	if verbose {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	// Read config file
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		// Default config locations
		home, err := os.UserHomeDir()
		if err != nil {
			log.Warn().Err(err).Msg("Could not determine home directory")
			return
		}

		viper.AddConfigPath(home + "/.config/nlsn-pcap")
		viper.AddConfigPath("/etc/nlsn-pcap")
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
	}

	// Environment variables
	viper.SetEnvPrefix("NLSN")
	viper.AutomaticEnv()

	// Read config
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			log.Warn().Err(err).Msg("Error reading config file")
		}
	} else {
		log.Debug().Str("file", viper.ConfigFileUsed()).
			Msg("Using config file")
	}
}

func runStart(cmd *cobra.Command, args []string) error {
	log.Info().Str("version", version).Msg("Starting NLSN Monitor")

	// Get configuration
	iface := viper.GetString("interface")
	snaplen := viper.GetInt("snaplen")
	promisc := viper.GetBool("promisc")
	filter := viper.GetString("filter")

	log.Info().
		Str("interface", iface).
		Int("snaplen", snaplen).
		Bool("promisc", promisc).
		Str("filter", filter).
		Msg("Configuration loaded")

	// TODO: Start packet capture
	fmt.Println("🔍 NLSN Monitor - Starting...")
	fmt.Printf("📡 Interface: %s\n", iface)
	fmt.Printf("🎯 Filter: %s\n", filter)

	return nil
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
```

#### 2. Configuration Module

Create `internal/config/config.go`:

```go
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	Capture   CaptureConfig   `mapstructure:"capture"`
	Detection DetectionConfig `mapstructure:"detection"`
	Storage   StorageConfig   `mapstructure:"storage"`
	Logging   LoggingConfig   `mapstructure:"logging"`
}

type CaptureConfig struct {
	Interface  string `mapstructure:"interface"`
	Snaplen    int    `mapstructure:"snaplen"`
	Promisc    bool   `mapstructure:"promisc"`
	BufferSize int    `mapstructure:"buffer_size"`
	Filter     string `mapstructure:"filter"`
}

type DetectionConfig struct {
	Enabled       bool   `mapstructure:"enabled"`
	PatternsFile  string `mapstructure:"patterns_file"`
	MinConfidence int    `mapstructure:"min_confidence"`
}

type StorageConfig struct {
	Type          string `mapstructure:"type"`
	Path          string `mapstructure:"path"`
	RetentionDays int    `mapstructure:"retention_days"`
}

type LoggingConfig struct {
	Level      string `mapstructure:"level"`
	File       string `mapstructure:"file"`
	MaxSizeMB  int    `mapstructure:"max_size_mb"`
	MaxBackups int    `mapstructure:"max_backups"`
}

func Load() (*Config, error) {
	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Expand paths
	cfg.Storage.Path = expandPath(cfg.Storage.Path)
	cfg.Logging.File = expandPath(cfg.Logging.File)

	return &cfg, nil
}

func expandPath(path string) string {
	if path == "" {
		return path
	}

	// Expand ~
	if len(path) > 0 && path[0] == '~' {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		path = filepath.Join(home, path[1:])
	}

	return path
}

func InitDirectories(cfg *Config) error {
	// Create config directory
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("could not get home directory: %w", err)
	}

	configDir := filepath.Join(home, ".config", "nlsn-pcap")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return fmt.Errorf("could not create config directory: %w", err)
	}

	// Create data directory
	dataDir := filepath.Join(home, ".local", "share", "nlsn-pcap")
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return fmt.Errorf("could not create data directory: %w", err)
	}

	// Create logs directory
	logsDir := filepath.Join(dataDir, "logs")
	if err := os.MkdirAll(logsDir, 0700); err != nil {
		return fmt.Errorf("could not create logs directory: %w", err)
	}

	return nil
}
```

#### 3. Sample Configuration File

Create `configs/config.example.yaml`:

```yaml
# NLSN PCAP Monitor Configuration
# Copy to ~/.config/nlsn-pcap/config.yaml and customize

version: "2.0"

# Packet capture settings
capture:
  interface: "auto"              # Network interface (auto-detect or specify)
  snaplen: 65535                 # Bytes to capture per packet
  promisc: true                  # Promiscuous mode
  buffer_size: 10485760          # 10MB packet buffer
  filter: "port 53 or port 80 or port 443"  # BPF filter

# Detection settings
detection:
  enabled: true
  patterns_file: "patterns.yaml" # Detection pattern definitions
  min_confidence: 50             # Minimum score (0-100) to trigger alert

# Storage settings
storage:
  type: "sqlite"                 # Database type (sqlite|postgres|none)
  path: "~/.local/share/nlsn-pcap/nlsn.db"  # Database path
  retention_days: 30             # Auto-delete data older than N days

# Logging settings
logging:
  level: "info"                  # Log level (debug|info|warn|error)
  file: "~/.local/share/nlsn-pcap/logs/nlsn.log"  # Log file path
  max_size_mb: 100               # Max log file size before rotation
  max_backups: 5                 # Number of old log files to keep
```

**Checkpoint:** CLI framework complete
```bash
make build
./nlsn-monitor --help      # Should show commands
./nlsn-monitor version     # Should show v0.1.0
./nlsn-monitor start --help # Should show flags
```

---

### Day 5-7: Packet Capture Engine (24 hours)

#### 1. Interface Detection

Create `internal/capture/interfaces.go`:

```go
package capture

import (
	"fmt"
	"net"

	"github.com/google/gopacket/pcap"
	"github.com/rs/zerolog/log"
)

// ListInterfaces returns all available network interfaces
func ListInterfaces() ([]string, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("failed to find devices: %w", err)
	}

	interfaces := make([]string, 0, len(devices))
	for _, device := range devices {
		interfaces = append(interfaces, device.Name)
	}

	return interfaces, nil
}

// SelectInterface chooses the best interface for capture
func SelectInterface(preferred string) (string, error) {
	if preferred != "" && preferred != "auto" {
		// Verify interface exists
		devices, err := pcap.FindAllDevs()
		if err != nil {
			return "", fmt.Errorf("failed to find devices: %w", err)
		}

		for _, device := range devices {
			if device.Name == preferred {
				return preferred, nil
			}
		}

		return "", fmt.Errorf("interface %s not found", preferred)
	}

	// Auto-detect: Find first non-loopback interface with IP
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return "", fmt.Errorf("failed to find devices: %w", err)
	}

	for _, device := range devices {
		// Skip loopback
		if device.Name == "lo" || device.Name == "lo0" {
			continue
		}

		// Must have at least one address
		if len(device.Addresses) > 0 {
			for _, addr := range device.Addresses {
				// Must be IPv4 or IPv6
				ip := addr.IP
				if ip.To4() != nil || ip.To16() != nil {
					log.Info().
						Str("interface", device.Name).
						Str("ip", ip.String()).
						Msg("Auto-selected interface")
					return device.Name, nil
				}
			}
		}
	}

	return "", fmt.Errorf("no suitable network interface found")
}

// GetInterfaceInfo returns information about an interface
func GetInterfaceInfo(name string) (*pcap.Interface, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("failed to find devices: %w", err)
	}

	for _, device := range devices {
		if device.Name == name {
			return &device, nil
		}
	}

	return nil, fmt.Errorf("interface %s not found", name)
}
```

#### 2. Packet Capture Implementation

Create `internal/capture/capture.go`:

```go
package capture

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/rs/zerolog/log"
)

type Statistics struct {
	PacketsCaptured   uint64
	PacketsDropped    uint64
	PacketsIfDropped  uint64
	BytesCaptured     uint64
	StartTime         time.Time
	LastPacketTime    time.Time
	mu                sync.RWMutex
}

type Capturer struct {
	handle     *pcap.Handle
	packetChan chan gopacket.Packet
	doneChan   chan struct{}
	stats      *Statistics
	wg         sync.WaitGroup
	running    bool
	mu         sync.RWMutex
}

func New(iface string, snaplen int32, promisc bool, timeout time.Duration) (*Capturer, error) {
	// Open device
	handle, err := pcap.OpenLive(iface, snaplen, promisc, timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to open device: %w", err)
	}

	log.Info().
		Str("interface", iface).
		Int32("snaplen", snaplen).
		Bool("promisc", promisc).
		Dur("timeout", timeout).
		Msg("Opened capture device")

	return &Capturer{
		handle:     handle,
		packetChan: make(chan gopacket.Packet, 1000),
		doneChan:   make(chan struct{}),
		stats: &Statistics{
			StartTime: time.Now(),
		},
	}, nil
}

func (c *Capturer) SetBPFFilter(filter string) error {
	if err := c.handle.SetBPFFilter(filter); err != nil {
		return fmt.Errorf("failed to set BPF filter: %w", err)
	}

	log.Info().Str("filter", filter).Msg("BPF filter applied")
	return nil
}

func (c *Capturer) Start() error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return fmt.Errorf("capturer already running")
	}
	c.running = true
	c.mu.Unlock()

	c.wg.Add(1)
	go c.captureLoop()

	log.Info().Msg("Packet capture started")
	return nil
}

func (c *Capturer) captureLoop() {
	defer c.wg.Done()

	packetSource := gopacket.NewPacketSource(c.handle, c.handle.LinkType())
	packetSource.DecodeOptions.Lazy = true
	packetSource.DecodeOptions.NoCopy = true

	for {
		select {
		case <-c.doneChan:
			return
		case packet := <-packetSource.Packets():
			if packet == nil {
				return
			}

			// Update statistics
			c.stats.mu.Lock()
			c.stats.PacketsCaptured++
			c.stats.BytesCaptured += uint64(len(packet.Data()))
			c.stats.LastPacketTime = packet.Metadata().Timestamp
			c.stats.mu.Unlock()

			// Send to processing
			select {
			case c.packetChan <- packet:
			case <-c.doneChan:
				return
			default:
				// Channel full, drop packet
				c.stats.mu.Lock()
				c.stats.PacketsDropped++
				c.stats.mu.Unlock()
				log.Warn().Msg("Packet buffer full, dropping packet")
			}
		}
	}
}

func (c *Capturer) Packets() <-chan gopacket.Packet {
	return c.packetChan
}

func (c *Capturer) Stop() error {
	c.mu.Lock()
	if !c.running {
		c.mu.Unlock()
		return fmt.Errorf("capturer not running")
	}
	c.running = false
	c.mu.Unlock()

	// Signal stop
	close(c.doneChan)

	// Wait for capture loop to finish
	c.wg.Wait()

	// Get final stats from pcap
	stats, err := c.handle.Stats()
	if err == nil {
		c.stats.mu.Lock()
		c.stats.PacketsIfDropped = uint64(stats.PacketsIfDropped)
		c.stats.mu.Unlock()
	}

	// Close handle
	c.handle.Close()

	log.Info().Msg("Packet capture stopped")
	return nil
}

func (c *Capturer) Stats() Statistics {
	c.stats.mu.RLock()
	defer c.stats.mu.RUnlock()

	return Statistics{
		PacketsCaptured:  c.stats.PacketsCaptured,
		PacketsDropped:   c.stats.PacketsDropped,
		PacketsIfDropped: c.stats.PacketsIfDropped,
		BytesCaptured:    c.stats.BytesCaptured,
		StartTime:        c.stats.StartTime,
		LastPacketTime:   c.stats.LastPacketTime,
	}
}

func (s *Statistics) Duration() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return time.Since(s.StartTime)
}

func (s *Statistics) PacketsPerSecond() float64 {
	s.mu.RLock()
	defer s.mu.RUnlock()

	duration := time.Since(s.StartTime).Seconds()
	if duration == 0 {
		return 0
	}

	return float64(s.PacketsCaptured) / duration
}
```

#### 3. Update main.go to use Capturer

Update `runStart` function in `cmd/nlsn-monitor/main.go`:

```go
func runStart(cmd *cobra.Command, args []string) error {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Initialize directories
	if err := config.InitDirectories(cfg); err != nil {
		return fmt.Errorf("failed to initialize directories: %w", err)
	}

	// Select interface
	iface, err := capture.SelectInterface(cfg.Capture.Interface)
	if err != nil {
		return fmt.Errorf("failed to select interface: %w", err)
	}

	// Create capturer
	capturer, err := capture.New(
		iface,
		int32(cfg.Capture.Snaplen),
		cfg.Capture.Promisc,
		time.Second,
	)
	if err != nil {
		return fmt.Errorf("failed to create capturer: %w", err)
	}
	defer capturer.Stop()

	// Set BPF filter
	if cfg.Capture.Filter != "" {
		if err := capturer.SetBPFFilter(cfg.Capture.Filter); err != nil {
			return fmt.Errorf("failed to set filter: %w", err)
		}
	}

	// Start capture
	if err := capturer.Start(); err != nil {
		return fmt.Errorf("failed to start capture: %w", err)
	}

	// Print banner
	fmt.Println("🔍 NLSN Monitor v" + version)
	fmt.Printf("📡 Interface: %s\n", iface)
	fmt.Printf("🎯 Filter: %s\n", cfg.Capture.Filter)
	fmt.Printf("📊 Storage: %s\n", cfg.Storage.Path)
	fmt.Println("")

	// Handle signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Process packets
	go processPackets(capturer.Packets())

	// Wait for signal
	<-sigChan
	fmt.Println("\n\n🛑 Stopping...")

	// Print statistics
	stats := capturer.Stats()
	fmt.Println("\n📊 Session Statistics:")
	fmt.Printf("   Packets captured: %d\n", stats.PacketsCaptured)
	fmt.Printf("   Packets dropped: %d\n", stats.PacketsDropped)
	fmt.Printf("   Bytes captured: %d\n", stats.BytesCaptured)
	fmt.Printf("   Duration: %s\n", stats.Duration().Round(time.Second))
	fmt.Printf("   Rate: %.0f pkt/s\n", stats.PacketsPerSecond())

	return nil
}

func processPackets(packets <-chan gopacket.Packet) {
	for packet := range packets {
		// TODO: Parse and detect
		// For now, just count
		log.Debug().
			Time("timestamp", packet.Metadata().Timestamp).
			Int("length", len(packet.Data())).
			Msg("Packet received")
	}
}
```

**Checkpoint:** Packet capture working
```bash
make build
sudo ./nlsn-monitor start --interface en0 --verbose
# Should see packets being captured
# Ctrl+C should show statistics
```

---

## Week 2: DNS Parser & Storage

*(Detailed tasks for Week 2 would continue here...)*

**To be continued in the implementation phase.**

---

## Quick Reference

### Key Files

| File | Purpose |
|------|---------|
| `cmd/nlsn-monitor/main.go` | Main CLI entry point |
| `internal/capture/capture.go` | Packet capture engine |
| `internal/parser/dns.go` | DNS protocol parser |
| `internal/detector/dns_hijack.go` | DNS hijacking detector |
| `internal/storage/sqlite.go` | SQLite database interface |
| `internal/config/config.go` | Configuration management |

### Common Commands

```bash
# Build
make build

# Test
make test

# Install (requires sudo)
make install

# Run
sudo nlsn-monitor start

# Run with specific interface
sudo nlsn-monitor start --interface eth0

# Verbose mode
sudo nlsn-monitor start --verbose

# Custom config
nlsn-monitor start --config /path/to/config.yaml
```

### Troubleshooting

**"Permission denied" error:**
```bash
# Option 1: Run as root
sudo nlsn-monitor start

# Option 2: Grant capabilities
sudo setcap cap_net_raw=eip ./nlsn-monitor
./nlsn-monitor start
```

**"No suitable interface found":**
```bash
# List interfaces
nlsn-monitor list-interfaces

# Specify manually
nlsn-monitor start --interface en0
```

**"Failed to open device":**
- Ensure libpcap is installed
- Check interface name is correct
- Verify you have necessary permissions

---

## Next Steps

After completing Week 1, continue with:
- **Week 2**: DNS parser implementation
- **Week 3**: DNS hijacking detection
- **Week 4**: Testing and polish

See `IMPLEMENTATION-PLAN.md` for the complete roadmap.
