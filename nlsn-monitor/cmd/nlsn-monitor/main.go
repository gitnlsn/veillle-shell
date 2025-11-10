package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/nlsn-pcap-monitor/nlsn-monitor/internal/capture"
	"github.com/nlsn-pcap-monitor/nlsn-monitor/internal/config"
	"github.com/nlsn-pcap-monitor/nlsn-monitor/internal/detector"
	"github.com/nlsn-pcap-monitor/nlsn-monitor/internal/parser"
	"github.com/nlsn-pcap-monitor/nlsn-monitor/internal/storage"
	"github.com/nlsn-pcap-monitor/nlsn-monitor/pkg/types"
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

var threatsCmd = &cobra.Command{
	Use:   "threats",
	Short: "Query detected threats from database",
	Long:  "View and filter detected security threats stored in the database",
	RunE:  runThreats,
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
	viper.BindPFlag("capture.interface", startCmd.Flags().Lookup("interface"))
	viper.BindPFlag("capture.snaplen", startCmd.Flags().Lookup("snaplen"))
	viper.BindPFlag("capture.promisc", startCmd.Flags().Lookup("promisc"))
	viper.BindPFlag("capture.filter", startCmd.Flags().Lookup("filter"))

	// Threats command flags
	threatsCmd.Flags().IntP("limit", "n", 10,
		"number of threats to display")
	threatsCmd.Flags().StringP("type", "t", "",
		"filter by threat type (dns_hijack, ssl_strip, etc.)")
	threatsCmd.Flags().StringP("severity", "s", "",
		"filter by severity (critical, high, medium, low)")
	threatsCmd.Flags().BoolP("all", "a", false,
		"show all threats (no limit)")
	threatsCmd.Flags().BoolP("json", "j", false,
		"output as JSON")

	// Add commands
	rootCmd.AddCommand(startCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(threatsCmd)
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

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Initialize directories
	if err := config.InitDirectories(cfg); err != nil {
		return fmt.Errorf("failed to initialize directories: %w", err)
	}

	// Initialize database
	store, err := storage.New(cfg.Storage.Path)
	if err != nil {
		return fmt.Errorf("failed to initialize storage: %w", err)
	}
	defer store.Close()

	// Create DNS parser
	dnsParser := parser.NewDNSParser()

	// Create DNS hijack detector
	detectorConfig := detector.DetectorConfig{
		MinConfidence: cfg.Detection.MinConfidence,
		Enabled:       cfg.Detection.Enabled,
	}
	dnsDetector := detector.NewDNSHijackDetector(detectorConfig)

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
	fmt.Println("🔍 NLSN Monitor v" + version + " - Network Security Monitor")
	fmt.Printf("📡 Capturing on interface: %s\n", iface)
	fmt.Printf("🎯 Filters: %s\n", cfg.Capture.Filter)
	fmt.Printf("📊 Storage: %s\n", cfg.Storage.Path)
	fmt.Println("")

	// Handle signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Counters for processed packets
	var dnsProcessed, dnsErrors, threatsDetected uint64

	// Process packets
	go processPackets(capturer.Packets(), dnsParser, dnsDetector, store, &dnsProcessed, &dnsErrors, &threatsDetected)

	// Wait for signal
	<-sigChan
	fmt.Println("\n\n🛑 Stopping...")

	// Give time for last packets to process
	time.Sleep(100 * time.Millisecond)

	// Print statistics
	stats := capturer.Stats()
	fmt.Println("\n📊 Session Statistics:")
	fmt.Printf("   Packets captured: %d\n", stats.PacketsCaptured)
	fmt.Printf("   DNS packets processed: %d\n", atomic.LoadUint64(&dnsProcessed))
	fmt.Printf("   DNS parsing errors: %d\n", atomic.LoadUint64(&dnsErrors))
	fmt.Printf("   Threats detected: %d\n", atomic.LoadUint64(&threatsDetected))
	fmt.Printf("   Packets dropped: %d\n", stats.PacketsDropped)
	fmt.Printf("   Bytes captured: %d\n", stats.BytesCaptured)
	fmt.Printf("   Duration: %s\n", stats.Duration().Round(time.Second))
	fmt.Printf("   Rate: %.0f pkt/s\n", stats.PacketsPerSecond())

	// Print database stats
	if dbStats, err := store.GetStats(); err == nil {
		fmt.Println("\n📊 Database Statistics:")
		fmt.Printf("   DNS packets stored: %v\n", dbStats["dns_packets"])
		fmt.Printf("   Threats detected: %v\n", dbStats["threats"])
	}

	return nil
}

func processPackets(packets <-chan gopacket.Packet, dnsParser *parser.DNSParser, dnsDetector *detector.DNSHijackDetector, store *storage.Store, dnsProcessed, dnsErrors, threatsDetected *uint64) {
	for packet := range packets {
		// Try to parse as DNS
		dnsPkt, err := dnsParser.Parse(packet)
		if err != nil {
			atomic.AddUint64(dnsErrors, 1)
			log.Debug().Err(err).Msg("Failed to parse DNS packet")
			continue
		}

		atomic.AddUint64(dnsProcessed, 1)

		// Store in database
		if err := store.SaveDNSPacket(dnsPkt); err != nil {
			log.Warn().Err(err).Msg("Failed to save DNS packet")
			continue
		}

		// Run threat detection
		threat, err := dnsDetector.Detect(dnsPkt)
		if err != nil {
			log.Debug().Err(err).Msg("Detection error")
		}

		// If threat detected
		if threat != nil {
			atomic.AddUint64(threatsDetected, 1)

			// Save threat to database
			if err := store.SaveThreat(threat); err != nil {
				log.Warn().Err(err).Msg("Failed to save threat")
			}

			// Print colored alert
			printThreatAlert(threat)
		} else {
			// Print normal DNS info (only for responses, and only if no threat)
			if dnsPkt.IsResponse {
				ips := ""
				if len(dnsPkt.ResponseIPs) > 0 {
					ips = dnsPkt.ResponseIPs[0].String()
					if len(dnsPkt.ResponseIPs) > 1 {
						ips += fmt.Sprintf(" (+%d more)", len(dnsPkt.ResponseIPs)-1)
					}
				}

				cname := ""
				if dnsPkt.ResponseCNAME != "" {
					cname = fmt.Sprintf(" → %s", dnsPkt.ResponseCNAME)
				}

				fmt.Printf("[%s] DNS %s: %s = %s%s (TTL: %ds, %s)\n",
					dnsPkt.Timestamp.Format("15:04:05"),
					dnsPkt.TypeString(),
					dnsPkt.QueryDomain,
					ips,
					cname,
					dnsPkt.TTL,
					dnsPkt.RCodeString(),
				)
			}
		}
	}
}

func printThreatAlert(threat *types.Threat) {
	color := types.SeverityColor(threat.Severity)
	reset := types.ColorReset()

	icon := "⚠️ "
	if threat.Severity == types.SeverityCritical {
		icon = "🚨 "
	} else if threat.Severity == types.SeverityHigh {
		icon = "⚠️  "
	}

	fmt.Printf("\n%s%s%s THREAT DETECTED%s\n", color, icon, threat.Severity, reset)
	fmt.Printf("%s   Type: %s%s\n", color, threat.Type, reset)
	fmt.Printf("%s   Target: %s%s\n", color, threat.Target, reset)
	fmt.Printf("%s   Confidence: %d/100%s\n", color, threat.Confidence, reset)
	fmt.Printf("%s   Source: %s%s\n", color, threat.Source.String(), reset)

	// Print key details
	if threat.Details != nil {
		if unexpectedServer, ok := threat.Details["unexpected_server"]; ok {
			fmt.Printf("%s   Unexpected DNS Server: %v%s\n", color, unexpectedServer, reset)
		}
		if unexpectedIP, ok := threat.Details["unexpected_ip"]; ok {
			fmt.Printf("%s   Unexpected IP: %v%s\n", color, unexpectedIP, reset)
			if expectedIPs, ok := threat.Details["expected_ips"]; ok {
				fmt.Printf("%s   Expected IPs: %v%s\n", color, expectedIPs, reset)
			}
		}
		if lowTTL, ok := threat.Details["low_ttl"]; ok {
			fmt.Printf("%s   Suspiciously Low TTL: %vs%s\n", color, lowTTL, reset)
		}
		if privateIP, ok := threat.Details["private_ip_for_public_domain"]; ok && privateIP == true {
			fmt.Printf("%s   Private IP for Public Domain!%s\n", color, reset)
		}
	}

	fmt.Printf("%s   Time: %s%s\n\n", color, threat.Timestamp.Format("15:04:05"), reset)
}

func runThreats(cmd *cobra.Command, args []string) error {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Open database
	store, err := storage.New(cfg.Storage.Path)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer store.Close()

	// Get flags
	limit, _ := cmd.Flags().GetInt("limit")
	threatType, _ := cmd.Flags().GetString("type")
	severity, _ := cmd.Flags().GetString("severity")
	all, _ := cmd.Flags().GetBool("all")
	jsonOutput, _ := cmd.Flags().GetBool("json")

	if all {
		limit = -1 // No limit
	}

	// Retrieve threats
	var threats []*types.Threat

	if threatType != "" {
		threats, err = store.GetThreatsByType(threatType, limit)
	} else {
		threats, err = store.GetRecentThreats(limit)
	}

	if err != nil {
		return fmt.Errorf("failed to query threats: %w", err)
	}

	// Filter by severity if specified
	if severity != "" {
		filtered := make([]*types.Threat, 0)
		for _, t := range threats {
			if t.Severity == severity {
				filtered = append(filtered, t)
			}
		}
		threats = filtered
	}

	// Output
	if jsonOutput {
		// JSON output
		fmt.Println("[")
		for i, threat := range threats {
			jsonBytes, _ := json.Marshal(threat)
			fmt.Print(string(jsonBytes))
			if i < len(threats)-1 {
				fmt.Println(",")
			} else {
				fmt.Println()
			}
		}
		fmt.Println("]")
	} else {
		// Pretty formatted output
		if len(threats) == 0 {
			fmt.Println("No threats found.")
			return nil
		}

		fmt.Printf("\n🚨 Found %d threat(s)\n", len(threats))
		fmt.Println(strings.Repeat("=", 80))

		for i, threat := range threats {
			color := types.SeverityColor(threat.Severity)
			reset := types.ColorReset()

			icon := "⚠️ "
			if threat.Severity == types.SeverityCritical {
				icon = "🚨 "
			} else if threat.Severity == types.SeverityHigh {
				icon = "⚠️  "
			}

			fmt.Printf("\n%s%s#%d - %s %s%s\n", color, icon, i+1, threat.Type, threat.Severity, reset)
			fmt.Printf("%sTarget:     %s%s\n", color, threat.Target, reset)
			fmt.Printf("%sSource:     %s%s\n", color, threat.Source.String(), reset)
			fmt.Printf("%sConfidence: %d/100%s\n", color, threat.Confidence, reset)
			fmt.Printf("%sTime:       %s%s\n", color, threat.Timestamp.Format("2006-01-02 15:04:05"), reset)

			// Show details
			if threat.Details != nil && len(threat.Details) > 0 {
				fmt.Printf("%sDetails:%s\n", color, reset)
				for key, value := range threat.Details {
					fmt.Printf("%s  - %s: %v%s\n", color, key, value, reset)
				}
			}

			if i < len(threats)-1 {
				fmt.Println(strings.Repeat("-", 80))
			}
		}

		fmt.Println(strings.Repeat("=", 80))
		fmt.Println()
	}

	return nil
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
