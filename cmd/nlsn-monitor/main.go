package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/nlsn-pcap-monitor/nlsn-monitor/internal/capture"
	"github.com/nlsn-pcap-monitor/nlsn-monitor/internal/config"
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
	viper.BindPFlag("capture.interface", startCmd.Flags().Lookup("interface"))
	viper.BindPFlag("capture.snaplen", startCmd.Flags().Lookup("snaplen"))
	viper.BindPFlag("capture.promisc", startCmd.Flags().Lookup("promisc"))
	viper.BindPFlag("capture.filter", startCmd.Flags().Lookup("filter"))

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
	fmt.Println("🔍 NLSN Monitor v" + version + " - Network Security Monitor")
	fmt.Printf("📡 Capturing on interface: %s\n", iface)
	fmt.Printf("🎯 Filters: %s\n", cfg.Capture.Filter)
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

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
