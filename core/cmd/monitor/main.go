package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

const (
	version = "0.1.0"
)

type Config struct {
	Interface   string
	Snaplen     int32
	Promiscuous bool
	Timeout     time.Duration
	RedisHost   string
	RedisPort   string
}

func main() {
	// Parse command line flags
	var (
		iface       = flag.String("interface", "", "Network interface to capture (empty for auto-detect)")
		snaplen     = flag.Int("snaplen", 65535, "Snapshot length")
		promiscuous = flag.Bool("promisc", true, "Enable promiscuous mode")
		showVersion = flag.Bool("version", false, "Show version")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("NLSN PCAP Monitor v%s\n", version)
		os.Exit(0)
	}

	// Load configuration
	config := Config{
		Interface:   *iface,
		Snaplen:     int32(*snaplen),
		Promiscuous: *promiscuous,
		Timeout:     pcap.BlockForever,
		RedisHost:   getEnv("REDIS_HOST", "localhost"),
		RedisPort:   getEnv("REDIS_PORT", "6379"),
	}

	// Auto-detect interface if not specified
	if config.Interface == "" {
		devices, err := pcap.FindAllDevs()
		if err != nil {
			log.Fatal("Error finding devices:", err)
		}

		// Find first non-loopback interface
		for _, device := range devices {
			if len(device.Addresses) > 0 && device.Name != "lo" {
				config.Interface = device.Name
				break
			}
		}

		if config.Interface == "" {
			log.Fatal("No suitable network interface found")
		}
	}

	log.Printf("Starting NLSN PCAP Monitor v%s", version)
	log.Printf("Capturing on interface: %s", config.Interface)
	log.Printf("Snapshot length: %d", config.Snaplen)
	log.Printf("Promiscuous mode: %t", config.Promiscuous)

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set up signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Start packet capture
	go func() {
		if err := startCapture(ctx, config); err != nil {
			log.Printf("Capture error: %v", err)
			cancel()
		}
	}()

	// Wait for shutdown signal
	sig := <-sigCh
	log.Printf("Received signal: %v, shutting down gracefully...", sig)
	cancel()

	// Give goroutines time to cleanup
	time.Sleep(2 * time.Second)
	log.Println("Shutdown complete")
}

func startCapture(ctx context.Context, config Config) error {
	// Open device for capturing
	handle, err := pcap.OpenLive(
		config.Interface,
		config.Snaplen,
		config.Promiscuous,
		config.Timeout,
	)
	if err != nil {
		return fmt.Errorf("error opening device: %w", err)
	}
	defer handle.Close()

	log.Println("Packet capture started")

	// Set filter for relevant traffic (DNS, HTTP, HTTPS, ARP)
	filter := "port 53 or port 80 or port 443 or arp"
	if err := handle.SetBPFFilter(filter); err != nil {
		return fmt.Errorf("error setting BPF filter: %w", err)
	}
	log.Printf("BPF filter applied: %s", filter)

	// Create packet source
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()

	// Packet processing loop
	packetCount := 0
	for {
		select {
		case <-ctx.Done():
			log.Printf("Stopping packet capture. Processed %d packets", packetCount)
			return nil

		case packet := <-packets:
			if packet == nil {
				continue
			}

			packetCount++

			// TODO: Process packet
			// For now, just log packet info periodically
			if packetCount%1000 == 0 {
				log.Printf("Processed %d packets", packetCount)
			}

			// This is where we'll:
			// 1. Parse packet (DNS, HTTP, TLS)
			// 2. Detect anomalies
			// 3. Publish events to Redis
		}
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
