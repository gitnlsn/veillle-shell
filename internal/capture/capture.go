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
	PacketsCaptured  uint64
	PacketsDropped   uint64
	PacketsIfDropped uint64
	BytesCaptured    uint64
	StartTime        time.Time
	LastPacketTime   time.Time
	mu               sync.RWMutex
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

// New creates a new packet capturer
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

// SetBPFFilter sets a BPF filter on the capture
func (c *Capturer) SetBPFFilter(filter string) error {
	if err := c.handle.SetBPFFilter(filter); err != nil {
		return fmt.Errorf("failed to set BPF filter: %w", err)
	}

	log.Info().Str("filter", filter).Msg("BPF filter applied")
	return nil
}

// Start begins packet capture
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

// captureLoop is the main capture goroutine
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

// Packets returns the channel of captured packets
func (c *Capturer) Packets() <-chan gopacket.Packet {
	return c.packetChan
}

// Stop stops packet capture
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

// Stats returns current capture statistics
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

// Duration returns how long capture has been running
func (s *Statistics) Duration() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return time.Since(s.StartTime)
}

// PacketsPerSecond returns the average packet capture rate
func (s *Statistics) PacketsPerSecond() float64 {
	s.mu.RLock()
	defer s.mu.RUnlock()

	duration := time.Since(s.StartTime).Seconds()
	if duration == 0 {
		return 0
	}

	return float64(s.PacketsCaptured) / duration
}
