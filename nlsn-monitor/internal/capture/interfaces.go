package capture

import (
	"fmt"

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
