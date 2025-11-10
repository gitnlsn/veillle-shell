package detector

import (
	"github.com/nlsn-pcap-monitor/nlsn-monitor/pkg/types"
)

// Detector is the interface for all detectors
type Detector interface {
	Name() string
	Type() string
	Detect(packet interface{}) (*types.Threat, error)
}

// DetectorConfig holds configuration for detectors
type DetectorConfig struct {
	MinConfidence int
	Enabled       bool
}
