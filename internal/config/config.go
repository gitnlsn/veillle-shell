package config

import (
	"fmt"
	"os"
	"path/filepath"

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

// Load reads configuration from viper and returns a Config struct
func Load() (*Config, error) {
	// Set defaults
	viper.SetDefault("capture.interface", "auto")
	viper.SetDefault("capture.snaplen", 65535)
	viper.SetDefault("capture.promisc", true)
	viper.SetDefault("capture.buffer_size", 10485760)
	viper.SetDefault("capture.filter", "port 53")

	viper.SetDefault("detection.enabled", true)
	viper.SetDefault("detection.patterns_file", "patterns.yaml")
	viper.SetDefault("detection.min_confidence", 50)

	viper.SetDefault("storage.type", "sqlite")
	viper.SetDefault("storage.path", "~/.local/share/nlsn-pcap/nlsn.db")
	viper.SetDefault("storage.retention_days", 30)

	viper.SetDefault("logging.level", "info")
	viper.SetDefault("logging.file", "~/.local/share/nlsn-pcap/logs/nlsn.log")
	viper.SetDefault("logging.max_size_mb", 100)
	viper.SetDefault("logging.max_backups", 5)

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Expand paths
	cfg.Storage.Path = expandPath(cfg.Storage.Path)
	cfg.Logging.File = expandPath(cfg.Logging.File)

	return &cfg, nil
}

// expandPath expands ~ to home directory
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

// InitDirectories creates necessary directories for configuration and data
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

	// Create database directory if needed
	if cfg.Storage.Path != "" {
		dbDir := filepath.Dir(cfg.Storage.Path)
		if err := os.MkdirAll(dbDir, 0700); err != nil {
			return fmt.Errorf("could not create database directory: %w", err)
		}
	}

	return nil
}
