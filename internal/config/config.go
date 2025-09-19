package config

import (
	"fmt"
	"os"
	"path/filepath"

	"proxmox-nat/internal/models"

	"gopkg.in/yaml.v3"
)

const (
	DefaultConfigPath  = "/etc/netnat/config.yml"
	FallbackConfigPath = "./configs/config.yml"
)

// Load loads configuration from default locations
func Load() (*models.Config, error) {
	// Try default system config path first
	if _, err := os.Stat(DefaultConfigPath); err == nil {
		return LoadFromFile(DefaultConfigPath)
	}

	// Try fallback config path
	if _, err := os.Stat(FallbackConfigPath); err == nil {
		return LoadFromFile(FallbackConfigPath)
	}

	// Create default config if none exists
	cfg := DefaultConfig()

	// Try to create config directory and save default config
	if err := ensureConfigDir(); err == nil {
		if err := SaveToFile(cfg, DefaultConfigPath); err == nil {
			fmt.Printf("Created default configuration at %s\n", DefaultConfigPath)
		}
	}

	return cfg, nil
}

// LoadFromFile loads configuration from specified file
func LoadFromFile(path string) (*models.Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", path, err)
	}

	var cfg models.Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file %s: %w", path, err)
	}

	// Validate configuration
	if err := validateConfig(&cfg); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	fmt.Printf("Loaded configuration from %s\n", path)
	return &cfg, nil
}

// SaveToFile saves configuration to specified file
func SaveToFile(cfg *models.Config, path string) error {
	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// DefaultConfig returns default configuration
func DefaultConfig() *models.Config {
	return &models.Config{
		Server: models.ServerConfig{
			ListenAddr: "127.0.0.1:9090",
			Username:   "netnat",
			Password:   "changeme",
		},
		Network: models.NetworkConfig{
			PublicInterface: "auto",
			InternalBridge:  "vmbr1",
			PortRange: models.PortRange{
				Min:     1,
				Max:     65535,
				Exclude: []int{22, 8006, 8007, 9090},
			},
		},
		Storage: models.StorageConfig{
			RulesFile:       "/etc/netnat/rules.json",
			BackupEnabled:   true,
			BackupDir:       "/etc/netnat/backups",
			BackupRetention: 30,
			AutoBackup:      true,
			DailyBackup:     true,
		},
		Security: models.SecurityConfig{
			CSRFEnabled: true,
			RateLimit:   60,
		},
	}
}

// validateConfig validates the configuration
func validateConfig(cfg *models.Config) error {
	if cfg.Server.ListenAddr == "" {
		return fmt.Errorf("server listen address cannot be empty")
	}

	if cfg.Server.Username == "" {
		return fmt.Errorf("server username cannot be empty")
	}

	if cfg.Server.Password == "" {
		return fmt.Errorf("server password cannot be empty")
	}

	if cfg.Network.InternalBridge == "" {
		return fmt.Errorf("internal bridge cannot be empty")
	}

	if cfg.Network.PortRange.Min < 1 || cfg.Network.PortRange.Min > 65535 {
		return fmt.Errorf("port range min must be between 1 and 65535")
	}

	if cfg.Network.PortRange.Max < 1 || cfg.Network.PortRange.Max > 65535 {
		return fmt.Errorf("port range max must be between 1 and 65535")
	}

	if cfg.Network.PortRange.Min > cfg.Network.PortRange.Max {
		return fmt.Errorf("port range min cannot be greater than max")
	}

	if cfg.Storage.RulesFile == "" {
		return fmt.Errorf("rules file path cannot be empty")
	}

	if cfg.Storage.BackupEnabled && cfg.Storage.BackupDir == "" {
		return fmt.Errorf("backup directory cannot be empty when backup is enabled")
	}

	if cfg.Security.RateLimit < 1 {
		return fmt.Errorf("rate limit must be at least 1")
	}

	return nil
}

// ensureConfigDir ensures the configuration directory exists
func ensureConfigDir() error {
	dir := filepath.Dir(DefaultConfigPath)
	return os.MkdirAll(dir, 0755)
}

// GetConfigPath returns the active configuration file path
func GetConfigPath() string {
	if _, err := os.Stat(DefaultConfigPath); err == nil {
		return DefaultConfigPath
	}
	return FallbackConfigPath
}

// Reload reloads configuration from the current config file
func Reload() (*models.Config, error) {
	return LoadFromFile(GetConfigPath())
}
