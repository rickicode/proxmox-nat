package models

import (
	"time"
)

// Config represents the application configuration
type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Network  NetworkConfig  `yaml:"network"`
	Storage  StorageConfig  `yaml:"storage"`
	Security SecurityConfig `yaml:"security"`
}

// ServerConfig contains server-related configuration
type ServerConfig struct {
	ListenAddr string `yaml:"listen_addr"`
	Username   string `yaml:"username"`
	Password   string `yaml:"password"`
}

// NetworkConfig contains network-related configuration
type NetworkConfig struct {
	PublicInterface string    `yaml:"public_interface"`
	InternalBridge  string    `yaml:"internal_bridge"`
	PortRange       PortRange `yaml:"port_range"`
}

// PortRange defines allowed port range for forwarding
type PortRange struct {
	Min     int   `yaml:"min"`
	Max     int   `yaml:"max"`
	Exclude []int `yaml:"exclude"`
}

// StorageConfig contains storage-related configuration
type StorageConfig struct {
	RulesFile       string `yaml:"rules_file"`
	BackupEnabled   bool   `yaml:"backup_enabled"`
	BackupDir       string `yaml:"backup_dir"`
	BackupRetention int    `yaml:"backup_retention"`
	AutoBackup      bool   `yaml:"auto_backup"`
	DailyBackup     bool   `yaml:"daily_backup"`
}

// SecurityConfig contains security-related configuration
type SecurityConfig struct {
	CSRFEnabled bool `yaml:"csrf_enabled"`
	RateLimit   int  `yaml:"rate_limit"`
}

// Rule represents a DNAT port forwarding rule
type Rule struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	ExternalPort int       `json:"external_port"`
	InternalIP   string    `json:"internal_ip"`
	InternalPort int       `json:"internal_port"`
	Protocol     string    `json:"protocol"` // tcp, udp, both
	Enabled      bool      `json:"enabled"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// RulesData represents the complete rules storage structure
type RulesData struct {
	Rules     []Rule                 `json:"rules"`
	Metadata  map[string]interface{} `json:"metadata"`
	UpdatedAt time.Time              `json:"updated_at"`
}

// VM represents a virtual machine or container
type VM struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Type   string `json:"type"` // qemu, lxc
	Status string `json:"status"`
	IP     string `json:"ip"`
	Source string `json:"source"` // agent, arp, manual
	Node   string `json:"node"`
}

// SystemStatus represents the current system status
type SystemStatus struct {
	NATEnabled       bool   `json:"nat_enabled"`
	IPForwardEnabled bool   `json:"ip_forward_enabled"`
	PublicInterface  string `json:"public_interface"`
	InternalBridge   string `json:"internal_bridge"`
	RulesCount       int    `json:"rules_count"`
	ActiveRules      int    `json:"active_rules"`
	Uptime           string `json:"uptime"`
}

// BackupMetadata represents backup file metadata
type BackupMetadata struct {
	Timestamp  time.Time `json:"timestamp"`
	Version    string    `json:"version"`
	Hostname   string    `json:"hostname"`
	RulesCount int       `json:"rules_count"`
	FileSize   int64     `json:"file_size"`
	Checksum   string    `json:"checksum"`
}

// BackupData represents complete backup data structure
type BackupData struct {
	Metadata      BackupMetadata `json:"metadata"`
	NetworkConfig NetworkConfig  `json:"network_config"`
	Rules         []Rule         `json:"rules"`
}

// APIResponse represents standard API response format
type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// ValidationError represents validation errors
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// DryRunResult represents dry-run operation result
type DryRunResult struct {
	Changes   []string `json:"changes"`
	Additions []Rule   `json:"additions"`
	Deletions []Rule   `json:"deletions"`
	Conflicts []string `json:"conflicts"`
}

// ValidationResult represents rule validation and cleanup result
type ValidationResult struct {
	TotalRules int      `json:"total_rules"`
	ValidRules int      `json:"valid_rules"`
	FixedRules int      `json:"fixed_rules"`
	Errors     []string `json:"errors"`
	Warnings   []string `json:"warnings"`
}

// OrphanCleanupResult represents the result of orphaned rules cleanup
type OrphanCleanupResult struct {
	TotalRules     int    `json:"total_rules"`
	OrphanedRules  []Rule `json:"orphaned_rules"`
	RemainingRules []Rule `json:"remaining_rules"`
	RemovedCount   int    `json:"removed_count"`
	DryRun         bool   `json:"dry_run"`
}

// NetworkTraffic represents real-time network traffic data
type NetworkTraffic struct {
	Interface         string           `json:"interface"`
	RXBytes           int64            `json:"rx_bytes"`
	TXBytes           int64            `json:"tx_bytes"`
	RXPackets         int64            `json:"rx_packets"`
	TXPackets         int64            `json:"tx_packets"`
	RXRate            float64          `json:"rx_rate"` // bytes per second
	TXRate            float64          `json:"tx_rate"` // bytes per second
	ActiveConnections int              `json:"active_connections"`
	PortUsage         map[string]int   `json:"port_usage"` // port -> connection count
	TopPorts          []PortConnection `json:"top_ports"`  // top 5 ports by connections
	Timestamp         time.Time        `json:"timestamp"`
}

// PortConnection represents port usage information
type PortConnection struct {
	Port        string `json:"port"`
	Protocol    string `json:"protocol"`
	Connections int    `json:"connections"`
	Description string `json:"description"`
}

// NetworkStats represents overall network statistics
type NetworkStats struct {
	TotalTraffic   NetworkTraffic   `json:"total_traffic"`
	InterfaceStats []NetworkTraffic `json:"interface_stats"`
	ActiveRules    int              `json:"active_rules"`
	TotalRules     int              `json:"total_rules"`
	LastUpdated    time.Time        `json:"last_updated"`
}
