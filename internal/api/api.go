package api

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"proxmox-nat/internal/auth"
	"proxmox-nat/internal/backup"
	"proxmox-nat/internal/discovery"
	"proxmox-nat/internal/models"
	"proxmox-nat/internal/network"
	"proxmox-nat/internal/storage"
)

// API represents the API server
type API struct {
	config     *models.Config
	storage    *storage.Storage
	network    *network.Manager
	backup     *backup.Manager
	discovery  *discovery.VMDiscovery
	version    string
	jwtManager *auth.JWTManager
	csrfTokens map[string]time.Time
	csrfMutex  sync.RWMutex
}

// New creates a new API instance
func New(config *models.Config, storage *storage.Storage, network *network.Manager, backup *backup.Manager, version string) *API {
	// Generate JWT secret if not set
	jwtSecret := config.Server.JWTSecret
	if jwtSecret == "" {
		jwtSecret = "netnat-default-secret-change-in-production"
	}

	api := &API{
		config:     config,
		storage:    storage,
		network:    network,
		backup:     backup,
		version:    version,
		jwtManager: auth.NewJWTManager(jwtSecret, 24*time.Hour),
		csrfTokens: make(map[string]time.Time),
	}

	// Initialize VM discovery
	api.discovery = discovery.New(config.Network.InternalBridge)
	api.discovery.StartBackgroundDiscovery()

	// Start CSRF token cleanup goroutine
	go api.cleanupExpiredCSRFTokens()

	// Register VM update callback to refresh dynamic rules
	api.discovery.RegisterUpdateCallback(func(vms []models.VM) {
		// Define resolver
		resolver := func(vmid string) (string, error) {
			for _, vm := range vms {
				if vm.ID == vmid {
					return vm.IP, nil
				}
			}
			return "", fmt.Errorf("VM not found")
		}

		// Re-apply rules with new VM data
		rulesData, err := api.storage.LoadRules()
		if err == nil {
			if err := api.network.ApplyRules(rulesData.Rules, resolver); err != nil {
				fmt.Printf("Warning: Failed to refresh rules after VM update: %v\n", err)
			} else {
				fmt.Println("Refreshed NAT rules based on updated VM data")
			}
		}
	})

	return api
}

// cleanupExpiredCSRFTokens periodically removes expired CSRF tokens
func (a *API) cleanupExpiredCSRFTokens() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		a.csrfMutex.Lock()
		now := time.Now()
		for token, expiry := range a.csrfTokens {
			if now.After(expiry) {
				delete(a.csrfTokens, token)
			}
		}
		a.csrfMutex.Unlock()
	}
}

// findBackupFile is a helper function to find backup file by timestamp
func (a *API) findBackupFile(targetTimestamp string) (string, string, error) {
	backups, err := a.backup.ListBackups()
	if err != nil {
		return "", "", fmt.Errorf("failed to list backups: %v", err)
	}

	// Create map for O(1) lookup
	backupMap := make(map[string]string)
	for _, backup := range backups {
		key := backup.Timestamp.Format(time.RFC3339Nano)
		backupMap[key] = backup.Timestamp.Format("20060102_150405")
	}

	timestampPart, exists := backupMap[targetTimestamp]
	if !exists {
		return "", "", fmt.Errorf("backup not found for timestamp: %s", targetTimestamp)
	}

	// Single loop to find file
	files, err := os.ReadDir(a.config.Storage.BackupDir)
	if err != nil {
		return "", "", fmt.Errorf("failed to read backup directory: %v", err)
	}

	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".json") {
			continue
		}

		if strings.Contains(file.Name(), timestampPart) {
			backupPath := filepath.Join(a.config.Storage.BackupDir, file.Name())
			return backupPath, file.Name(), nil
		}
	}

	return "", "", fmt.Errorf("backup file not found for timestamp: %s", targetTimestamp)
}

// validateRule validates a rule before creating/updating
func (a *API) validateRule(rule models.Rule) error {
	if rule.ExternalPort < 1 || rule.ExternalPort > 65535 {
		return fmt.Errorf("external port must be between 1 and 65535")
	}

	if rule.InternalPort < 1 || rule.InternalPort > 65535 {
		return fmt.Errorf("internal port must be between 1 and 65535")
	}

	if rule.Protocol != "tcp" && rule.Protocol != "udp" && rule.Protocol != "both" {
		return fmt.Errorf("protocol must be tcp, udp, or both")
	}

	if rule.InternalIP == "" {
		return fmt.Errorf("internal IP is required")
	}

	return nil
}

// GetDiscovery returns the discovery module instance
func (a *API) GetDiscovery() *discovery.VMDiscovery {
	return a.discovery
}
