package backup

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"proxmox-nat/internal/models"
	"proxmox-nat/internal/storage"

	"github.com/robfig/cron/v3"
)

// Manager handles backup and restore operations
type Manager struct {
	config   *models.Config
	storage  *storage.Storage
	cron     *cron.Cron
	hostname string
}

// New creates a new backup manager
func New(config *models.Config, storage *storage.Storage) (*Manager, error) {
	// Get hostname
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	// Ensure backup directory exists
	if config.Storage.BackupEnabled {
		if err := os.MkdirAll(config.Storage.BackupDir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create backup directory: %w", err)
		}
	}

	return &Manager{
		config:   config,
		storage:  storage,
		hostname: hostname,
		cron:     cron.New(),
	}, nil
}

// SetStorage sets the storage instance
func (m *Manager) SetStorage(storage *storage.Storage) {
	m.storage = storage
}

// StartScheduler starts the backup scheduler
func (m *Manager) StartScheduler() error {
	if !m.config.Storage.BackupEnabled {
		return nil
	}

	// Schedule daily backup at 2:00 AM
	if m.config.Storage.DailyBackup {
		_, err := m.cron.AddFunc("0 2 * * *", func() {
			if err := m.CreateAutoBackup("daily"); err != nil {
				fmt.Printf("Daily backup failed: %v\n", err)
			}
		})
		if err != nil {
			return fmt.Errorf("failed to schedule daily backup: %w", err)
		}
	}

	m.cron.Start()
	fmt.Println("Backup scheduler started")
	return nil
}

// StopScheduler stops the backup scheduler
func (m *Manager) StopScheduler() {
	if m.cron != nil {
		m.cron.Stop()
		fmt.Println("Backup scheduler stopped")
	}
}

// CreateBackup creates a manual backup
func (m *Manager) CreateBackup(name string) (*models.BackupMetadata, error) {
	if !m.config.Storage.BackupEnabled {
		return nil, fmt.Errorf("backup is disabled")
	}

	return m.createBackup(name, "manual")
}

// CreateAutoBackup creates an automatic backup
func (m *Manager) CreateAutoBackup(trigger string) error {
	if !m.config.Storage.BackupEnabled {
		return nil
	}

	_, err := m.createBackup("", trigger)
	return err
}

// createBackup creates a backup with specified name and trigger
func (m *Manager) createBackup(name, trigger string) (*models.BackupMetadata, error) {
	if m.storage == nil {
		return nil, fmt.Errorf("storage not initialized")
	}

	// Load current rules
	rulesData, err := m.storage.LoadRules()
	if err != nil {
		return nil, fmt.Errorf("failed to load rules: %w", err)
	}

	// Generate backup filename
	timestamp := time.Now()
	filename := fmt.Sprintf("backup_%s_%s.json",
		timestamp.Format("20060102_150405"),
		trigger)

	if name != "" {
		filename = fmt.Sprintf("backup_%s_%s_%s.json",
			timestamp.Format("20060102_150405"),
			name,
			trigger)
	}

	backupPath := filepath.Join(m.config.Storage.BackupDir, filename)

	// Create backup data
	backupData := models.BackupData{
		Metadata: models.BackupMetadata{
			Timestamp:  timestamp,
			Version:    "1.0.0",
			Hostname:   m.hostname,
			RulesCount: len(rulesData.Rules),
		},
		NetworkConfig: m.config.Network,
		Rules:         rulesData.Rules,
	}

	// Marshal backup data
	data, err := json.MarshalIndent(backupData, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal backup data: %w", err)
	}

	// Calculate checksum
	hash := sha256.Sum256(data)
	backupData.Metadata.Checksum = fmt.Sprintf("%x", hash)
	backupData.Metadata.FileSize = int64(len(data))

	// Re-marshal with checksum
	data, err = json.MarshalIndent(backupData, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal backup data with checksum: %w", err)
	}

	// Write backup file
	if err := os.WriteFile(backupPath, data, 0644); err != nil {
		return nil, fmt.Errorf("failed to write backup file: %w", err)
	}

	fmt.Printf("Backup created: %s (%d rules)\n", filename, len(rulesData.Rules))

	// Clean up old backups
	if err := m.cleanupOldBackups(); err != nil {
		fmt.Printf("Warning: Failed to cleanup old backups: %v\n", err)
	}

	return &backupData.Metadata, nil
}

// ListBackups lists available backup files
func (m *Manager) ListBackups() ([]models.BackupMetadata, error) {
	if !m.config.Storage.BackupEnabled {
		return nil, fmt.Errorf("backup is disabled")
	}

	files, err := os.ReadDir(m.config.Storage.BackupDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read backup directory: %w", err)
	}

	var backups []models.BackupMetadata
	for _, file := range files {
		if file.IsDir() || !strings.HasPrefix(file.Name(), "backup_") || !strings.HasSuffix(file.Name(), ".json") {
			continue
		}

		filePath := filepath.Join(m.config.Storage.BackupDir, file.Name())
		metadata, err := m.getBackupMetadata(filePath)
		if err != nil {
			fmt.Printf("Warning: Failed to read backup metadata for %s: %v\n", file.Name(), err)
			continue
		}

		backups = append(backups, *metadata)
	}

	// Sort by timestamp (newest first)
	sort.Slice(backups, func(i, j int) bool {
		return backups[i].Timestamp.After(backups[j].Timestamp)
	})

	return backups, nil
}

// getBackupMetadata reads metadata from backup file
func (m *Manager) getBackupMetadata(filePath string) (*models.BackupMetadata, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var backupData models.BackupData
	if err := json.Unmarshal(data, &backupData); err != nil {
		return nil, err
	}

	// Update file size if not set
	if backupData.Metadata.FileSize == 0 {
		backupData.Metadata.FileSize = int64(len(data))
	}

	return &backupData.Metadata, nil
}

// RestoreBackup restores from a backup file
func (m *Manager) RestoreBackup(backupPath string, preview bool) (*models.DryRunResult, error) {
	if m.storage == nil {
		return nil, fmt.Errorf("storage not initialized")
	}

	// Read backup file
	data, err := os.ReadFile(backupPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read backup file: %w", err)
	}

	var backupData models.BackupData
	if err := json.Unmarshal(data, &backupData); err != nil {
		return nil, fmt.Errorf("invalid backup file format: %w", err)
	}

	// Validate checksum if present
	if backupData.Metadata.Checksum != "" {
		// Calculate checksum of the data as it was when the backup was created
		// The checksum was calculated on the JSON without the checksum field
		validationData := backupData
		validationData.Metadata.Checksum = ""
		validationData.Metadata.FileSize = 0

		// Marshal in the same way as during backup creation
		tempData, err := json.MarshalIndent(validationData, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("failed to marshal validation data: %w", err)
		}

		// Calculate hash
		hash := sha256.Sum256(tempData)
		expectedChecksum := fmt.Sprintf("%x", hash)

		if backupData.Metadata.Checksum != expectedChecksum {
			return nil, fmt.Errorf("backup file checksum mismatch")
		}
	}

	// Load current rules for comparison
	currentRules, err := m.storage.LoadRules()
	if err != nil {
		return nil, fmt.Errorf("failed to load current rules: %w", err)
	}

	// Generate dry-run result
	result := &models.DryRunResult{
		Changes:   []string{},
		Additions: []models.Rule{},
		Deletions: []models.Rule{},
		Conflicts: []string{},
	}

	// Compare rules
	currentRuleMap := make(map[string]models.Rule)
	for _, rule := range currentRules.Rules {
		currentRuleMap[rule.ID] = rule
	}

	backupRuleMap := make(map[string]models.Rule)
	for _, rule := range backupData.Rules {
		backupRuleMap[rule.ID] = rule
	}

	// Find additions and modifications
	for _, backupRule := range backupData.Rules {
		if currentRule, exists := currentRuleMap[backupRule.ID]; exists {
			if !rulesEqual(currentRule, backupRule) {
				result.Changes = append(result.Changes,
					fmt.Sprintf("Modify rule %s (%s:%d -> %s:%d)",
						backupRule.ID, backupRule.InternalIP, backupRule.InternalPort,
						backupRule.InternalIP, backupRule.InternalPort))
			}
		} else {
			result.Additions = append(result.Additions, backupRule)
			result.Changes = append(result.Changes,
				fmt.Sprintf("Add rule %s (%s:%d)",
					backupRule.ID, backupRule.InternalIP, backupRule.InternalPort))
		}
	}

	// Find deletions
	for _, currentRule := range currentRules.Rules {
		if _, exists := backupRuleMap[currentRule.ID]; !exists {
			result.Deletions = append(result.Deletions, currentRule)
			result.Changes = append(result.Changes,
				fmt.Sprintf("Delete rule %s (%s:%d)",
					currentRule.ID, currentRule.InternalIP, currentRule.InternalPort))
		}
	}

	// If preview mode, return without applying changes
	if preview {
		return result, nil
	}

	// Apply restore (create backup first if auto-backup is enabled)
	if m.config.Storage.AutoBackup {
		if err := m.CreateAutoBackup("pre-restore"); err != nil {
			fmt.Printf("Warning: Failed to create pre-restore backup: %v\n", err)
		}
	}

	// Save restored rules
	restoredData := &models.RulesData{
		Rules:     backupData.Rules,
		Metadata:  make(map[string]interface{}),
		UpdatedAt: time.Now(),
	}

	if err := m.storage.SaveRules(restoredData); err != nil {
		return nil, fmt.Errorf("failed to save restored rules: %w", err)
	}

	fmt.Printf("Restored %d rules from backup\n", len(backupData.Rules))
	return result, nil
}

// cleanupOldBackups removes old backup files based on retention policy
func (m *Manager) cleanupOldBackups() error {
	if m.config.Storage.BackupRetention <= 0 {
		return nil // No cleanup if retention is 0 or negative
	}

	backups, err := m.ListBackups()
	if err != nil {
		return err
	}

	if len(backups) <= m.config.Storage.BackupRetention {
		return nil // No cleanup needed
	}

	// Remove old backups
	toRemove := len(backups) - m.config.Storage.BackupRetention
	for i := len(backups) - toRemove; i < len(backups); i++ {
		filename := fmt.Sprintf("backup_%s.json",
			backups[i].Timestamp.Format("20060102_150405"))
		filePath := filepath.Join(m.config.Storage.BackupDir, filename)

		if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
			fmt.Printf("Warning: Failed to remove old backup %s: %v\n", filename, err)
		}
	}

	fmt.Printf("Cleaned up %d old backup files\n", toRemove)
	return nil
}

// rulesEqual compares two rules for equality
func rulesEqual(a, b models.Rule) bool {
	return a.Name == b.Name &&
		a.ExternalPort == b.ExternalPort &&
		a.InternalIP == b.InternalIP &&
		a.InternalPort == b.InternalPort &&
		a.Protocol == b.Protocol &&
		a.Enabled == b.Enabled
}

// ExportBackup exports backup to a file
func (m *Manager) ExportBackup(backupPath, exportPath string) error {
	// Copy backup file to export location
	source, err := os.Open(backupPath)
	if err != nil {
		return fmt.Errorf("failed to open backup file: %w", err)
	}
	defer source.Close()

	dest, err := os.Create(exportPath)
	if err != nil {
		return fmt.Errorf("failed to create export file: %w", err)
	}
	defer dest.Close()

	_, err = io.Copy(dest, source)
	if err != nil {
		return fmt.Errorf("failed to copy backup file: %w", err)
	}

	return nil
}

// ImportBackup imports backup from external file
func (m *Manager) ImportBackup(importPath string) (*models.BackupMetadata, error) {
	// Validate import file
	data, err := os.ReadFile(importPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read import file: %w", err)
	}

	var backupData models.BackupData
	if err := json.Unmarshal(data, &backupData); err != nil {
		return nil, fmt.Errorf("invalid import file format: %w", err)
	}

	// Generate new backup filename
	timestamp := time.Now()
	filename := fmt.Sprintf("backup_%s_imported.json",
		timestamp.Format("20060102_150405"))

	backupPath := filepath.Join(m.config.Storage.BackupDir, filename)

	// Update metadata
	backupData.Metadata.Timestamp = timestamp
	backupData.Metadata.Hostname = m.hostname

	// Save as backup
	newData, err := json.MarshalIndent(backupData, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal imported backup: %w", err)
	}

	if err := os.WriteFile(backupPath, newData, 0644); err != nil {
		return nil, fmt.Errorf("failed to save imported backup: %w", err)
	}

	fmt.Printf("Imported backup: %s (%d rules)\n", filename, len(backupData.Rules))
	return &backupData.Metadata, nil
}
