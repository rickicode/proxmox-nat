package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"proxmox-nat/internal/models"
)

// Storage handles rules persistence
type Storage struct {
	filePath string
	mutex    sync.RWMutex
}

// New creates a new storage instance
func New(filePath string) (*Storage, error) {
	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
		return nil, fmt.Errorf("failed to create rules directory: %w", err)
	}

	s := &Storage{
		filePath: filePath,
	}

	// Initialize empty rules file if it doesn't exist
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		emptyRules := &models.RulesData{
			Rules:     []models.Rule{},
			Metadata:  make(map[string]interface{}),
			UpdatedAt: time.Now(),
		}
		if err := s.SaveRules(emptyRules); err != nil {
			return nil, fmt.Errorf("failed to initialize rules file: %w", err)
		}
		fmt.Printf("Initialized empty rules file at %s\n", filePath)
	}

	return s, nil
}

// LoadRules loads rules from storage
func (s *Storage) LoadRules() (*models.RulesData, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	data, err := os.ReadFile(s.filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read rules file: %w", err)
	}

	var rulesData models.RulesData
	if err := json.Unmarshal(data, &rulesData); err != nil {
		return nil, fmt.Errorf("failed to parse rules file: %w", err)
	}

	return &rulesData, nil
}

// SaveRules saves rules to storage
func (s *Storage) SaveRules(rulesData *models.RulesData) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	rulesData.UpdatedAt = time.Now()

	data, err := json.MarshalIndent(rulesData, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal rules: %w", err)
	}

	// Write to temporary file first, then rename for atomic operation
	tempFile := s.filePath + ".tmp"
	if err := os.WriteFile(tempFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write temporary rules file: %w", err)
	}

	if err := os.Rename(tempFile, s.filePath); err != nil {
		os.Remove(tempFile) // Clean up temp file
		return fmt.Errorf("failed to rename rules file: %w", err)
	}

	return nil
}

// AddRule adds a new rule
func (s *Storage) AddRule(rule models.Rule) error {
	rulesData, err := s.LoadRules()
	if err != nil {
		return err
	}

	// Check for duplicate external port and protocol
	for _, existingRule := range rulesData.Rules {
		if existingRule.ExternalPort == rule.ExternalPort &&
			existingRule.Protocol == rule.Protocol &&
			existingRule.Enabled {
			return fmt.Errorf("rule with external port %d (%s) already exists", rule.ExternalPort, rule.Protocol)
		}
	}

	// Set timestamps
	rule.CreatedAt = time.Now()
	rule.UpdatedAt = time.Now()

	// Add rule
	rulesData.Rules = append(rulesData.Rules, rule)

	return s.SaveRules(rulesData)
}

// UpdateRule updates an existing rule
func (s *Storage) UpdateRule(id string, updatedRule models.Rule) error {
	rulesData, err := s.LoadRules()
	if err != nil {
		return err
	}

	// Find and update rule
	found := false
	for i, rule := range rulesData.Rules {
		if rule.ID == id {
			// Check for duplicate external port (excluding current rule)
			for j, existingRule := range rulesData.Rules {
				if j != i &&
					existingRule.ExternalPort == updatedRule.ExternalPort &&
					existingRule.Protocol == updatedRule.Protocol &&
					existingRule.Enabled {
					return fmt.Errorf("rule with external port %d (%s) already exists", updatedRule.ExternalPort, updatedRule.Protocol)
				}
			}

			// Preserve created time, update modified time
			updatedRule.CreatedAt = rule.CreatedAt
			updatedRule.UpdatedAt = time.Now()
			updatedRule.ID = id

			rulesData.Rules[i] = updatedRule
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("rule with ID %s not found", id)
	}

	return s.SaveRules(rulesData)
}

// DeleteRule deletes a rule by ID
func (s *Storage) DeleteRule(id string) error {
	rulesData, err := s.LoadRules()
	if err != nil {
		return err
	}

	// Find and remove rule
	found := false
	for i, rule := range rulesData.Rules {
		if rule.ID == id {
			rulesData.Rules = append(rulesData.Rules[:i], rulesData.Rules[i+1:]...)
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("rule with ID %s not found", id)
	}

	return s.SaveRules(rulesData)
}

// GetRule gets a rule by ID
func (s *Storage) GetRule(id string) (*models.Rule, error) {
	rulesData, err := s.LoadRules()
	if err != nil {
		return nil, err
	}

	for _, rule := range rulesData.Rules {
		if rule.ID == id {
			return &rule, nil
		}
	}

	return nil, fmt.Errorf("rule with ID %s not found", id)
}

// GetEnabledRules returns only enabled rules
func (s *Storage) GetEnabledRules() ([]models.Rule, error) {
	rulesData, err := s.LoadRules()
	if err != nil {
		return nil, err
	}

	var enabledRules []models.Rule
	for _, rule := range rulesData.Rules {
		if rule.Enabled {
			enabledRules = append(enabledRules, rule)
		}
	}

	return enabledRules, nil
}

// ToggleRule toggles a rule's enabled status
func (s *Storage) ToggleRule(id string) error {
	rulesData, err := s.LoadRules()
	if err != nil {
		return err
	}

	found := false
	for i, rule := range rulesData.Rules {
		if rule.ID == id {
			rulesData.Rules[i].Enabled = !rule.Enabled
			rulesData.Rules[i].UpdatedAt = time.Now()
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("rule with ID %s not found", id)
	}

	return s.SaveRules(rulesData)
}

// GetRulesCount returns total and enabled rules count
func (s *Storage) GetRulesCount() (total int, enabled int, err error) {
	rulesData, err := s.LoadRules()
	if err != nil {
		return 0, 0, err
	}

	total = len(rulesData.Rules)
	for _, rule := range rulesData.Rules {
		if rule.Enabled {
			enabled++
		}
	}

	return total, enabled, nil
}

// BackupRules creates a backup of current rules
func (s *Storage) BackupRules(backupPath string) error {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	// Ensure backup directory exists
	if err := os.MkdirAll(filepath.Dir(backupPath), 0755); err != nil {
		return fmt.Errorf("failed to create backup directory: %w", err)
	}

	// Copy current rules file to backup location
	sourceData, err := os.ReadFile(s.filePath)
	if err != nil {
		return fmt.Errorf("failed to read source rules file: %w", err)
	}

	if err := os.WriteFile(backupPath, sourceData, 0644); err != nil {
		return fmt.Errorf("failed to write backup file: %w", err)
	}

	return nil
}

// RestoreRules restores rules from backup
func (s *Storage) RestoreRules(backupPath string) error {
	// Validate backup file
	backupData, err := os.ReadFile(backupPath)
	if err != nil {
		return fmt.Errorf("failed to read backup file: %w", err)
	}

	var rulesData models.RulesData
	if err := json.Unmarshal(backupData, &rulesData); err != nil {
		return fmt.Errorf("invalid backup file format: %w", err)
	}

	// Save as current rules
	return s.SaveRules(&rulesData)
}

// GetFilePath returns the rules file path
func (s *Storage) GetFilePath() string {
	return s.filePath
}
