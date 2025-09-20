package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

// CleanupDuplicateRules removes duplicate port rules (keeping the first one)
func (s *Storage) CleanupDuplicateRules() (int, error) {
	rulesData, err := s.LoadRules()
	if err != nil {
		return 0, err
	}

	// Map to track seen port/protocol combinations
	seen := make(map[string]bool)
	var cleanRules []models.Rule
	duplicatesRemoved := 0

	for _, rule := range rulesData.Rules {
		key := fmt.Sprintf("%d-%s", rule.ExternalPort, rule.Protocol)

		if !seen[key] {
			// First occurrence, keep it
			seen[key] = true
			cleanRules = append(cleanRules, rule)
		} else {
			// Duplicate found, skip it
			duplicatesRemoved++
			fmt.Printf("Removed duplicate rule: %s (port %d/%s)\n", rule.Name, rule.ExternalPort, rule.Protocol)
		}
	}

	// Update rules if duplicates were found
	if duplicatesRemoved > 0 {
		rulesData.Rules = cleanRules
		if err := s.SaveRules(rulesData); err != nil {
			return 0, err
		}
	}

	return duplicatesRemoved, nil
}

// ValidateAndFixRules validates all rules and fixes common issues
func (s *Storage) ValidateAndFixRules() (*models.ValidationResult, error) {
	rulesData, err := s.LoadRules()
	if err != nil {
		return nil, err
	}

	result := &models.ValidationResult{
		TotalRules: len(rulesData.Rules),
		ValidRules: 0,
		FixedRules: 0,
		Errors:     []string{},
		Warnings:   []string{},
	}

	var validRules []models.Rule

	for i, rule := range rulesData.Rules {
		fixed := false

		// Validate and fix rule name
		if rule.Name == "" {
			rule.Name = fmt.Sprintf("Rule-%d", i+1)
			fixed = true
			result.Warnings = append(result.Warnings, fmt.Sprintf("Fixed missing name for rule at index %d", i))
		}

		// Validate ports
		if rule.ExternalPort < 1 || rule.ExternalPort > 65535 {
			result.Errors = append(result.Errors, fmt.Sprintf("Invalid external port %d for rule '%s'", rule.ExternalPort, rule.Name))
			continue
		}

		if rule.InternalPort < 1 || rule.InternalPort > 65535 {
			result.Errors = append(result.Errors, fmt.Sprintf("Invalid internal port %d for rule '%s'", rule.InternalPort, rule.Name))
			continue
		}

		// Validate IP address
		if rule.InternalIP == "" {
			result.Errors = append(result.Errors, fmt.Sprintf("Missing internal IP for rule '%s'", rule.Name))
			continue
		}

		// Validate protocol
		if rule.Protocol != "tcp" && rule.Protocol != "udp" && rule.Protocol != "both" {
			rule.Protocol = "tcp" // Default to TCP
			fixed = true
			result.Warnings = append(result.Warnings, fmt.Sprintf("Fixed invalid protocol for rule '%s', set to TCP", rule.Name))
		}

		// Ensure timestamps exist
		if rule.CreatedAt.IsZero() {
			rule.CreatedAt = time.Now()
			fixed = true
		}
		if rule.UpdatedAt.IsZero() {
			rule.UpdatedAt = time.Now()
			fixed = true
		}

		// Generate ID if missing
		if rule.ID == "" {
			rule.ID = fmt.Sprintf("rule-%d", time.Now().Unix()+int64(i))
			fixed = true
			result.Warnings = append(result.Warnings, fmt.Sprintf("Generated missing ID for rule '%s'", rule.Name))
		}

		if fixed {
			result.FixedRules++
		}

		validRules = append(validRules, rule)
		result.ValidRules++
	}

	// Save if any rules were fixed
	if result.FixedRules > 0 {
		rulesData.Rules = validRules
		if err := s.SaveRules(rulesData); err != nil {
			return result, err
		}
	}

	return result, nil
}

// GetFilePath returns the rules file path
func (s *Storage) GetFilePath() string {
	return s.filePath
}

// DetectOrphanedRules detects rules pointing to non-existent VMs
func (s *Storage) DetectOrphanedRules(activeVMIPs []string) ([]models.Rule, error) {
	rulesData, err := s.LoadRules()
	if err != nil {
		return nil, err
	}

	// Create map of active IPs for faster lookup
	activeIPMap := make(map[string]bool)
	for _, ip := range activeVMIPs {
		activeIPMap[ip] = true
	}

	var orphanedRules []models.Rule
	for _, rule := range rulesData.Rules {
		// Check if rule's internal IP is still active
		if !activeIPMap[rule.InternalIP] {
			orphanedRules = append(orphanedRules, rule)
		}
	}

	return orphanedRules, nil
}

// RemoveOrphanedRules removes rules pointing to non-existent VMs with smart detection
func (s *Storage) RemoveOrphanedRules(activeVMIPs []string, allVMIDs []string, dryRun bool) (*models.OrphanCleanupResult, error) {
	rulesData, err := s.LoadRules()
	if err != nil {
		return nil, err
	}

	// Create maps for faster lookup
	activeIPMap := make(map[string]bool)
	for _, ip := range activeVMIPs {
		activeIPMap[ip] = true
	}

	activeVMMap := make(map[string]bool)
	for _, vmid := range allVMIDs {
		activeVMMap[vmid] = true
	}

	result := &models.OrphanCleanupResult{
		TotalRules:     len(rulesData.Rules),
		OrphanedRules:  []models.Rule{},
		RemainingRules: []models.Rule{},
		RemovedCount:   0,
		DryRun:         dryRun,
	}

	for _, rule := range rulesData.Rules {
		isOrphaned := false

		// Check if rule points to an IP that's no longer active
		if !activeIPMap[rule.InternalIP] {
			// Additional check: is this IP in private range and could be valid?
			if s.isPrivateIP(rule.InternalIP) {
				// Check if this rule was created for a VM that still exists but without guest agent
				// Look for patterns like "VM 100", "CT 101", etc. in rule name
				if !s.isRuleForExistingVM(rule, activeVMMap) {
					// This is likely an orphaned rule - VM deleted
					isOrphaned = true
				}
				// Else: VM exists but no IP detected (no guest agent) - keep rule
			} else {
				// Non-private IP or invalid IP - likely orphaned
				isOrphaned = true
			}
		}

		if isOrphaned {
			result.OrphanedRules = append(result.OrphanedRules, rule)
			result.RemovedCount++
		} else {
			result.RemainingRules = append(result.RemainingRules, rule)
		}
	}

	// If not a dry run, actually remove orphaned rules
	if !dryRun && result.RemovedCount > 0 {
		rulesData.Rules = result.RemainingRules
		if err := s.SaveRules(rulesData); err != nil {
			return result, err
		}
	}

	return result, nil
}

// isPrivateIP checks if an IP address is in private range
func (s *Storage) isPrivateIP(ipStr string) bool {
	// Simple check for private IP ranges
	if ipStr == "" {
		return false
	}

	// Private ranges: 10.x.x.x, 172.16-31.x.x, 192.168.x.x
	if strings.HasPrefix(ipStr, "10.") ||
		strings.HasPrefix(ipStr, "192.168.") ||
		(strings.HasPrefix(ipStr, "172.") && len(ipStr) > 4) {
		return true
	}

	return false
}

// isRuleForExistingVM checks if rule name contains VM/CT ID that still exists
func (s *Storage) isRuleForExistingVM(rule models.Rule, activeVMMap map[string]bool) bool {
	// Look for patterns like "VM 100", "CT 101", "(100)", etc. in rule name
	ruleName := strings.ToLower(rule.Name)

	// Extract potential VM/CT IDs from rule name
	for vmid := range activeVMMap {
		// Check various patterns
		patterns := []string{
			"vm " + vmid,
			"ct " + vmid,
			"(" + vmid + ")",
			"vm" + vmid,
			"ct" + vmid,
			vmid + ")", // For patterns like "webserver (100)"
		}

		for _, pattern := range patterns {
			if strings.Contains(ruleName, pattern) {
				return true
			}
		}
	}

	return false
}

// GetRulesByIP returns all rules pointing to a specific IP
func (s *Storage) GetRulesByIP(targetIP string) ([]models.Rule, error) {
	rulesData, err := s.LoadRules()
	if err != nil {
		return nil, err
	}

	var matchingRules []models.Rule
	for _, rule := range rulesData.Rules {
		if rule.InternalIP == targetIP {
			matchingRules = append(matchingRules, rule)
		}
	}

	return matchingRules, nil
}
