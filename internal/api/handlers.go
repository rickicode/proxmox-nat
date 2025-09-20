package api

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"proxmox-nat/internal/backup"
	"proxmox-nat/internal/discovery"
	"proxmox-nat/internal/models"
	"proxmox-nat/internal/network"
	"proxmox-nat/internal/storage"
	"proxmox-nat/internal/web"

	"github.com/gin-gonic/gin"
)

// API represents the API server
type API struct {
	config    *models.Config
	storage   *storage.Storage
	network   *network.Manager
	backup    *backup.Manager
	discovery *discovery.VMDiscovery
}

// New creates a new API instance
func New(config *models.Config, storage *storage.Storage, network *network.Manager, backup *backup.Manager) *API {
	api := &API{
		config:  config,
		storage: storage,
		network: network,
		backup:  backup,
	}

	// Initialize VM discovery
	api.discovery = discovery.New(config.Network.InternalBridge)

	return api
}

// Handler returns the HTTP handler
func (a *API) Handler() http.Handler {
	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery())

	// Add middleware
	r.Use(a.corsMiddleware())
	r.Use(a.authMiddleware())
	r.Use(a.rateLimitMiddleware())

	// Static files from embedded filesystem
	r.StaticFS("/static", http.FS(web.GetStaticFS()))
	r.SetHTMLTemplate(web.LoadTemplates())

	// Web UI
	r.GET("/", a.indexHandler)

	// API routes
	api := r.Group("/api")
	{
		// CSRF protection for mutating operations
		mutating := api.Group("")
		mutating.Use(a.csrfMiddleware())

		// System status
		api.GET("/status", a.getSystemStatus)

		// Rules CRUD
		api.GET("/rules", a.getRules)
		api.GET("/rules/:id", a.getRule)
		mutating.POST("/rules", a.createRule)
		mutating.PUT("/rules/:id", a.updateRule)
		mutating.DELETE("/rules/:id", a.deleteRule)
		mutating.POST("/rules/:id/toggle", a.toggleRule)
		mutating.POST("/rules/cleanup", a.cleanupRules)

		// VM/CT discovery
		api.GET("/vms", a.getVMs)
		api.GET("/vms/:id", a.getVM)
		api.POST("/vms/refresh", a.refreshVMs)

		// Network operations
		mutating.POST("/nat/enable", a.enableNAT)
		mutating.POST("/nat/disable", a.disableNAT)
		mutating.POST("/forwarding/enable", a.enableForwarding)
		mutating.POST("/forwarding/disable", a.disableForwarding)

		// Backup operations
		api.GET("/backup/list", a.listBackups)
		mutating.POST("/backup/create", a.createBackup)
		mutating.POST("/backup/restore", a.restoreBackup)
		mutating.POST("/backup/import", a.importBackup)
		api.GET("/backup/export/:id", a.exportBackup)

		// Dry-run operations
		mutating.POST("/dry-run", a.dryRun)

		// CSRF token endpoint
		api.GET("/csrf-token", a.getCSRFToken)
	}

	return r
}

// indexHandler serves the main web UI
func (a *API) indexHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "index.html", gin.H{
		"title": "NetNAT - NAT & Port Forwarding Manager",
	})
}

// getSystemStatus returns current system status
func (a *API) getSystemStatus(c *gin.Context) {
	status, err := a.network.GetSystemStatus()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to get system status: %v", err),
		})
		return
	}

	// Add rules count
	total, active, err := a.storage.GetRulesCount()
	if err == nil {
		status.RulesCount = total
		status.ActiveRules = active
	}

	// Add uptime (placeholder - would be calculated from service start time)
	status.Uptime = "N/A"

	c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Data:    status,
	})
}

// getRules returns all rules
func (a *API) getRules(c *gin.Context) {
	rulesData, err := a.storage.LoadRules()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to load rules: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Data:    rulesData.Rules,
	})
}

// getRule returns a specific rule
func (a *API) getRule(c *gin.Context) {
	id := c.Param("id")
	rule, err := a.storage.GetRule(id)
	if err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Rule not found: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Data:    rule,
	})
}

// createRule creates a new rule
func (a *API) createRule(c *gin.Context) {
	var rule models.Rule
	if err := c.ShouldBindJSON(&rule); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Invalid request: %v", err),
		})
		return
	}

	// Validate rule
	if err := a.validateRule(rule); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Validation failed: %v", err),
		})
		return
	}

	// Generate ID
	rule.ID = fmt.Sprintf("rule-%d", time.Now().Unix())

	// Create backup if auto-backup is enabled
	if a.config.Storage.AutoBackup {
		if err := a.backup.CreateAutoBackup("pre-create"); err != nil {
			fmt.Printf("Warning: Failed to create backup: %v\n", err)
		}
	}

	// Add rule to storage
	if err := a.storage.AddRule(rule); err != nil {
		c.JSON(http.StatusConflict, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to add rule: %v", err),
		})
		return
	}

	// Apply rule if enabled
	if rule.Enabled {
		if err := a.network.AddDNATRule(rule); err != nil {
			fmt.Printf("Warning: Failed to apply rule: %v\n", err)
		}
	}

	c.JSON(http.StatusCreated, models.APIResponse{
		Success: true,
		Message: "Rule created successfully",
		Data:    rule,
	})
}

// updateRule updates an existing rule
func (a *API) updateRule(c *gin.Context) {
	id := c.Param("id")
	var updatedRule models.Rule
	if err := c.ShouldBindJSON(&updatedRule); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Invalid request: %v", err),
		})
		return
	}

	// Validate rule
	if err := a.validateRule(updatedRule); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Validation failed: %v", err),
		})
		return
	}

	// Get old rule for network cleanup
	oldRule, err := a.storage.GetRule(id)
	if err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{
			Success: false,
			Error:   "Rule not found",
		})
		return
	}

	// Create backup if auto-backup is enabled
	if a.config.Storage.AutoBackup {
		if err := a.backup.CreateAutoBackup("pre-update"); err != nil {
			fmt.Printf("Warning: Failed to create backup: %v\n", err)
		}
	}

	// Remove old network rule
	if oldRule.Enabled {
		if err := a.network.RemoveDNATRule(*oldRule); err != nil {
			fmt.Printf("Warning: Failed to remove old rule: %v\n", err)
		}
	}

	// Update rule in storage
	if err := a.storage.UpdateRule(id, updatedRule); err != nil {
		c.JSON(http.StatusConflict, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to update rule: %v", err),
		})
		return
	}

	// Apply new rule if enabled
	if updatedRule.Enabled {
		if err := a.network.AddDNATRule(updatedRule); err != nil {
			fmt.Printf("Warning: Failed to apply updated rule: %v\n", err)
		}
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Message: "Rule updated successfully",
		Data:    updatedRule,
	})
}

// deleteRule deletes a rule
func (a *API) deleteRule(c *gin.Context) {
	id := c.Param("id")

	// Get rule for network cleanup
	rule, err := a.storage.GetRule(id)
	if err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{
			Success: false,
			Error:   "Rule not found",
		})
		return
	}

	// Create backup if auto-backup is enabled
	if a.config.Storage.AutoBackup {
		if err := a.backup.CreateAutoBackup("pre-delete"); err != nil {
			fmt.Printf("Warning: Failed to create backup: %v\n", err)
		}
	}

	// Remove network rule
	if rule.Enabled {
		if err := a.network.RemoveDNATRule(*rule); err != nil {
			fmt.Printf("Warning: Failed to remove network rule: %v\n", err)
		}
	}

	// Delete from storage
	if err := a.storage.DeleteRule(id); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to delete rule: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Message: "Rule deleted successfully",
	})
}

// toggleRule toggles a rule's enabled status
func (a *API) toggleRule(c *gin.Context) {
	id := c.Param("id")

	// Get current rule
	rule, err := a.storage.GetRule(id)
	if err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{
			Success: false,
			Error:   "Rule not found",
		})
		return
	}

	// Create backup if auto-backup is enabled
	if a.config.Storage.AutoBackup {
		if err := a.backup.CreateAutoBackup("pre-toggle"); err != nil {
			fmt.Printf("Warning: Failed to create backup: %v\n", err)
		}
	}

	newEnabled := !rule.Enabled

	// Apply/remove network rule
	if newEnabled {
		if err := a.network.AddDNATRule(*rule); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{
				Success: false,
				Error:   fmt.Sprintf("Failed to enable rule: %v", err),
			})
			return
		}
	} else {
		if err := a.network.RemoveDNATRule(*rule); err != nil {
			fmt.Printf("Warning: Failed to disable rule: %v\n", err)
		}
	}

	// Toggle in storage
	if err := a.storage.ToggleRule(id); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to toggle rule: %v", err),
		})
		return
	}

	status := "disabled"
	if newEnabled {
		status = "enabled"
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Message: fmt.Sprintf("Rule %s successfully", status),
	})
}

// getVMs returns discovered VMs/containers
func (a *API) getVMs(c *gin.Context) {
	vms, err := a.discovery.DiscoverVMs()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to discover VMs: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Data:    vms,
	})
}

// getVM returns a specific VM
func (a *API) getVM(c *gin.Context) {
	id := c.Param("id")
	vm, err := a.discovery.GetVMByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("VM not found: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Data:    vm,
	})
}

// refreshVMs forces a refresh of VM discovery
func (a *API) refreshVMs(c *gin.Context) {
	vms, err := a.discovery.RefreshVMData()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to refresh VMs: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Message: "VMs refreshed successfully",
		Data:    vms,
	})
}

// validateRule validates a rule structure
func (a *API) validateRule(rule models.Rule) error {
	if rule.Name == "" {
		return fmt.Errorf("rule name is required")
	}

	if rule.ExternalPort < 1 || rule.ExternalPort > 65535 {
		return fmt.Errorf("external port must be between 1 and 65535")
	}

	if rule.InternalPort < 1 || rule.InternalPort > 65535 {
		return fmt.Errorf("internal port must be between 1 and 65535")
	}

	if rule.InternalIP == "" {
		return fmt.Errorf("internal IP is required")
	}

	if rule.Protocol != "tcp" && rule.Protocol != "udp" && rule.Protocol != "both" {
		return fmt.Errorf("protocol must be tcp, udp, or both")
	}

	// Check port range restrictions
	if rule.ExternalPort < a.config.Network.PortRange.Min || rule.ExternalPort > a.config.Network.PortRange.Max {
		return fmt.Errorf("external port %d is outside allowed range %d-%d",
			rule.ExternalPort, a.config.Network.PortRange.Min, a.config.Network.PortRange.Max)
	}

	// Check excluded ports
	for _, excluded := range a.config.Network.PortRange.Exclude {
		if rule.ExternalPort == excluded {
			return fmt.Errorf("external port %d is in excluded list", rule.ExternalPort)
		}
	}

	return nil
}

// enableNAT enables NAT masquerade
func (a *API) enableNAT(c *gin.Context) {
	if err := a.network.EnableNAT(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to enable NAT: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Message: "NAT enabled successfully",
	})
}

// disableNAT disables NAT masquerade
func (a *API) disableNAT(c *gin.Context) {
	if err := a.network.DisableNAT(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to disable NAT: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Message: "NAT disabled successfully",
	})
}

// enableForwarding enables IPv4 forwarding
func (a *API) enableForwarding(c *gin.Context) {
	if err := a.network.EnableIPForwarding(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to enable IP forwarding: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Message: "IP forwarding enabled successfully",
	})
}

// disableForwarding disables IPv4 forwarding
func (a *API) disableForwarding(c *gin.Context) {
	if err := a.network.DisableIPForwarding(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to disable IP forwarding: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Message: "IP forwarding disabled successfully",
	})
}

// listBackups lists available backup files
func (a *API) listBackups(c *gin.Context) {
	backups, err := a.backup.ListBackups()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to list backups: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Data:    backups,
	})
}

// createBackup creates a manual backup
func (a *API) createBackup(c *gin.Context) {
	var req struct {
		Name string `json:"name"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Invalid request: %v", err),
		})
		return
	}

	metadata, err := a.backup.CreateBackup(req.Name)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to create backup: %v", err),
		})
		return
	}

	c.JSON(http.StatusCreated, models.APIResponse{
		Success: true,
		Message: "Backup created successfully",
		Data:    metadata,
	})
}

// restoreBackup restores from a backup
func (a *API) restoreBackup(c *gin.Context) {
	var req struct {
		BackupPath string `json:"backup_path"`
		Preview    bool   `json:"preview"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Invalid request: %v", err),
		})
		return
	}

	// Convert timestamp to actual backup file path
	// Frontend sends timestamp, we need to find the matching backup file
	backups, err := a.backup.ListBackups()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to list backups: %v", err),
		})
		return
	}

	var backupPath string
	targetTimestamp := req.BackupPath

	// Search for backup file by scanning actual files in backup directory
	files, err := os.ReadDir(a.config.Storage.BackupDir)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to read backup directory: %v", err),
		})
		return
	}

	// Try to match by timestamp in filename
	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".json") {
			continue
		}

		// Check if any backup metadata matches the requested timestamp
		for _, backup := range backups {
			if backup.Timestamp.Format(time.RFC3339Nano) == targetTimestamp {
				// Found matching timestamp, now find the actual file
				// The filename pattern is: backup_YYYYMMDD_HHMMSS_*_*.json
				timestampPart := backup.Timestamp.Format("20060102_150405")
				if strings.Contains(file.Name(), timestampPart) {
					backupPath = filepath.Join(a.config.Storage.BackupDir, file.Name())
					break
				}
			}
		}
		if backupPath != "" {
			break
		}
	}

	if backupPath == "" {
		c.JSON(http.StatusNotFound, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Backup file not found for timestamp: %s", targetTimestamp),
		})
		return
	}

	result, err := a.backup.RestoreBackup(backupPath, req.Preview)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to restore backup: %v", err),
		})
		return
	}

	message := "Backup preview generated"
	if !req.Preview {
		message = "Backup restored successfully"

		// Reload and apply rules after restore
		if rules, err := a.storage.GetEnabledRules(); err == nil {
			if err := a.network.ApplyRules(rules); err != nil {
				fmt.Printf("Warning: Failed to apply restored rules: %v\n", err)
			}
		}
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Message: message,
		Data:    result,
	})
}

// importBackup imports a backup from external file
func (a *API) importBackup(c *gin.Context) {
	var req struct {
		ImportPath string `json:"import_path"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Invalid request: %v", err),
		})
		return
	}

	metadata, err := a.backup.ImportBackup(req.ImportPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to import backup: %v", err),
		})
		return
	}

	c.JSON(http.StatusCreated, models.APIResponse{
		Success: true,
		Message: "Backup imported successfully",
		Data:    metadata,
	})
}

// exportBackup exports a backup file
func (a *API) exportBackup(c *gin.Context) {
	id := c.Param("id")

	// Convert timestamp to actual backup file path
	backups, err := a.backup.ListBackups()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to list backups: %v", err),
		})
		return
	}

	var backupPath string
	var filename string
	targetTimestamp := id

	// Search for backup file by scanning actual files in backup directory
	files, err := os.ReadDir(a.config.Storage.BackupDir)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to read backup directory: %v", err),
		})
		return
	}

	// Try to match by timestamp in filename
	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".json") {
			continue
		}

		// Check if any backup metadata matches the requested timestamp
		for _, backup := range backups {
			if backup.Timestamp.Format(time.RFC3339Nano) == targetTimestamp {
				// Found matching timestamp, now find the actual file
				timestampPart := backup.Timestamp.Format("20060102_150405")
				if strings.Contains(file.Name(), timestampPart) {
					filename = file.Name()
					backupPath = filepath.Join(a.config.Storage.BackupDir, filename)
					break
				}
			}
		}
		if backupPath != "" {
			break
		}
	}

	if backupPath == "" {
		c.JSON(http.StatusNotFound, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Backup file not found for timestamp: %s", targetTimestamp),
		})
		return
	}

	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	c.Header("Content-Type", "application/json")
	c.File(backupPath)
}

// dryRun performs a dry-run operation
func (a *API) dryRun(c *gin.Context) {
	var req struct {
		Operation string      `json:"operation"`
		Data      interface{} `json:"data"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Invalid request: %v", err),
		})
		return
	}

	var result interface{}
	var err error

	switch req.Operation {
	case "restore":
		if restoreReq, ok := req.Data.(map[string]interface{}); ok {
			if backupPath, ok := restoreReq["backup_path"].(string); ok {
				result, err = a.backup.RestoreBackup(backupPath, true)
			} else {
				err = fmt.Errorf("backup_path is required for restore dry-run")
			}
		} else {
			err = fmt.Errorf("invalid data format for restore dry-run")
		}
	default:
		err = fmt.Errorf("unsupported dry-run operation: %s", req.Operation)
	}

	if err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Dry-run failed: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Message: "Dry-run completed successfully",
		Data:    result,
	})
}

// cleanupRules cleans up duplicate port rules and validates all rules
func (a *API) cleanupRules(c *gin.Context) {
	// Create backup if auto-backup is enabled
	if a.config.Storage.AutoBackup {
		if err := a.backup.CreateAutoBackup("pre-cleanup"); err != nil {
			fmt.Printf("Warning: Failed to create backup: %v\n", err)
		}
	}

	// Cleanup duplicate rules
	duplicatesRemoved, err := a.storage.CleanupDuplicateRules()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to cleanup duplicate rules: %v", err),
		})
		return
	}

	// Validate and fix rules
	validationResult, err := a.storage.ValidateAndFixRules()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to validate rules: %v", err),
		})
		return
	}

	// Reload and apply rules after cleanup
	rules, err := a.storage.GetEnabledRules()
	if err == nil {
		if err := a.network.ApplyRules(rules); err != nil {
			fmt.Printf("Warning: Failed to apply cleaned rules: %v\n", err)
		}
	}

	result := map[string]interface{}{
		"duplicates_removed": duplicatesRemoved,
		"validation_result":  validationResult,
	}

	message := fmt.Sprintf("Rules cleanup completed. Removed %d duplicates, fixed %d rules",
		duplicatesRemoved, validationResult.FixedRules)

	c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Message: message,
		Data:    result,
	})
}
