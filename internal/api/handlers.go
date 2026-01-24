package api

import (
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	web "proxmox-nat/frontend"
	"proxmox-nat/internal/config"
	"proxmox-nat/internal/models"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"gopkg.in/yaml.v3"
)

// Handler returns the HTTP handler using Echo framework
func (a *API) Handler() http.Handler {
	e := echo.New()
	e.HideBanner = true
	e.HidePort = true

	// Middleware
	e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{
		Format: "${time_custom} | ${status} | ${method} | ${uri} | ${latency_human}\n",
		CustomTimeFormat: "2006-01-02 15:04:05",
	}))
	e.Use(middleware.Recover())
	e.Use(a.corsMiddleware())

	// Get embedded filesystem
	rawStaticFS := web.GetStaticFS()

	// Serve Vite static assets (assets directory)
	e.GET("/assets/*", echo.WrapHandler(http.StripPrefix("/assets/", http.FileServer(http.FS(web.GetSubFS("assets"))))))

	// Serve favicon
	e.GET("/favicon.png", func(c echo.Context) error {
		data, err := fs.ReadFile(rawStaticFS, "favicon.png")
		if err != nil {
			return c.String(http.StatusNotFound, "Favicon not found")
		}
		return c.Blob(http.StatusOK, "image/png", data)
	})

	// Root handler - serve index.html (NO AUTH)
	e.GET("/", func(c echo.Context) error {
		data, err := fs.ReadFile(rawStaticFS, "index.html")
		if err != nil {
			fmt.Printf("ERROR: Cannot read index.html: %v\n", err)
			return c.String(http.StatusInternalServerError, "Application error: failed to load index.html")
		}
		return c.HTMLBlob(http.StatusOK, data)
	})

	// Public API routes (NO AUTH)
	e.POST("/api/login", a.login)
	e.POST("/api/logout", a.logout)

	// Protected API routes (WITH JWT AUTH)
	api := e.Group("/api")
	api.Use(a.jwtAuthMiddleware())
	api.Use(a.rateLimitMiddleware())

	// System status
	api.GET("/status", a.getSystemStatus)

	// Rules CRUD
	api.GET("/rules", a.getRules)
	api.GET("/rules/:id", a.getRule)
	api.POST("/rules", a.createRule, a.csrfMiddleware())
	api.PUT("/rules/:id", a.updateRule, a.csrfMiddleware())
	api.DELETE("/rules/:id", a.deleteRule, a.csrfMiddleware())
	api.POST("/rules/:id/toggle", a.toggleRule, a.csrfMiddleware())
	api.POST("/rules/cleanup", a.cleanupRules, a.csrfMiddleware())

	// VM/CT discovery
	api.GET("/vms", a.getVMs)
	api.GET("/vms/:id", a.getVM)
	api.POST("/vms/refresh", a.refreshVMs)

	// Configuration management
	api.GET("/config", a.getConfig)
	api.PUT("/config", a.updateConfig, a.csrfMiddleware())

	// Backup operations
	api.GET("/backup/list", a.listBackups)
	api.POST("/backup/create", a.createBackup, a.csrfMiddleware())
	api.POST("/backup/restore", a.restoreBackup, a.csrfMiddleware())
	api.POST("/backup/import", a.importBackup, a.csrfMiddleware())
	api.GET("/backup/export/:id", a.exportBackup)

	// Dry-run operations
	api.POST("/dry-run", a.dryRun, a.csrfMiddleware())

	// Orphaned rules management
	api.GET("/rules/orphaned", a.detectOrphanedRules)
	api.POST("/rules/orphaned/cleanup", a.cleanOrphanedRules, a.csrfMiddleware())

	// CSRF token endpoint
	api.GET("/csrf-token", a.getCSRFToken)

	// Network monitoring
	api.GET("/network/traffic", a.getNetworkTraffic)

	// System info
	api.GET("/version", a.getVersion)

	// SPA fallback - serve index.html for all other routes
	e.RouteNotFound("/*", func(c echo.Context) error {
		// Don't serve SPA for API routes
		if strings.HasPrefix(c.Request().URL.Path, "/api") {
			return c.JSON(http.StatusNotFound, models.APIResponse{
				Success: false,
				Error:   "API endpoint not found",
			})
		}

		// Serve index.html for SPA routing
		data, err := fs.ReadFile(rawStaticFS, "index.html")
		if err != nil {
			fmt.Printf("ERROR: Cannot read index.html in RouteNotFound: %v\n", err)
			return c.String(http.StatusNotFound, "Page not found")
		}
		return c.HTMLBlob(http.StatusOK, data)
	})

	return e
}

// corsMiddleware configures CORS for Echo
func (a *API) corsMiddleware() echo.MiddlewareFunc {
	return middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"},
		AllowMethods: []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodOptions},
		AllowHeaders: []string{"Content-Type", "Authorization", "X-CSRF-Token"},
	})
}

// getSystemStatus returns system status
func (a *API) getSystemStatus(c echo.Context) error {
	status, err := a.network.GetSystemStatus()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to get system status: %v", err),
		})
	}

	total, active, err := a.storage.GetRulesCount()
	if err == nil {
		status.RulesCount = total
		status.ActiveRules = active
	}


	return c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Data:    status,
	})
}

// Echo wrapper handlers - Rules
func (a *API) getRules(c echo.Context) error {
	rulesData, err := a.storage.LoadRules()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to load rules: %v", err),
		})
	}

	return c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Data:    rulesData.Rules,
	})
}

func (a *API) getRule(c echo.Context) error {
	id := c.Param("id")
	rule, err := a.storage.GetRule(id)
	if err != nil {
		return c.JSON(http.StatusNotFound, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Rule not found: %v", err),
		})
	}

	return c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Data:    rule,
	})
}

func (a *API) createRule(c echo.Context) error {
	var rule models.Rule
	if err := c.Bind(&rule); err != nil {
		return c.JSON(http.StatusBadRequest, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Invalid request: %v", err),
		})
	}

	if err := a.validateRule(rule); err != nil {
		return c.JSON(http.StatusBadRequest, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Validation failed: %v", err),
		})
	}

	rule.ID = fmt.Sprintf("rule-%d", time.Now().Unix())

	if a.config.Storage.AutoBackup {
		if err := a.backup.CreateAutoBackup("pre-create"); err != nil {
			fmt.Printf("Warning: Failed to create backup: %v\n", err)
		}
	}

	if err := a.storage.AddRule(rule); err != nil {
		return c.JSON(http.StatusConflict, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to add rule: %v", err),
		})
	}

	if rule.Enabled {
		if err := a.network.AddDNATRule(rule); err != nil {
			fmt.Printf("Warning: Failed to apply rule: %v\n", err)
		}
	}

	return c.JSON(http.StatusCreated, models.APIResponse{
		Success: true,
		Message: "Rule created successfully",
		Data:    rule,
	})
}

func (a *API) updateRule(c echo.Context) error {
	id := c.Param("id")
	var updatedRule models.Rule
	if err := c.Bind(&updatedRule); err != nil {
		return c.JSON(http.StatusBadRequest, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Invalid request: %v", err),
		})
	}

	if err := a.validateRule(updatedRule); err != nil {
		return c.JSON(http.StatusBadRequest, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Validation failed: %v", err),
		})
	}

	oldRule, err := a.storage.GetRule(id)
	if err != nil {
		return c.JSON(http.StatusNotFound, models.APIResponse{
			Success: false,
			Error:   "Rule not found",
		})
	}

	if a.config.Storage.AutoBackup {
		if err := a.backup.CreateAutoBackup("pre-update"); err != nil {
			fmt.Printf("Warning: Failed to create backup: %v\n", err)
		}
	}

	if oldRule.Enabled {
		if err := a.network.RemoveDNATRule(*oldRule); err != nil {
			return c.JSON(http.StatusInternalServerError, models.APIResponse{
				Success: false,
				Error:   fmt.Sprintf("Failed to remove old network rule: %v", err),
			})
		}
	}

	if err := a.storage.UpdateRule(id, updatedRule); err != nil {
		if oldRule.Enabled {
			a.network.AddDNATRule(*oldRule)
		}
		return c.JSON(http.StatusConflict, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to update rule: %v", err),
		})
	}

	if updatedRule.Enabled {
		if err := a.network.AddDNATRule(updatedRule); err != nil {
			fmt.Printf("Warning: Failed to apply updated rule: %v\n", err)
		}
	}

	return c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Message: "Rule updated successfully",
		Data:    updatedRule,
	})
}

func (a *API) deleteRule(c echo.Context) error {
	id := c.Param("id")

	rule, err := a.storage.GetRule(id)
	if err != nil {
		return c.JSON(http.StatusNotFound, models.APIResponse{
			Success: false,
			Error:   "Rule not found",
		})
	}

	if a.config.Storage.AutoBackup {
		if err := a.backup.CreateAutoBackup("pre-delete"); err != nil {
			fmt.Printf("Warning: Failed to create backup: %v\n", err)
		}
	}

	if rule.Enabled {
		if err := a.network.RemoveDNATRule(*rule); err != nil {
			fmt.Printf("Warning: Failed to remove network rule: %v\n", err)
		}
	}

	if err := a.storage.DeleteRule(id); err != nil {
		return c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to delete rule: %v", err),
		})
	}

	return c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Message: "Rule deleted successfully",
	})
}

func (a *API) toggleRule(c echo.Context) error {
	id := c.Param("id")

	_, err := a.storage.GetRule(id)
	if err != nil {
		return c.JSON(http.StatusNotFound, models.APIResponse{
			Success: false,
			Error:   "Rule not found",
		})
	}

	if a.config.Storage.AutoBackup {
		if err := a.backup.CreateAutoBackup("pre-toggle"); err != nil {
			fmt.Printf("Warning: Failed to create backup: %v\n", err)
		}
	}

	if err := a.storage.ToggleRule(id); err != nil {
		return c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to toggle rule: %v", err),
		})
	}

	updatedRule, err := a.storage.GetRule(id)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   "Failed to get updated rule",
		})
	}

	if updatedRule.Enabled {
		if err := a.network.AddDNATRule(*updatedRule); err != nil {
			a.storage.ToggleRule(id)
			return c.JSON(http.StatusInternalServerError, models.APIResponse{
				Success: false,
				Error:   fmt.Sprintf("Failed to enable rule: %v", err),
			})
		}
	} else {
		if err := a.network.RemoveDNATRule(*updatedRule); err != nil {
			a.storage.ToggleRule(id)
			return c.JSON(http.StatusInternalServerError, models.APIResponse{
				Success: false,
				Error:   fmt.Sprintf("Failed to disable rule: %v", err),
			})
		}
	}

	status := "disabled"
	if updatedRule.Enabled {
		status = "enabled"
	}

	return c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Message: fmt.Sprintf("Rule %s successfully", status),
	})
}

func (a *API) cleanupRules(c echo.Context) error {
	if a.config.Storage.AutoBackup {
		if err := a.backup.CreateAutoBackup("pre-cleanup"); err != nil {
			fmt.Printf("Warning: Failed to create backup: %v\n", err)
		}
	}

	duplicatesRemoved, err := a.storage.CleanupDuplicateRules()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to cleanup duplicate rules: %v", err),
		})
	}

	validationResult, err := a.storage.ValidateAndFixRules()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to validate rules: %v", err),
		})
	}

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

	return c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Message: message,
		Data:    result,
	})
}

// Continue with other Echo handlers...
// (VMs, Network, Backup, etc - I'll create stub implementations)

func (a *API) getVMs(c echo.Context) error {
	vms, err := a.discovery.DiscoverVMs()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to discover VMs: %v", err),
		})
	}
	return c.JSON(http.StatusOK, models.APIResponse{Success: true, Data: vms})
}

func (a *API) getVM(c echo.Context) error {
	id := c.Param("id")
	vm, err := a.discovery.GetVMByID(id)
	if err != nil {
		return c.JSON(http.StatusNotFound, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("VM not found: %v", err),
		})
	}
	return c.JSON(http.StatusOK, models.APIResponse{Success: true, Data: vm})
}

func (a *API) refreshVMs(c echo.Context) error {
	a.discovery.RefreshVMData()
	return c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Message: "VM refresh started in background",
	})
}

func (a *API) getConfig(c echo.Context) error {
	configPath := config.GetConfigPath()
	data, err := os.ReadFile(configPath)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to read config file: %v", err),
		})
	}

	return c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Data:    string(data),
	})
}

func (a *API) updateConfig(c echo.Context) error {
	var req struct {
		Content string `json:"content"`
	}
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Invalid request: %v", err),
		})
	}

	// Validate the new config content
	var newConfig models.Config
	if err := yaml.Unmarshal([]byte(req.Content), &newConfig); err != nil {
		return c.JSON(http.StatusBadRequest, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Invalid YAML format: %v", err),
		})
	}

	if err := config.Validate(&newConfig); err != nil {
		return c.JSON(http.StatusBadRequest, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Invalid configuration: %v", err),
		})
	}

	// Create backup of current config
	configPath := config.GetConfigPath()
	if err := a.backupConfig(configPath); err != nil {
		fmt.Printf("Warning: Failed to backup config before update: %v\n", err)
	}

	// Save new config
	if err := os.WriteFile(configPath, []byte(req.Content), 0644); err != nil {
		return c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to save config file: %v", err),
		})
	}

	return c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Message: "Configuration saved successfully. Some changes may require a server restart.",
	})
}

func (a *API) backupConfig(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	backupPath := fmt.Sprintf("%s.bak.%d", path, time.Now().Unix())
	return os.WriteFile(backupPath, data, 0644)
}

func (a *API) listBackups(c echo.Context) error {
	backups, err := a.backup.ListBackups()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to list backups: %v", err),
		})
	}
	return c.JSON(http.StatusOK, models.APIResponse{Success: true, Data: backups})
}

func (a *API) createBackup(c echo.Context) error {
	var req struct {
		Name string `json:"name"`
	}
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Invalid request: %v", err),
		})
	}

	metadata, err := a.backup.CreateBackup(req.Name)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to create backup: %v", err),
		})
	}

	return c.JSON(http.StatusCreated, models.APIResponse{
		Success: true,
		Message: "Backup created successfully",
		Data:    metadata,
	})
}

func (a *API) restoreBackup(c echo.Context) error {
	var req struct {
		BackupPath string `json:"backup_path"`
		Preview    bool   `json:"preview"`
	}
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Invalid request: %v", err),
		})
	}

	backupPath, _, err := a.findBackupFile(req.BackupPath)
	if err != nil {
		return c.JSON(http.StatusNotFound, models.APIResponse{
			Success: false,
			Error:   err.Error(),
		})
	}

	result, err := a.backup.RestoreBackup(backupPath, req.Preview)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to restore backup: %v", err),
		})
	}

	message := "Backup preview generated"
	if !req.Preview {
		message = "Backup restored successfully"
		if rules, err := a.storage.GetEnabledRules(); err == nil {
			if err := a.network.ApplyRules(rules); err != nil {
				fmt.Printf("Warning: Failed to apply restored rules: %v\n", err)
			}
		}
	}

	return c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Message: message,
		Data:    result,
	})
}

func (a *API) importBackup(c echo.Context) error {
	var req struct {
		ImportPath string `json:"import_path"`
	}
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Invalid request: %v", err),
		})
	}

	metadata, err := a.backup.ImportBackup(req.ImportPath)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to import backup: %v", err),
		})
	}

	return c.JSON(http.StatusCreated, models.APIResponse{
		Success: true,
		Message: "Backup imported successfully",
		Data:    metadata,
	})
}

func (a *API) exportBackup(c echo.Context) error {
	id := c.Param("id")
	backups, err := a.backup.ListBackups()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to list backups: %v", err),
		})
	}

	var backupPath string
	var filename string
	targetTimestamp := id

	files, err := os.ReadDir(a.config.Storage.BackupDir)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to read backup directory: %v", err),
		})
	}

	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".json") {
			continue
		}

		for _, backup := range backups {
			if backup.Timestamp.Format(time.RFC3339Nano) == targetTimestamp {
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
		return c.JSON(http.StatusNotFound, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Backup file not found for timestamp: %s", targetTimestamp),
		})
	}

	return c.Attachment(backupPath, filename)
}

func (a *API) dryRun(c echo.Context) error {
	var req struct {
		Operation string      `json:"operation"`
		Data      interface{} `json:"data"`
	}
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Invalid request: %v", err),
		})
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
		return c.JSON(http.StatusBadRequest, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Dry-run failed: %v", err),
		})
	}

	return c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Message: "Dry-run completed successfully",
		Data:    result,
	})
}

func (a *API) detectOrphanedRules(c echo.Context) error {
	allVMs, err := a.discovery.DiscoverVMs()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to discover VMs for orphan detection: %v", err),
		})
	}

	var activeVMIPs []string
	var allVMIDs []string

	for _, vm := range allVMs {
		if vm.IP != "" {
			activeVMIPs = append(activeVMIPs, vm.IP)
		}
		if vm.ID != "" {
			allVMIDs = append(allVMIDs, vm.ID)
		}
	}

	result, err := a.storage.RemoveOrphanedRules(activeVMIPs, allVMIDs, true)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to detect orphaned rules: %v", err),
		})
	}

	return c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Data:    result,
	})
}

func (a *API) cleanOrphanedRules(c echo.Context) error {
	allVMs, err := a.discovery.DiscoverVMs()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to discover VMs for orphan cleanup: %v", err),
		})
	}

	var activeVMIPs []string
	var allVMIDs []string

	for _, vm := range allVMs {
		if vm.IP != "" {
			activeVMIPs = append(activeVMIPs, vm.IP)
		}
		if vm.ID != "" {
			allVMIDs = append(allVMIDs, vm.ID)
		}
	}

	if a.config.Storage.AutoBackup {
		if err := a.backup.CreateAutoBackup("pre-orphan-cleanup"); err != nil {
			fmt.Printf("Warning: Failed to create backup: %v\n", err)
		}
	}

	result, err := a.storage.RemoveOrphanedRules(activeVMIPs, allVMIDs, false)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to clean orphaned rules: %v", err),
		})
	}

	rules, err := a.storage.GetEnabledRules()
	if err == nil {
		if err := a.network.ApplyRules(rules); err != nil {
			fmt.Printf("Warning: Failed to apply rules after orphan cleanup: %v\n", err)
		}
	}

	return c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Message: fmt.Sprintf("Orphaned rules cleanup completed. Removed %d rules", result.RemovedCount),
		Data:    result,
	})
}

func (a *API) getNetworkTraffic(c echo.Context) error {
	traffic, err := a.network.GetNetworkTraffic()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to get network traffic: %v", err),
		})
	}

	total, active, err := a.storage.GetRulesCount()
	if err == nil {
		traffic.ActiveRules = active
		traffic.TotalRules = total
	}

	traffic.LastUpdated = time.Now()

	return c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Data:    traffic,
	})
}

func (a *API) getVersion(c echo.Context) error {
	versionInfo := map[string]interface{}{
		"version":     a.version,
		"app_name":    "NetNAT",
		"description": "NAT & Port Forwarding Manager",
		"build_time":  time.Now().Format("2006-01-02"),
	}

	return c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Data:    versionInfo,
	})
}
