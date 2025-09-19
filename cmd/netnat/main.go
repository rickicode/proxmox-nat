package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"proxmox-nat/internal/api"
	"proxmox-nat/internal/backup"
	"proxmox-nat/internal/config"
	"proxmox-nat/internal/network"
	"proxmox-nat/internal/storage"
)

const (
	AppName    = "NetNAT"
	AppVersion = "1.0.0"
)

func main() {
	fmt.Printf("%s v%s - NAT & Port Forwarding Manager\n", AppName, AppVersion)

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize storage
	store, err := storage.New(cfg.Storage.RulesFile)
	if err != nil {
		log.Fatalf("Failed to initialize storage: %v", err)
	}

	// Initialize backup manager
	backupMgr, err := backup.New(cfg, store)
	if err != nil {
		log.Fatalf("Failed to initialize backup manager: %v", err)
	}

	// Initialize network manager
	netMgr, err := network.New(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize network manager: %v", err)
	}

	// Enable IPv4 forwarding
	if err := netMgr.EnableIPForwarding(); err != nil {
		log.Printf("Warning: Failed to enable IP forwarding: %v", err)
	}

	// Apply NAT masquerade
	if err := netMgr.EnableNAT(); err != nil {
		log.Printf("Warning: Failed to enable NAT: %v", err)
	}

	// Restore existing rules
	rules, err := store.LoadRules()
	if err != nil {
		log.Printf("Warning: Failed to load existing rules: %v", err)
	} else {
		if err := netMgr.ApplyRules(rules.Rules); err != nil {
			log.Printf("Warning: Failed to apply existing rules: %v", err)
		} else {
			log.Printf("Restored %d rules", len(rules.Rules))
		}
	}

	// Start backup scheduler if enabled
	if cfg.Storage.BackupEnabled {
		backupMgr.StartScheduler()
		defer backupMgr.StopScheduler()
	}

	// Initialize API server
	apiServer := api.New(cfg, store, netMgr, backupMgr)

	// Setup HTTP server
	srv := &http.Server{
		Addr:         cfg.Server.ListenAddr,
		Handler:      apiServer.Handler(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in goroutine
	go func() {
		log.Printf("Server starting on %s", cfg.Server.ListenAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exited")
}
