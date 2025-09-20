package main

import (
	"context"
	"flag"
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
	AppVersion = "1.1.1"
)

var (
	Version = AppVersion // Can be overridden at build time
)

func showUsage() {
	fmt.Printf("%s v%s - NAT & Port Forwarding Manager\n", AppName, Version)
	fmt.Println()
	fmt.Println("USAGE:")
	fmt.Printf("  %s [options]\n", os.Args[0])
	fmt.Println()
	fmt.Println("OPTIONS:")
	fmt.Println("  -config string    Configuration file path (default: \"./configs/config.yml\")")
	fmt.Println("  -version          Show version information")
	fmt.Println("  -help             Show this help message")
	fmt.Println()
	fmt.Println("EXAMPLES:")
	fmt.Printf("  %s                           # Start with default config\n", os.Args[0])
	fmt.Printf("  %s -config /etc/netnat.yml   # Start with custom config\n", os.Args[0])
	fmt.Println()
	fmt.Println("WEB INTERFACE:")
	fmt.Println("  Open http://localhost:9090 in your browser")
	fmt.Println("  Default credentials: netnat / changeme")
	fmt.Println()
}

func main() {
	var (
		configPath  = flag.String("config", "./configs/config.yml", "Configuration file path")
		showVersion = flag.Bool("version", false, "Show version information")
		showHelp    = flag.Bool("help", false, "Show help message")
	)

	flag.Usage = showUsage
	flag.Parse()

	if *showHelp {
		showUsage()
		return
	}

	if *showVersion {
		fmt.Printf("%s v%s\n", AppName, Version)
		fmt.Println("NAT & Port Forwarding Manager for Proxmox")
		fmt.Println("Copyright (c) 2025 NetNAT Project")
		fmt.Println("https://github.com/rickicode/proxmox-nat")
		return
	}

	fmt.Printf("%s v%s - NAT & Port Forwarding Manager\n", AppName, Version)

	// Load configuration
	cfg, err := config.LoadFromFile(*configPath)
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
	log.Printf("Initializing API server...")
	apiServer := api.New(cfg, store, netMgr, backupMgr)
	log.Printf("API server initialized successfully")

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
		log.Printf("API server initialized successfully")
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
