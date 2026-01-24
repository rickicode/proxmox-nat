.PHONY: build install uninstall clean run help

# Variables
APP_NAME := netnat
VERSION ?= 1.0.0
BUILD_DIR := build
INSTALL_DIR := /opt/netnat
CONFIG_DIR := $(INSTALL_DIR)
DATA_DIR := $(INSTALL_DIR)/data
LOG_DIR := $(INSTALL_DIR)/logs
SERVICE_DIR := /etc/systemd/system

# Build everything (always rebuild)
build:
	@echo "Building Frontend..."
	cd frontend && npm install && npm run build
	@echo "Building Backend for Linux..."
	go mod tidy
	mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-X main.Version=$(VERSION)" -o $(BUILD_DIR)/$(APP_NAME) cmd/netnat/main.go
	@echo "✓ Build complete: $(BUILD_DIR)/$(APP_NAME) (Linux AMD64)"

# Install to system (always rebuild first)
install: build
	@echo "Installing $(APP_NAME)..."
	
	# Stop service if running
	-systemctl stop netnat 2>/dev/null || true
	
	# Create directories
	mkdir -p $(INSTALL_DIR)
	mkdir -p $(CONFIG_DIR)
	mkdir -p $(CONFIG_DIR)/backups
	mkdir -p $(LOG_DIR)
	mkdir -p $(DATA_DIR)
	mkdir -p $(DATA_DIR)/backups
	
	# Install binary
	install -m 755 $(BUILD_DIR)/$(APP_NAME) $(INSTALL_DIR)/$(APP_NAME)
	
	# Install configuration
	cp configs/config.yml $(CONFIG_DIR)/config.yml.example
	@if [ ! -f $(CONFIG_DIR)/config.yml ]; then \
		cp configs/config.yml $(CONFIG_DIR)/config.yml; \
		echo "✓ Created default configuration"; \
	else \
		echo "✓ Configuration already exists (not overwritten)"; \
	fi
	
	# Install systemd service
	cp systemd/netnat.service $(SERVICE_DIR)/netnat.service
	
	# Set permissions
	chown -R root:root $(INSTALL_DIR)
	chmod 755 $(INSTALL_DIR)
	chown -R root:root $(CONFIG_DIR)
	chmod 750 $(CONFIG_DIR)
	chmod 640 $(CONFIG_DIR)/*.yml
	chown -R root:root $(DATA_DIR)
	chmod 750 $(DATA_DIR)
	chown -R root:root $(LOG_DIR)
	chmod 755 $(LOG_DIR)
	
	# Enable IP forwarding
	@if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then \
		echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf; \
		sysctl -p; \
	fi
	
	# Reload systemd and start service
	systemctl daemon-reload
	systemctl enable netnat
	systemctl start netnat
	
	@echo ""
	@echo "✓ Installation complete!"
	@echo ""
	@echo "📋 Service Information:"
	@echo "   Binary:  $(INSTALL_DIR)/$(APP_NAME)"
	@echo "   Config:  $(CONFIG_DIR)/config.yml"
	@echo "   Data:    $(DATA_DIR)"
	@echo "   Logs:    $(LOG_DIR)"
	@echo ""
	@echo "Service status:"
	@systemctl status netnat --no-pager || true
	@echo ""
	@echo "🌐 Access web interface at: http://localhost:8080"
	@echo "🔐 Default credentials: admin / netnat123"
	@echo ""
	@echo "⚠️  IMPORTANT: Change default password and JWT secret in $(CONFIG_DIR)/config.yml"

# Uninstall from system
uninstall:
	@echo "Uninstalling $(APP_NAME)..."
	systemctl stop netnat || true
	systemctl disable netnat || true
	rm -f $(INSTALL_DIR)/$(APP_NAME)
	rm -f $(SERVICE_DIR)/netnat.service
	systemctl daemon-reload
	@echo "✓ Uninstall complete"
	@echo "Note: Config files in $(CONFIG_DIR) and data in $(DATA_DIR) were preserved"
	@echo "To remove all data: sudo rm -rf $(INSTALL_DIR) $(CONFIG_DIR) $(DATA_DIR) $(LOG_DIR)"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	rm -rf frontend/node_modules
	rm -rf frontend/.svelte-kit
	rm -rf frontend/build/*
	@echo "✓ Clean complete"

# Run locally (for development)
run: build
	@echo "Starting $(APP_NAME) locally..."
	sudo $(BUILD_DIR)/$(APP_NAME)

# Show help
help:
	@echo "NetNAT Makefile Commands:"
	@echo ""
	@echo "  make build      - Build frontend and backend"
	@echo "  make install    - Build and install to system (requires sudo)"
	@echo "  make uninstall  - Remove from system (requires sudo)"
	@echo "  make clean      - Clean build artifacts"
	@echo "  make run        - Build and run locally (requires sudo)"
	@echo "  make help       - Show this help message"
	@echo ""
	@echo "Quick start:"
	@echo "  sudo make install"
	@echo ""
