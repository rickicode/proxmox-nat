# NetNAT Makefile

# Variables
APP_NAME = netnat
VERSION = 1.0.0
MAIN_PATH = ./cmd/netnat
BUILD_DIR = ./build
INSTALL_PREFIX = /usr/local
CONFIG_DIR = /etc/netnat
SERVICE_DIR = /etc/systemd/system

# Go build flags
LDFLAGS = -ldflags "-X main.Version=$(VERSION) -s -w"
GOFLAGS = -trimpath

# Default target
.PHONY: all
all: build

# Build the application
.PHONY: build
build:
	@echo "Building $(APP_NAME) v$(VERSION)..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 go build $(GOFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(APP_NAME) $(MAIN_PATH)
	@echo "Build complete: $(BUILD_DIR)/$(APP_NAME)"

# Build for different architectures
.PHONY: build-all
build-all:
	@echo "Building for multiple architectures..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build $(GOFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(APP_NAME)-linux-amd64 $(MAIN_PATH)
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build $(GOFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(APP_NAME)-linux-arm64 $(MAIN_PATH)
	@echo "Multi-arch build complete"

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)
	@echo "Clean complete"

# Run tests
.PHONY: test
test:
	@echo "Running tests..."
	go test -v ./...

# Run with race detection
.PHONY: test-race
test-race:
	@echo "Running tests with race detection..."
	go test -race -v ./...

# Format code
.PHONY: fmt
fmt:
	@echo "Formatting code..."
	go fmt ./...
	gofmt -s -w .

# Lint code
.PHONY: lint
lint:
	@echo "Linting code..."
	golangci-lint run

# Install dependencies
.PHONY: deps
deps:
	@echo "Installing dependencies..."
	go mod download
	go mod tidy

# Development server
.PHONY: dev
dev: build
	@echo "Starting development server..."
	sudo $(BUILD_DIR)/$(APP_NAME)

# Install to system
.PHONY: install
install: build
	@echo "Installing $(APP_NAME) to system..."
	
	# Create directories
	sudo mkdir -p $(CONFIG_DIR)
	sudo mkdir -p $(CONFIG_DIR)/backups
	sudo mkdir -p /var/log/netnat
	sudo mkdir -p /opt/netnat/web
	
	# Install binary
	sudo cp $(BUILD_DIR)/$(APP_NAME) $(INSTALL_PREFIX)/bin/$(APP_NAME)
	sudo chmod +x $(INSTALL_PREFIX)/bin/$(APP_NAME)
	
	# Install configuration
	sudo cp configs/config.yml $(CONFIG_DIR)/config.yml.example
	@if [ ! -f $(CONFIG_DIR)/config.yml ]; then \
		sudo cp configs/config.yml $(CONFIG_DIR)/config.yml; \
		echo "Created default configuration at $(CONFIG_DIR)/config.yml"; \
	else \
		echo "Configuration file already exists at $(CONFIG_DIR)/config.yml"; \
	fi
	
	# Install web files
	sudo cp -r web/* /opt/netnat/web/
	
	# Install systemd service
	sudo cp systemd/netnat.service $(SERVICE_DIR)/netnat.service
	sudo systemctl daemon-reload
	
	# Set permissions
	sudo chown -R root:root $(CONFIG_DIR)
	sudo chmod 750 $(CONFIG_DIR)
	sudo chmod 640 $(CONFIG_DIR)/*.yml
	sudo chown -R root:root /opt/netnat
	
	@echo "Installation complete!"
	@echo "Configuration: $(CONFIG_DIR)/config.yml"
	@echo "Start service: sudo systemctl start netnat"
	@echo "Enable service: sudo systemctl enable netnat"

# Uninstall from system
.PHONY: uninstall
uninstall:
	@echo "Uninstalling $(APP_NAME)..."
	
	# Stop and disable service
	-sudo systemctl stop netnat
	-sudo systemctl disable netnat
	
	# Remove files
	sudo rm -f $(INSTALL_PREFIX)/bin/$(APP_NAME)
	sudo rm -f $(SERVICE_DIR)/netnat.service
	sudo rm -rf /opt/netnat
	
	# Remove config (with confirmation)
	@read -p "Remove configuration directory $(CONFIG_DIR)? [y/N]: " confirm; \
	if [ "$$confirm" = "y" ] || [ "$$confirm" = "Y" ]; then \
		sudo rm -rf $(CONFIG_DIR); \
		echo "Configuration removed"; \
	else \
		echo "Configuration preserved"; \
	fi
	
	sudo systemctl daemon-reload
	@echo "Uninstall complete!"

# Package for distribution
.PHONY: package
package: build-all
	@echo "Creating distribution packages..."
	@mkdir -p $(BUILD_DIR)/dist
	
	# Create tar.gz for each architecture
	for arch in amd64 arm64; do \
		mkdir -p $(BUILD_DIR)/$(APP_NAME)-$(VERSION)-linux-$$arch; \
		cp $(BUILD_DIR)/$(APP_NAME)-linux-$$arch $(BUILD_DIR)/$(APP_NAME)-$(VERSION)-linux-$$arch/$(APP_NAME); \
		cp -r configs $(BUILD_DIR)/$(APP_NAME)-$(VERSION)-linux-$$arch/; \
		cp -r web $(BUILD_DIR)/$(APP_NAME)-$(VERSION)-linux-$$arch/; \
		cp -r systemd $(BUILD_DIR)/$(APP_NAME)-$(VERSION)-linux-$$arch/; \
		cp README.md $(BUILD_DIR)/$(APP_NAME)-$(VERSION)-linux-$$arch/; \
		cp Makefile $(BUILD_DIR)/$(APP_NAME)-$(VERSION)-linux-$$arch/; \
		tar -czf $(BUILD_DIR)/dist/$(APP_NAME)-$(VERSION)-linux-$$arch.tar.gz -C $(BUILD_DIR) $(APP_NAME)-$(VERSION)-linux-$$arch; \
		rm -rf $(BUILD_DIR)/$(APP_NAME)-$(VERSION)-linux-$$arch; \
	done
	
	@echo "Packages created in $(BUILD_DIR)/dist/"

# Quick start (development)
.PHONY: start
start: deps build
	@echo "Quick start - building and running..."
	@echo "Note: This requires sudo privileges for network operations"
	sudo $(BUILD_DIR)/$(APP_NAME)

# Check system requirements
.PHONY: check
check:
	@echo "Checking system requirements..."
	@command -v go >/dev/null 2>&1 || { echo "Go is required but not installed"; exit 1; }
	@command -v iptables >/dev/null 2>&1 || { echo "Warning: iptables not found"; }
	@command -v nft >/dev/null 2>&1 || echo "Warning: nftables not found"
	@command -v systemctl >/dev/null 2>&1 || echo "Warning: systemctl not found"
	@echo "System check complete"

# Show help
.PHONY: help
help:
	@echo "NetNAT Build System"
	@echo ""
	@echo "Usage: make <target>"
	@echo ""
	@echo "Targets:"
	@echo "  build      Build the application"
	@echo "  build-all  Build for multiple architectures"
	@echo "  clean      Clean build artifacts"
	@echo "  test       Run tests"
	@echo "  test-race  Run tests with race detection"
	@echo "  fmt        Format code"
	@echo "  lint       Lint code"
	@echo "  deps       Install dependencies"
	@echo "  dev        Build and run development server"
	@echo "  start      Quick start (deps + build + run)"
	@echo "  install    Install to system"
	@echo "  uninstall  Remove from system"
	@echo "  package    Create distribution packages"
	@echo "  check      Check system requirements"
	@echo "  help       Show this help"
	@echo ""
	@echo "Version: $(VERSION)"

# Show version
.PHONY: version
version:
	@echo "$(APP_NAME) v$(VERSION)"