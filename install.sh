#!/bin/bash

# NetNAT Installer Script for Proxmox/Debian
# This script installs NetNAT service and configures it to start automatically

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="/opt/netnat"
CONFIG_DIR="/etc/netnat"
DATA_DIR="/var/lib/netnat"
LOG_DIR="/var/log/netnat"
SERVICE_NAME="netnat"
GITHUB_REPO="https://github.com/rickicode/proxmox-nat"

# Print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        echo "Please run: sudo $0"
        exit 1
    fi
}

# Check system requirements
check_requirements() {
    print_status "Checking system requirements..."
    
    # Check if running on Debian/Ubuntu
    if ! command -v apt &> /dev/null; then
        print_error "This installer is designed for Debian/Ubuntu systems"
        exit 1
    fi
    
    # Check if systemd is available
    if ! command -v systemctl &> /dev/null; then
        print_error "systemd is required but not found"
        exit 1
    fi
    
    # Check if iptables/nftables tools are available
    if ! command -v iptables &> /dev/null && ! command -v nft &> /dev/null; then
        print_error "iptables or nftables is required but not found"
        exit 1
    fi
    
    print_success "System requirements met"
}

# Install dependencies
install_dependencies() {
    print_status "Installing dependencies..."
    
    apt update
    apt install -y \
        iptables \
        nftables \
        curl \
        wget \
        jq \
        net-tools \
        iproute2 \
        bridge-utils \
        git \
        build-essential
    
    print_success "Dependencies installed"
}

# Create directories
create_directories() {
    print_status "Creating directories..."
    
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$DATA_DIR"
    mkdir -p "$LOG_DIR"
    
    # Set proper permissions
    chown root:root "$INSTALL_DIR"
    chown root:root "$CONFIG_DIR"
    chown netnat:netnat "$DATA_DIR" 2>/dev/null || true
    chown netnat:netnat "$LOG_DIR" 2>/dev/null || true
    
    chmod 755 "$INSTALL_DIR"
    chmod 755 "$CONFIG_DIR"
    chmod 755 "$DATA_DIR"
    chmod 755 "$LOG_DIR"
    
    print_success "Directories created"
}

# Create netnat user
create_user() {
    print_status "Creating netnat user..."
    
    if ! id "netnat" &>/dev/null; then
        useradd --system --shell /bin/false --home-dir "$DATA_DIR" --create-home netnat
        print_success "User 'netnat' created"
    else
        print_warning "User 'netnat' already exists"
    fi
}

# Download and install binary
install_binary() {
    print_status "Installing NetNAT binary..."
    
    # Check if binary exists in build directory (for local install)
    if [[ -f "build/netnat" ]]; then
        print_status "Using local binary from build directory"
        cp "build/netnat" "$INSTALL_DIR/netnat"
    elif [[ -f "netnat" ]]; then
        print_status "Using binary from current directory"
        cp "netnat" "$INSTALL_DIR/netnat"
    else
        print_status "Downloading latest release from GitHub..."
        
        # Try to get latest release binary
        LATEST_URL=$(curl -s "https://api.github.com/repos/rickicode/proxmox-nat/releases/latest" | jq -r '.assets[] | select(.name=="netnat") | .browser_download_url' 2>/dev/null)
        
        if [[ -n "$LATEST_URL" && "$LATEST_URL" != "null" ]]; then
            print_status "Downloading pre-built binary..."
            if wget -O "$INSTALL_DIR/netnat" "$LATEST_URL"; then
                print_success "Downloaded pre-built binary"
            else
                print_error "Failed to download pre-built binary from GitHub"
                print_error "Please ensure you have internet connectivity"
                exit 1
            fi
        else
            print_error "No pre-built binary found in GitHub releases"
            print_error "Please check the repository: $GITHUB_REPO"
            exit 1
        fi
    fi
    
    # Set executable permissions
    chmod +x "$INSTALL_DIR/netnat"
    chown root:root "$INSTALL_DIR/netnat"
    
    print_success "NetNAT binary installed"
}

# Install configuration files
install_config() {
    print_status "Installing configuration files..."
    
    # Copy config file
    if [[ -f "configs/config.yml" ]]; then
        cp "configs/config.yml" "$CONFIG_DIR/config.yml"
        chown root:root "$CONFIG_DIR/config.yml"
        chmod 644 "$CONFIG_DIR/config.yml"
        print_success "Configuration file installed"
    else
        print_warning "Config file not found, creating default configuration"
        cat > "$CONFIG_DIR/config.yml" << 'EOF'
server:
  host: "0.0.0.0"
  port: 8080
  auth:
    username: "admin"
    password: "netnat123"

network:
  public_interface: "auto"
  bridge_interface: "vmbr0"
  enable_ipv4_forward: true
  enable_nat: true

storage:
  rules_file: "/var/lib/netnat/rules.json"
  backup_dir: "/var/lib/netnat/backups"

logging:
  level: "info"
  file: "/var/log/netnat/netnat.log"
  max_size: 10
  max_backups: 5
  max_age: 30

security:
  csrf_key: "netnat-csrf-secret-key-change-this-in-production"
  rate_limit:
    requests_per_minute: 60
    burst: 10
EOF
        chown root:root "$CONFIG_DIR/config.yml"
        chmod 644 "$CONFIG_DIR/config.yml"
    fi
    
    # Create initial rules file
    if [[ ! -f "$DATA_DIR/rules.json" ]]; then
        echo '{"rules": []}' > "$DATA_DIR/rules.json"
        chown netnat:netnat "$DATA_DIR/rules.json"
        chmod 644 "$DATA_DIR/rules.json"
    fi
    
    # Create backup directory
    mkdir -p "$DATA_DIR/backups"
    chown -R netnat:netnat "$DATA_DIR"
}

# Install systemd service
install_service() {
    print_status "Installing systemd service..."
    
    cat > "/etc/systemd/system/$SERVICE_NAME.service" << EOF
[Unit]
Description=NetNAT - Proxmox NAT & Port Forwarding Manager
Documentation=https://github.com/rickicode/proxmox-nat
After=network.target
Wants=network.target

[Service]
Type=simple
User=netnat
Group=netnat
ExecStart=$INSTALL_DIR/netnat -config $CONFIG_DIR/config.yml
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=netnat

# Security settings
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$DATA_DIR $LOG_DIR
ProtectKernelTunables=no
ProtectKernelModules=yes
ProtectControlGroups=yes

# Network capabilities
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW

# Environment
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
WorkingDirectory=$DATA_DIR

[Install]
WantedBy=multi-user.target
EOF
    
    # Reload systemd and enable service
    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    
    print_success "Systemd service installed and enabled"
}

# Configure firewall
configure_firewall() {
    print_status "Configuring firewall..."
    
    # Enable IP forwarding
    echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-netnat.conf
    sysctl -p /etc/sysctl.d/99-netnat.conf
    
    print_success "IP forwarding enabled"
}

# Start service
start_service() {
    print_status "Starting NetNAT service..."
    
    systemctl start "$SERVICE_NAME"
    
    # Wait a moment and check status
    sleep 2
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        print_success "NetNAT service started successfully"
        
        # Get service status
        local port=$(grep -E "^\s*port:" "$CONFIG_DIR/config.yml" | awk '{print $2}' | tr -d '"')
        local host=$(grep -E "^\s*host:" "$CONFIG_DIR/config.yml" | awk '{print $2}' | tr -d '"')
        
        echo ""
        echo "🎉 NetNAT installation completed successfully!"
        echo ""
        echo "📋 Service Information:"
        echo "   Status: $(systemctl is-active $SERVICE_NAME)"
        echo "   Web UI: http://${host}:${port}"
        echo "   Config: $CONFIG_DIR/config.yml"
        echo "   Data: $DATA_DIR"
        echo "   Logs: $LOG_DIR"
        echo ""
        echo "🔧 Management Commands:"
        echo "   Start:   systemctl start $SERVICE_NAME"
        echo "   Stop:    systemctl stop $SERVICE_NAME"
        echo "   Restart: systemctl restart $SERVICE_NAME"
        echo "   Status:  systemctl status $SERVICE_NAME"
        echo "   Logs:    journalctl -u $SERVICE_NAME -f"
        echo ""
        echo "🔐 Default Login:"
        echo "   Username: admin"
        echo "   Password: netnat123"
        echo ""
        echo "⚠️  Please change the default password in $CONFIG_DIR/config.yml"
        echo ""
    else
        print_error "Failed to start NetNAT service"
        print_error "Check logs with: journalctl -u $SERVICE_NAME"
        exit 1
    fi
}

# Uninstall function
uninstall() {
    print_status "Uninstalling NetNAT..."
    
    # Stop and disable service
    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    
    # Remove systemd service file
    rm -f "/etc/systemd/system/$SERVICE_NAME.service"
    systemctl daemon-reload
    
    # Remove files and directories
    rm -rf "$INSTALL_DIR"
    rm -rf "$CONFIG_DIR"
    rm -rf "$LOG_DIR"
    
    # Ask about data directory
    read -p "Remove data directory $DATA_DIR? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "$DATA_DIR"
        print_success "Data directory removed"
    fi
    
    # Remove user
    if id "netnat" &>/dev/null; then
        userdel netnat 2>/dev/null || true
        print_success "User 'netnat' removed"
    fi
    
    # Remove sysctl config
    rm -f /etc/sysctl.d/99-netnat.conf
    
    print_success "NetNAT uninstalled successfully"
}

# Main installation function
main() {
    echo "================================================"
    echo "🚀 NetNAT Installer for Proxmox/Debian"
    echo "================================================"
    echo ""
    
    case "${1:-install}" in
        "install")
            check_root
            check_requirements
            install_dependencies
            create_user
            create_directories
            install_binary
            install_config
            install_service
            configure_firewall
            start_service
            ;;
        "uninstall")
            check_root
            uninstall
            ;;
        "help"|"--help"|"-h")
            echo "Usage: $0 [install|uninstall|help]"
            echo ""
            echo "Commands:"
            echo "  install     Install NetNAT service (default)"
            echo "  uninstall   Remove NetNAT service"
            echo "  help        Show this help message"
            echo ""
            ;;
        *)
            print_error "Unknown command: $1"
            echo "Use '$0 help' for usage information"
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"