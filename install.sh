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

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

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
        echo "Please run: sudo su -c \"$0\""
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
    chown root:root "$DATA_DIR"
    chown root:root "$LOG_DIR"
    
    chmod 755 "$INSTALL_DIR"
    chmod 755 "$CONFIG_DIR"
    chmod 755 "$DATA_DIR"
    chmod 755 "$LOG_DIR"
    
    print_success "Directories created"
}

# Remove netnat user function
create_user() {
    print_status "Skipping user creation. Running as root."
}

# Get installed version
get_installed_version() {
    if [[ -f "$INSTALL_DIR/netnat" ]]; then
        "$INSTALL_DIR/netnat" --version 2>/dev/null | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' || echo "unknown"
    else
        echo "not_installed"
    fi
}

# Get latest version from GitHub
get_latest_version() {
    curl -s "https://api.github.com/repos/rickicode/proxmox-nat/releases/latest" | jq -r '.tag_name' 2>/dev/null || echo "unknown"
}

# Download and install binary
install_binary() {
    print_status "Installing NetNAT binary..."
    
    local force_update="${1:-false}"
    local installed_version=""
    local latest_version=""
    
    # Check if binary exists locally
    if [[ -f "$SCRIPT_DIR/build/netnat" ]]; then
        cp "$SCRIPT_DIR/build/netnat" "$INSTALL_DIR/netnat"
    elif [[ -f "$SCRIPT_DIR/netnat" ]]; then
        cp "$SCRIPT_DIR/netnat" "$INSTALL_DIR/netnat"
    else
        print_status "Checking for latest release from GitHub..."
        
        # Get current and latest versions
        installed_version=$(get_installed_version)
        latest_version=$(get_latest_version)
        
        print_status "Installed version: $installed_version"
        print_status "Latest version: $latest_version"
        
        # Check if update is needed
        if [[ "$installed_version" != "not_installed" && "$installed_version" == "$latest_version" && "$force_update" != "true" ]]; then
            print_success "NetNAT is already up to date ($installed_version)"
            return 0
        fi
        
        if [[ "$installed_version" != "not_installed" && "$installed_version" != "$latest_version" ]]; then
            print_status "Update available: $installed_version → $latest_version"
        fi
        
        # Detect architecture
        local arch=$(uname -m)
        local binary_name="netnat"
        case $arch in
            x86_64)  binary_name="netnat-linux-amd64" ;;
            aarch64) binary_name="netnat-linux-arm64" ;;
            armv7l)  binary_name="netnat-linux-armv7" ;;
            *)       binary_name="netnat" ;;
        esac
        
        # Try to get latest release binary
        LATEST_URL=$(curl -s "https://api.github.com/repos/rickicode/proxmox-nat/releases/latest" | jq -r ".assets[] | select(.name==\"$binary_name\") | .browser_download_url" 2>/dev/null)
        
        # Fallback to generic binary name
        if [[ -z "$LATEST_URL" || "$LATEST_URL" == "null" ]]; then
            print_warning "Architecture-specific binary not found, trying generic binary..."
            LATEST_URL=$(curl -s "https://api.github.com/repos/rickicode/proxmox-nat/releases/latest" | jq -r '.assets[] | select(.name=="netnat") | .browser_download_url' 2>/dev/null)
        fi
        
        if [[ -n "$LATEST_URL" && "$LATEST_URL" != "null" ]]; then
            print_status "Downloading pre-built binary from: $LATEST_URL"
            
            # Backup existing binary if it exists
            if [[ -f "$INSTALL_DIR/netnat" ]]; then
                cp "$INSTALL_DIR/netnat" "$INSTALL_DIR/netnat.backup"
                print_status "Backed up existing binary"
            fi
            
            # Download new binary
            if wget -O "$INSTALL_DIR/netnat.new" "$LATEST_URL"; then
                # Verify the download
                if [[ -f "$INSTALL_DIR/netnat.new" && -s "$INSTALL_DIR/netnat.new" ]]; then
                    mv "$INSTALL_DIR/netnat.new" "$INSTALL_DIR/netnat"
                    rm -f "$INSTALL_DIR/netnat.backup"
                    print_success "Downloaded and installed latest binary ($latest_version)"
                else
                    print_error "Downloaded file is empty or corrupt"
                    if [[ -f "$INSTALL_DIR/netnat.backup" ]]; then
                        mv "$INSTALL_DIR/netnat.backup" "$INSTALL_DIR/netnat"
                        print_status "Restored backup binary"
                    fi
                    exit 1
                fi
            else
                print_error "Failed to download pre-built binary from GitHub"
                if [[ -f "$INSTALL_DIR/netnat.backup" ]]; then
                    mv "$INSTALL_DIR/netnat.backup" "$INSTALL_DIR/netnat"
                    print_status "Restored backup binary"
                fi
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
    print_status "Checking configuration files..."

    # Skip if config already exists (upgrade scenario)
    if [[ -f "$CONFIG_DIR/config.yml" ]]; then
        print_status "Configuration file already exists, skipping config installation"
        return 0
    fi

    # Copy config file if it exists
    if [[ -f "$SCRIPT_DIR/configs/config.yml" ]]; then
        cp "$SCRIPT_DIR/configs/config.yml" "$CONFIG_DIR/config.yml"
        chown root:root "$CONFIG_DIR/config.yml"
        chmod 644 "$CONFIG_DIR/config.yml"
        print_success "Configuration file installed"
    else
        print_warning "Config file not found, creating default configuration"
        cat > "$CONFIG_DIR/config.yml" << 'EOF'
server:
  listen_addr: "0.0.0.0:8080"
  username: "admin"
  password: "netnat123"

network:
  public_interface: "auto"
  internal_bridge: "vmbr1"
  port_range:
    min: 1
    max: 65535
    exclude:
      - 22
      - 8006
      - 8007
      - 8080

storage:
  rules_file: "/var/lib/netnat/rules.json"
  backup_enabled: true
  backup_dir: "/var/lib/netnat/backups"
  backup_retention: 30
  auto_backup: true
  daily_backup: true

security:
  csrf_enabled: true
  rate_limit: 60
EOF
        chown root:root "$CONFIG_DIR/config.yml"
        chmod 644 "$CONFIG_DIR/config.yml"
    fi
    
    # Create initial rules file
    if [[ ! -f "$DATA_DIR/rules.json" ]]; then
        echo '{"rules": []}' > "$DATA_DIR/rules.json"
        chown root:root "$DATA_DIR/rules.json"
        chmod 644 "$DATA_DIR/rules.json"
    fi
    
    # Create backup directory
    mkdir -p "$DATA_DIR/backups"
    chown -R root:root "$DATA_DIR"
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
User=root
Group=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/netnat -config $CONFIG_DIR/config.yml
Restart=always
RestartSec=5
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
StandardOutput=journal
StandardError=journal
SyslogIdentifier=netnat

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
        local listen_addr=$(grep -E "^\s*listen_addr:" "$CONFIG_DIR/config.yml" | awk '{print $2}' | tr -d '"')
        local host=$(echo "$listen_addr" | cut -d':' -f1)
        local port=$(echo "$listen_addr" | cut -d':' -f2)
        
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

# Update function
update() {
    print_status "Updating NetNAT to latest version..."
    
    # Check if service is running
    local was_running=false
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        was_running=true
        print_status "Stopping service for update..."
        systemctl stop "$SERVICE_NAME"
    fi
    
    # Force update binary
    install_binary "true"
    
    # Restart service if it was running
    if [[ "$was_running" == "true" ]]; then
        print_status "Restarting service..."
        systemctl start "$SERVICE_NAME"
        
        # Check if service started successfully
        sleep 2
        if systemctl is-active --quiet "$SERVICE_NAME"; then
            print_success "NetNAT updated and service restarted successfully"
        else
            print_error "Service failed to start after update"
            print_error "Check logs with: journalctl -u $SERVICE_NAME"
            exit 1
        fi
    else
        print_success "NetNAT updated successfully"
    fi
}

# Check version function
check_version() {
    local installed_version=$(get_installed_version)
    local latest_version=$(get_latest_version)
    
    echo "📦 NetNAT Version Information:"
    echo "   Installed: $installed_version"
    echo "   Latest:    $latest_version"
    echo ""
    
    if [[ "$installed_version" == "not_installed" ]]; then
        echo "❌ NetNAT is not installed"
        echo "   Run: $0 install"
    elif [[ "$installed_version" == "$latest_version" ]]; then
        echo "✅ NetNAT is up to date"
    else
        echo "⚠️  Update available!"
        echo "   Run: $0 update"
    fi
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
        "update")
            check_root
            update
            ;;
        "uninstall")
            check_root
            uninstall
            ;;
        "version")
            check_version
            ;;
        "help"|"--help"|"-h")
            echo "Usage: $0 [install|update|uninstall|version|help]"
            echo ""
            echo "Commands:"
            echo "  install     Install NetNAT service (default)"
            echo "  update      Update NetNAT to latest version"
            echo "  uninstall   Remove NetNAT service"
            echo "  version     Check version information"
            echo "  help        Show this help message"
            echo ""
            echo "Examples:"
            echo "  curl -sSL https://raw.githubusercontent.com/rickicode/proxmox-nat/main/install.sh | sudo bash"
            echo "  curl -sSL https://raw.githubusercontent.com/rickicode/proxmox-nat/main/install.sh | sudo bash -s update"
            echo "  curl -sSL https://raw.githubusercontent.com/rickicode/proxmox-nat/main/install.sh | sudo bash -s version"
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