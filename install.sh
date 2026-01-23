#!/bin/bash

# NetNAT Installer Script for Proxmox/Debian
# This script installs NetNAT service from local build
# For users who don't use GitHub - install directly from built binary

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration (MUST match Makefile)
INSTALL_DIR="/opt/netnat"
CONFIG_DIR="/etc/netnat"
DATA_DIR="/var/lib/netnat"
LOG_DIR="/var/log/netnat"
SERVICE_NAME="netnat"

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
        net-tools \
        iproute2 \
        bridge-utils
    
    print_success "Dependencies installed"
}

# Create directories
create_directories() {
    print_status "Creating directories..."
    
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$CONFIG_DIR/backups"
    mkdir -p "$DATA_DIR"
    mkdir -p "$DATA_DIR/backups"
    mkdir -p "$LOG_DIR"
    
    print_success "Directories created"
}

# Install binary from local build
install_binary() {
    print_status "Installing NetNAT binary..."
    
    # Check if binary exists locally
    if [[ -f "$SCRIPT_DIR/build/netnat" ]]; then
        print_status "Found binary in $SCRIPT_DIR/build/netnat"
        cp "$SCRIPT_DIR/build/netnat" "$INSTALL_DIR/netnat"
    elif [[ -f "$SCRIPT_DIR/netnat" ]]; then
        print_status "Found binary in $SCRIPT_DIR/netnat"
        cp "$SCRIPT_DIR/netnat" "$INSTALL_DIR/netnat"
    else
        print_error "Binary not found!"
        print_error "Please build first with: make build"
        print_error "Or ensure binary exists in: $SCRIPT_DIR/build/netnat"
        exit 1
    fi
    
    # Set executable permissions
    chmod 755 "$INSTALL_DIR/netnat"
    chown root:root "$INSTALL_DIR/netnat"
    
    print_success "NetNAT binary installed to $INSTALL_DIR/netnat"
}

# Install configuration files
install_config() {
    print_status "Installing configuration files..."
    
    # Copy example config
    if [[ -f "$SCRIPT_DIR/configs/config.yml" ]]; then
        cp "$SCRIPT_DIR/configs/config.yml" "$CONFIG_DIR/config.yml.example"
        print_success "Example config installed"
        
        # Only create config.yml if it doesn't exist
        if [[ ! -f "$CONFIG_DIR/config.yml" ]]; then
            cp "$SCRIPT_DIR/configs/config.yml" "$CONFIG_DIR/config.yml"
            print_success "Default configuration created"
        else
            print_status "Configuration already exists (not overwritten)"
        fi
    else
        print_error "Config file not found at $SCRIPT_DIR/configs/config.yml"
        exit 1
    fi
    
    # Create initial rules file if it doesn't exist
    if [[ ! -f "$DATA_DIR/rules.json" ]]; then
        echo '{"rules": []}' > "$DATA_DIR/rules.json"
        print_success "Initial rules file created"
    fi
}

# Set permissions
set_permissions() {
    print_status "Setting permissions..."
    
    # Binary directory
    chown -R root:root "$INSTALL_DIR"
    chmod 755 "$INSTALL_DIR"
    
    # Config directory
    chown -R root:root "$CONFIG_DIR"
    chmod 750 "$CONFIG_DIR"
    chmod 640 "$CONFIG_DIR"/*.yml 2>/dev/null || true
    
    # Data directory
    chown -R root:root "$DATA_DIR"
    chmod 750 "$DATA_DIR"
    
    # Log directory
    chown -R root:root "$LOG_DIR"
    chmod 755 "$LOG_DIR"
    
    print_success "Permissions set"
}

# Install systemd service
install_service() {
    print_status "Installing systemd service..."
    
    # Check if systemd service file exists in repo
    if [[ -f "$SCRIPT_DIR/systemd/netnat.service" ]]; then
        cp "$SCRIPT_DIR/systemd/netnat.service" "/etc/systemd/system/$SERVICE_NAME.service"
        print_success "Systemd service file installed"
    else
        print_error "Systemd service file not found at $SCRIPT_DIR/systemd/netnat.service"
        exit 1
    fi
    
    # Reload systemd
    systemctl daemon-reload
    
    print_success "Systemd service installed"
}

# Configure system
configure_system() {
    print_status "Configuring system..."
    
    # Enable IP forwarding
    if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf 2>/dev/null; then
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
        sysctl -p
        print_success "IP forwarding enabled"
    else
        print_status "IP forwarding already enabled"
    fi
}

# Start service
start_service() {
    print_status "Starting NetNAT service..."
    
    # Enable service
    systemctl enable "$SERVICE_NAME"
    
    # Start service
    systemctl start "$SERVICE_NAME"
    
    # Wait a moment and check status
    sleep 2
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        print_success "NetNAT service started successfully"
        
        echo ""
        echo "================================================"
        echo "🎉 NetNAT Installation Complete!"
        echo "================================================"
        echo ""
        echo "📋 Service Information:"
        echo "   Binary:  $INSTALL_DIR/netnat"
        echo "   Config:  $CONFIG_DIR/config.yml"
        echo "   Data:    $DATA_DIR"
        echo "   Logs:    $LOG_DIR"
        echo ""
        echo "🔧 Management Commands:"
        echo "   Start:   systemctl start $SERVICE_NAME"
        echo "   Stop:    systemctl stop $SERVICE_NAME"
        echo "   Restart: systemctl restart $SERVICE_NAME"
        echo "   Status:  systemctl status $SERVICE_NAME"
        echo "   Logs:    journalctl -u $SERVICE_NAME -f"
        echo ""
        echo "🌐 Access web interface at: http://localhost:8080"
        echo "🔐 Default credentials: admin / netnat123"
        echo ""
        echo "⚠️  IMPORTANT: Change default password and JWT secret in $CONFIG_DIR/config.yml"
        echo ""
    else
        print_error "Failed to start NetNAT service"
        print_error "Check logs with: journalctl -u $SERVICE_NAME -xe"
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
    
    # Remove binary
    rm -f "$INSTALL_DIR/netnat"
    
    # Ask about config and data
    echo ""
    read -p "Remove configuration directory $CONFIG_DIR? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "$CONFIG_DIR"
        print_success "Configuration directory removed"
    else
        print_status "Configuration directory preserved"
    fi
    
    echo ""
    read -p "Remove data directory $DATA_DIR? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "$DATA_DIR"
        print_success "Data directory removed"
    else
        print_status "Data directory preserved"
    fi
    
    # Remove log directory
    rm -rf "$LOG_DIR"
    
    # Remove install directory if empty
    rmdir "$INSTALL_DIR" 2>/dev/null || true
    
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
            create_directories
            install_binary
            install_config
            set_permissions
            install_service
            configure_system
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
            echo "  install     Install NetNAT service from local build (default)"
            echo "  uninstall   Remove NetNAT service"
            echo "  help        Show this help message"
            echo ""
            echo "Prerequisites:"
            echo "  1. Build the binary first: make build"
            echo "  2. Run installer: sudo ./install.sh"
            echo ""
            echo "Or use Makefile directly:"
            echo "  sudo make install    # Build and install in one command"
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
