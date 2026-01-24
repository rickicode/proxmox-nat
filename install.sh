#!/bin/bash

# NetNAT Installer Script for Proxmox/Debian
# Installs NetNAT from GitHub Releases

set -e

# Configuration
REPO="rickicode/proxmox-nat"
INSTALL_DIR="/opt/netnat"
CONFIG_DIR="$INSTALL_DIR"
DATA_DIR="$INSTALL_DIR/data"
LOG_DIR="$INSTALL_DIR/logs"
SERVICE_NAME="netnat"
GITHUB_RAW="https://raw.githubusercontent.com/$REPO/main"

# output colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check root
if [[ $EUID -ne 0 ]]; then
   print_error "This script must be run as root"
   exit 1
fi

detect_arch() {
    ARCH=$(uname -m)
    case $ARCH in
        x86_64)  ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        armv7l)  ARCH="armv7" ;;
        *)
            print_error "Unsupported architecture: $ARCH"
            exit 1
            ;;
    esac
    print_status "Detected architecture: $ARCH"
}

check_requirements() {
    print_status "Checking requirements..."
    if ! command -v curl &> /dev/null; then
        apt update && apt install -y curl
    fi
    # Install core dependencies if missing
    DEPS="iptables nftables wget net-tools iproute2 bridge-utils"
    for dep in $DEPS; do
        if ! dpkg -s $dep >/dev/null 2>&1; then
            print_status "Installing missing dependency: $dep"
            apt install -y $dep
        fi
    done
}

create_directories() {
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$DATA_DIR/backups"
    mkdir -p "$LOG_DIR"
}

get_latest_version() {
    curl -s "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/'
}

install_binary() {
    print_status "Downloading latest release from GitHub..."
    detect_arch
    VERSION=$(get_latest_version)
    if [[ -z "$VERSION" ]]; then
        print_error "Failed to fetch latest version from GitHub"
        exit 1
    fi
    
    print_status "Downloading version $VERSION..."
    DOWNLOAD_URL="https://github.com/$REPO/releases/download/$VERSION/netnat-linux-$ARCH"
    
    if ! curl -L -o "$INSTALL_DIR/netnat" "$DOWNLOAD_URL"; then
        print_error "Failed to download binary"
        exit 1
    fi
    
    chmod 755 "$INSTALL_DIR/netnat"
}

install_config() {
    if [[ ! -f "$CONFIG_DIR/config.yml" ]]; then
        print_status "Downloading default configuration from GitHub..."
        curl -L -o "$CONFIG_DIR/config.yml" "$GITHUB_RAW/configs/config.yml"
    else
        print_status "Configuration already exists"
    fi

    # Ensure rules file exists
    if [[ ! -f "$DATA_DIR/rules.json" ]]; then
        echo '{"rules": []}' > "$DATA_DIR/rules.json"
    fi
}

install_service() {
    print_status "Installing systemd service..."
    SERVICE_PATH="/etc/systemd/system/$SERVICE_NAME.service"
    
    print_status "Downloading service file from GitHub..."
    curl -L -o "$SERVICE_PATH" "$GITHUB_RAW/systemd/netnat.service"
    
    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    systemctl restart "$SERVICE_NAME"
}

main() {
    echo "================================================"
    echo "🚀 NetNAT Installer"
    echo "================================================"
    
    if [[ "$1" == "uninstall" ]]; then
        systemctl stop "$SERVICE_NAME" || true
        systemctl disable "$SERVICE_NAME" || true
        rm -f "/etc/systemd/system/$SERVICE_NAME.service"
        systemctl daemon-reload
        rm -f "$INSTALL_DIR/netnat"
        print_success "Uninstalled service and binary. Data preserved in $INSTALL_DIR"
        exit 0
    fi

    check_requirements
    create_directories
    install_binary
    install_config
    install_service
    
    print_success "Installation Complete!"
    
    # Extract port from config
    PORT="8080"
    if [[ -f "$CONFIG_DIR/config.yml" ]]; then
        DETECTED_PORT=$(grep "listen_addr" "$CONFIG_DIR/config.yml" | sed -E 's/.*:([0-9]+).*/\1/' | head -n 1)
        if [[ -n "$DETECTED_PORT" ]]; then
            PORT="$DETECTED_PORT"
        fi
    fi
    
    echo "Web Interface: http://localhost:$PORT"
}

main "$@"
