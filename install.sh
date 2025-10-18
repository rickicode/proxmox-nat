#!/bin/bash

# NetNAT Installer Script for Proxmox/Debian
# Enhanced with Interactive Setup Wizard and Configuration Preservation

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

# Parse command line arguments
FRESH_INSTALL=false
NON_INTERACTIVE=false

for arg in "$@"; do
    case $arg in
        --fresh-install)
            FRESH_INSTALL=true
            ;;
        --non-interactive)
            NON_INTERACTIVE=true
            ;;
    esac
done

# Global variables for network detection
detected_interfaces=()
detected_bridges=()
default_route_iface=""

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
        echo "Please run: sudo su -c \"$0 $*\""
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
        build-essential \
        vnstat \
        bc

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

    # Skip if config already exists (unless fresh install)
    if [[ -f "$CONFIG_DIR/config.yml" && "$FRESH_INSTALL" != "true" ]]; then
        print_status "Configuration file already exists, preserving existing config"
        return 0
    fi

    # Create default configuration if none exists or fresh install requested
    if [[ ! -f "$CONFIG_DIR/config.yml" ]] || [[ "$FRESH_INSTALL" == "true" ]]; then
        if [[ "$FRESH_INSTALL" == "true" ]]; then
            print_status "Fresh install requested, creating new configuration..."
            if [[ -f "$CONFIG_DIR/config.yml" ]]; then
                cp "$CONFIG_DIR/config.yml" "$CONFIG_DIR/config.yml.backup.$(date +%Y%m%d_%H%M%S)"
                print_status "Existing config backed up"
            fi
        fi

        create_default_config
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

# Create default configuration
create_default_config() {
    local public_iface="${1:-auto}"
    local internal_bridge="${2:-vmbr1}"

    cat > "$CONFIG_DIR/config.yml" << EOF
server:
  listen_addr: "0.0.0.0:8080"
  username: "admin"
  password: "netnat123"

network:
  public_interface: "$public_iface"
  internal_bridge: "$internal_bridge"
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
    print_success "Configuration file created"
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

# Configure firewall and network
configure_firewall() {
    print_status "Configuring firewall and network settings..."

    # Enable IP forwarding
    echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-netnat.conf
    echo 'net.ipv6.conf.all.forwarding=1' >> /etc/sysctl.d/99-netnat.conf
    sysctl -p /etc/sysctl.d/99-netnat.conf

    # Configure bridge networks for VMs
    configure_bridge_networks

    # Set up NAT rules for internal networks
    configure_nat_rules

    print_success "Network configuration completed"
}

# Configure bridge networks for VMs
configure_bridge_networks() {
    print_status "Configuring VM bridge networks..."

    # Get Proxmox bridges
    bridges=($(brctl show | grep -E '^[a-zA-Z]' | awk '{print $1}'))

    if [ ${#bridges[@]} -eq 0 ]; then
        print_warning "No bridges found. Creating default vmbr1..."
        create_default_bridge
    else
        print_status "Found bridges: ${bridges[*]}"

        # Configure each bridge for VM access
        for bridge in "${bridges[@]}"; do
            configure_bridge_interface "$bridge"
        done
    fi

    print_success "Bridge networks configured"
}

# Create default bridge if none exists
create_default_bridge() {
    # Get first available network interface
    primary_iface=$(ip route | grep default | awk '{print $5}' | head -1)

    if [ -z "$primary_iface" ]; then
        print_error "No network interface found for bridge creation"
        return 1
    fi

    print_status "Creating vmbr1 bridge using $primary_iface..."

    # Create bridge configuration
    cat > /etc/network/interfaces.d/vmbr1 << EOF
auto vmbr1
iface vmbr1 inet static
    address 192.168.100.1
    netmask 255.255.255.0
    bridge_ports $primary_iface
    bridge_stp off
    bridge_fd 0
    post-up echo 1 > /proc/sys/net/ipv4/ip_forward
    post-up iptables -t nat -A POSTROUTING -s 192.168.100.0/24 -o $primary_iface -j MASQUERADE
    post-down iptables -t nat -D POSTROUTING -s 192.168.100.0/24 -o $primary_iface -j MASQUERADE
EOF

    # Bring up the bridge
    ifup vmbr1 2>/dev/null || systemctl restart networking 2>/dev/null

    print_success "Default bridge vmbr1 created with 192.168.100.1/24"
}

# Configure individual bridge interface
configure_bridge_interface() {
    local bridge="$1"

    # Get bridge IP and subnet
    bridge_ip=$(ip addr show "$bridge" | grep -oP 'inet \K[\d.]+' | head -1)

    if [ -z "$bridge_ip" ]; then
        print_warning "Bridge $bridge has no IP address"
        return 1
    fi

    # Get bridge subnet (assuming /24 for simplicity)
    bridge_subnet="${bridge_ip}.0/24"

    # Add NAT rule for this bridge
    local external_iface=$(ip route | grep default | awk '{print $5}')
    if [ -n "$external_iface" ]; then
        # Add persistent NAT rule
        add_nat_rule "$bridge_subnet" "$external_iface" "$bridge"
    fi
}

# Configure NAT rules
configure_nat_rules() {
    print_status "Setting up NAT rules for VM networks..."

    # Get all bridge interfaces
    bridges=($(brctl show | grep -E '^[a-zA-Z]' | awk '{print $1}'))

    for bridge in "${bridges[@]}"; do
        bridge_ip=$(ip addr show "$bridge" | grep -oP 'inet \K[\d.]+' | head -1)
        if [ -n "$bridge_ip" ]; then
            # Get external interface
            external_iface=$(ip route | grep default | awk '{print $5}')
            if [ -n "$external_iface" ]; then
                bridge_subnet="${bridge_ip}.0/24"
                add_nat_rule "$bridge_subnet" "$external_iface" "$bridge"
            fi
        fi
    done

    # Add rule for same-subnet access (critical for your use case)
    configure_same_subnet_nat

    print_success "NAT rules configured"
}

# Add persistent NAT rule
add_nat_rule() {
    local subnet="$1"
    local external_iface="$2"
    local bridge="$3"

    # Create iptables rule
    iptables -t nat -A POSTROUTING -s "$subnet" -o "$external_iface" -j MASQUERADE 2>/dev/null

    # Save to persistence
    if command -v iptables-save &> /dev/null; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    fi

    print_status "Added NAT rule for $bridge ($subnet) via $external_iface"
}

# Configure same-subnet NAT (VMs access Proxmox host)
configure_same_subnet_nat() {
    print_status "Configuring same-subnet access for VMs..."

    # Get all network interfaces
    interfaces=($(ip link show | grep -E '^[0-9]+:' | awk -F': ' '{print $2}' | grep -v lo))

    for iface in "${interfaces[@]}"; do
        # Skip bridges (handled separately)
        if [[ "$iface" == vmbr* ]]; then
            continue
        fi

        iface_ip=$(ip addr show "$iface" | grep -oP 'inet \K[\d.]+' | head -1)
        if [ -n "$iface_ip" ]; then
            # Add rule for same subnet access
            iptables -t nat -A POSTROUTING -s "${iface_ip}.0/24" -o "$iface" -j MASQUERADE 2>/dev/null
        fi
    done

    print_success "Same-subnet NAT configured"
}

# Detect and recommend network configuration
detect_network_configuration() {
    print_status "Detecting network configuration..."

    # Get Proxmox IP and subnet
    proxmox_ip=$(hostname -I | awk '{print $1}')
    if [ -n "$proxmox_ip" ]; then
        proxmox_subnet=$(echo "$proxmox_ip" | awk -F. '{print $1"."$2"."$3".0/24"}')
        print_status "Proxmox IP: $proxmox_ip (Subnet: $proxmox_subnet)"

        # Check for existing bridges
        bridges=($(brctl show | grep -E '^[a-zA-Z]' | awk '{print $1}'))
        if [ ${#bridges[@]} -gt 0 ]; then
            print_status "Existing bridges: ${bridges[*]}"

            for bridge in "${bridges[@]}"; do
                bridge_ip=$(ip addr show "$bridge" | grep -oP 'inet \K[\d.]+' | head -1)
                if [ -n "$bridge_ip" ]; then
                    bridge_subnet=$(echo "$bridge_ip" | awk -F. '{print $1"."$2"."$3".0/24}')

                    if [ "$bridge_subnet" == "$proxmox_subnet" ]; then
                        print_status "$bridge is in same subnet as Proxmox ($bridge_subnet)"
                    else
                        print_status "$bridge is in different subnet ($bridge_subnet)"
                    fi
                fi
            done
        fi
    fi

    print_success "Network detection completed"
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

# Detect available network interfaces with details
detect_available_interfaces() {
    print_status "Detecting network interfaces..."

    # Get non-loopback interfaces
    mapfile -t detected_interfaces < <(ip link show | grep -E '^[0-9]+:' | awk -F': ' '{print $2}' | grep -v lo)

    # Get default route interface
    default_route_iface=$(ip route | grep default | awk '{print $5}')

    # Get bridge interfaces
    mapfile -t detected_bridges < <(brctl show | grep -E '^[a-zA-Z]' | awk '{print $1}')

    print_success "Network interface detection completed"
}

# Get IP address of interface
get_interface_ip() {
    local iface="$1"
    ip addr show "$iface" 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1
}

# Interactive interface selection wizard
interactive_network_setup() {
    echo "================================================"
    echo "🌐 NetNAT Network Configuration Wizard"
    echo "================================================"
    echo

    # Detect available interfaces first
    detect_available_interfaces

    echo "This wizard will help you configure NetNAT for optimal performance."
    echo "Please answer the following questions:"
    echo

    # Public Interface Selection
    echo "📡 QUESTION 1: Which interface should be your PUBLIC/GATEWAY interface?"
    echo "   This interface connects to the internet/modem and handles all external traffic."
    echo ""

    local public_interface=""
    local public_options=()
    local i=1

    # Display detected interfaces with details
    for iface in "${detected_interfaces[@]}"; do
        local ip=$(get_interface_ip "$iface")
        local default_marker=""

        if [ "$iface" == "$default_route_iface" ]; then
            default_marker=" 📍 (DEFAULT ROUTE)"
        fi

        local description=""
        if [[ "$iface" == vmbr* ]]; then
            description=" - Bridge Interface"
        elif [[ "$iface" == eth* || "$iface" == en* ]]; then
            description=" - Ethernet Interface"
        elif [[ "$iface" == wlan* ]]; then
            description=" - Wireless Interface"
        fi

        echo "   $i) $iface${default_marker} - IP: $ip$description"
        public_options+=("$iface")
        ((i++))
    done

    echo "   a) Auto-detect (Recommended)"
    echo
    read -p "Select public interface [1-${#public_options[@]}, a]: " public_choice

    case "$public_choice" in
        "a"|"A"|"")
            public_interface="auto"
            print_status "Auto-detection selected for public interface"
            ;;
        *)
            if [[ "$public_choice" =~ ^[0-9]+$ ]] && [ "$public_choice" -ge 1 ] && [ "$public_choice" -le ${#public_options[@]} ]; then
                public_interface="${public_options[$((public_choice-1))]}"
                print_status "Selected public interface: $public_interface"
            else
                print_error "Invalid choice. Using auto-detection."
                public_interface="auto"
            fi
            ;;
    esac

    echo

    # Internal Bridge Selection
    echo "🌉 QUESTION 2: Which bridge should be your INTERNAL/VM network?"
    echo "   This bridge will be used by your VMs and containers for internal networking."
    echo "   Port forwarding rules will route traffic from public to internal networks."
    echo ""

    local internal_bridge=""
    local internal_options=()
    local i=1

    # Display detected bridges with details
    if [ ${#detected_bridges[@]} -gt 0 ]; then
        for bridge in "${detected_bridges[@]}"; do
            local ip=$(get_interface_ip "$bridge")
            local description="VM Bridge"

            # Check if bridge is in same subnet as Proxmox
            local proxmox_ip=$(hostname -I | awk '{print $1}')
            if [ -n "$proxmox_ip" ] && [ -n "$ip" ]; then
                local proxmox_subnet=$(echo "$proxmox_ip" | awk -F. '{print $1"."$2"."$3}')
                local bridge_subnet=$(echo "$ip" | awk -F. '{print $1"."$2"."$3}')

                if [ "$bridge_subnet" = "$proxmox_subnet" ]; then
                    description="$description (Same subnet as Proxmox)"
                else
                    description="$description (Different subnet)"
                fi
            fi

            echo "   $i) $bridge - IP: $ip - $description"
            internal_options+=("$bridge")
            ((i++))
        done

        echo "   a) Create new bridge (192.168.100.0/24)"
        echo "   s) Skip - Use existing configuration"
        echo
    else
        echo "   No existing bridges detected."
        echo "   1) Create new bridge vmbr1 (192.168.100.0/24)"
        echo "   s) Skip - Use default configuration"
        echo
        internal_options=("vmbr1")
    fi

    read -p "Select internal bridge [${#internal_options[@]}, a, s]: " internal_choice

    case "$internal_choice" in
        "a"|"A")
            internal_bridge="auto"
            print_status "Will create new bridge automatically"
            ;;
        "s"|"S"|"")
            internal_bridge="skip"
            print_status "Skipping bridge configuration"
            ;;
        *)
            if [[ "$internal_choice" =~ ^[0-9]+$ ]] && [ "$internal_choice" -ge 1 ] && [ "$internal_choice" -le ${#internal_options[@]} ]; then
                internal_bridge="${internal_options[$((internal_choice-1))]}"
                print_status "Selected internal bridge: $internal_bridge"
            else
                print_error "Invalid choice. Using default configuration."
                internal_bridge="auto"
            fi
            ;;
    esac

    echo

    # Confirmation
    echo "📋 Configuration Summary:"
    echo "   Public Interface: $public_interface"
    echo "   Internal Bridge: $internal_bridge"
    echo

    read -p "Do you want to proceed with this configuration? [Y/n]: " confirm
    if [[ "$confirm" =~ ^[Nn]$ ]]; then
        print_error "Installation cancelled by user."
        exit 1
    fi

    # Update configuration file
    update_config_file "$public_interface" "$internal_bridge"
}

# Update configuration file with user choices
update_config_file() {
    local public_iface="$1"
    local internal_bridge="$2"

    if [ ! -f "$CONFIG_DIR/config.yml" ]; then
        # Create new config file
        create_default_config "$public_iface" "$internal_bridge"
    else
        # Update existing config file
        update_existing_config "$public_iface" "$internal_bridge"
    fi
}

# Update existing configuration file
update_existing_config() {
    local public_iface="$1"
    local internal_bridge="$2"

    # Backup existing config
    cp "$CONFIG_DIR/config.yml" "$CONFIG_DIR/config.yml.backup.$(date +%Y%m%d_%H%M%S)"

    # Update network section
    sed -i "s/^public_interface:.*/public_interface: \"$public_iface\"/" "$CONFIG_DIR/config.yml"
    sed -i "s/^internal_bridge:.*/internal_bridge: \"$internal_bridge\"/" "$CONFIG_DIR/config.yml"

    print_success "Configuration file updated with new network settings"
    print_info "Backup saved: $CONFIG_DIR/config.yml.backup.$(date +%Y%m%d_%H%M%S)"
}

# Main installation function
main() {
    echo "================================================"
    echo "🚀 NetNAT Installer for Proxmox/Debian (Enhanced)"
    echo "================================================"
    echo ""

    case "${1:-install}" in
        "install")
            check_root
            check_requirements
            install_dependencies

            # Run interactive network setup wizard
            if [ "$NON_INTERACTIVE" != "true" ]; then
                interactive_network_setup
            fi

            # Network detection and configuration
            detect_network_configuration
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
            echo "Usage: $0 [install|update|uninstall|version|help] [options]"
            echo ""
            echo "Commands:"
            echo "  install     Install NetNAT service (default)"
            echo "  update      Update NetNAT to latest version"
            echo "  uninstall   Remove NetNAT service"
            echo "  version     Check version information"
            echo "  help        Show this help message"
            echo ""
            echo "Options:"
            echo "  --non-interactive  Skip interactive setup wizard"
            echo "  --fresh-install      Remove existing config and create new one"
            echo ""
            echo "Examples:"
            echo "  $0                     # Interactive setup (recommended)"
            echo "  $0 --non-interactive  # Automatic setup with defaults"
            echo "  $0 --fresh-install      # Remove config and reinstall"
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