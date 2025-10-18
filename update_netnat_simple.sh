#!/bin/bash

# Simple NetNAT Update Script (Manual Mode)
# Instructions for manual update via SSH

set -e

# Configuration
PROXMOX_HOST="192.168.90.2"
REMOTE_PATH="/opt/netnat/netnat"
LOCAL_BINARY="./netnat"
BACKUP_PATH="/opt/netnat/netnat.backup.$(date +%Y%m%d_%H%M%S)"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_header() {
    echo -e "${BLUE}===============================================${NC}"
    echo -e "${BLUE}    NetNAT Manual Update Instructions         ${NC}"
    echo -e "${BLUE}===============================================${NC}"
    echo
}

print_step() {
    echo -e "${YELLOW}[STEP]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_command() {
    echo -e "${BLUE}COMMAND:${NC} $1"
}

# Main function
main() {
    print_header

    # Check if local binary exists
    print_step "Checking local binary..."
    if [ ! -f "$LOCAL_BINARY" ]; then
        echo "ERROR: Local binary not found at $LOCAL_BINARY"
        echo "Please run: go build ./cmd/netnat"
        exit 1
    fi
    print_success "Local binary found: $LOCAL_BINARY"

    echo
    print_step "Generating update commands for you..."
    echo

    echo "Please run these commands on your local machine:"
    echo
    print_command "scp ./netnat root@${PROXMOX_HOST}:/tmp/netnat.new"
    print_command "ssh root@${PROXMOX_HOST}"
    echo

    echo "Then run these commands on the Proxmox server:"
    echo
    print_command "# Create backup"
    print_command "sudo cp $REMOTE_PATH $BACKUP_PATH"
    echo
    print_command "# Stop NetNAT service"
    print_command "sudo systemctl stop netnat"
    print_command "# OR if no systemctl: sudo pkill -f netnat"
    echo
    print_command "# Replace binary"
    print_command "sudo mv /tmp/netnat.new $REMOTE_PATH"
    print_command "sudo chmod +x $REMOTE_PATH"
    print_command "sudo chown root:root $REMOTE_PATH"
    echo
    print_command "# Start NetNAT service"
    print_command "sudo systemctl start netnat"
    print_command "# OR if no systemctl: nohup $REMOTE_PATH > /var/log/netnat.log 2>&1 &"
    echo
    print_command "# Check status"
    print_command "sudo systemctl status netnat"
    print_command "curl http://localhost:8080"
    echo

    echo "If something goes wrong, restore with:"
    print_command "sudo cp $BACKUP_PATH $REMOTE_PATH"
    print_command "sudo systemctl restart netnat"
    echo

    print_success "Instructions generated! Follow the commands above."
}

main "$@"