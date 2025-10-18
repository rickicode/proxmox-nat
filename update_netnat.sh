#!/bin/bash

# NetNAT Update Script
# Updates NetNAT binary on Proxmox server via SFTP

set -e  # Exit on any error

# Configuration
PROXMOX_HOST="192.168.90.2"
PROXMOX_USER="root"
PROXMOX_PASSWORD="p1kunPISAN"
REMOTE_PATH="/opt/netnat/netnat"
LOCAL_BINARY="./netnat"
BACKUP_PATH="/opt/netnat/netnat.backup.$(date +%Y%m%d_%H%M%S)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
print_header() {
    echo -e "${BLUE}===============================================${NC}"
    echo -e "${BLUE}       NetNAT Binary Update Script             ${NC}"
    echo -e "${BLUE}===============================================${NC}"
    echo
}

print_step() {
    echo -e "${YELLOW}[STEP]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# Check if local binary exists
check_local_binary() {
    print_step "Checking local binary..."
    if [ ! -f "$LOCAL_BINARY" ]; then
        print_error "Local binary not found at $LOCAL_BINARY"
        print_info "Please run 'go build ./cmd/netnat' first"
        exit 1
    fi

    # Check if binary is executable
    if [ ! -x "$LOCAL_BINARY" ]; then
        print_error "Binary is not executable"
        chmod +x "$LOCAL_BINARY"
        print_info "Made binary executable"
    fi

    print_success "Local binary found: $LOCAL_BINARY"
}

# Check required tools
check_dependencies() {
    print_step "Checking dependencies..."

    if ! command -v sshpass &> /dev/null; then
        print_error "sshpass is not installed"
        print_info "Installing sshpass..."
        if command -v apt-get &> /dev/null; then
            sudo apt-get update && sudo apt-get install -y sshpass
        elif command -v yum &> /dev/null; then
            sudo yum install -y sshpass
        elif command -v dnf &> /dev/null; then
            sudo dnf install -y sshpass
        else
            print_error "Cannot install sshpass automatically. Please install it manually."
            exit 1
        fi
    fi

    if ! command -v ssh &> /dev/null; then
        print_error "SSH client is not installed"
        exit 1
    fi

    if ! command -v scp &> /dev/null; then
        print_error "SCP is not installed"
        exit 1
    fi

    print_success "All dependencies are available"
}

# Test connection to Proxmox server
test_connection() {
    print_step "Testing connection to Proxmox server..."

    if sshpass -p "$PROXMOX_PASSWORD" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 "$PROXMOX_USER@$PROXMOX_HOST" "echo 'Connection successful'" &> /dev/null; then
        print_success "Connection to Proxmox server successful"
    else
        print_error "Cannot connect to Proxmox server at $PROXMOX_HOST"
        print_info "Please check:"
        print_info "  - Server IP address: $PROXMOX_HOST"
        print_info "  - SSH service is running"
        print_info "  - Network connectivity"
        print_info "  - Credentials are correct"
        exit 1
    fi
}

# Check if remote service is running
check_remote_service() {
    print_step "Checking NetNAT service status..."

    service_status=$(sshpass -p "$PROXMOX_PASSWORD" ssh -o StrictHostKeyChecking=no "$PROXMOX_USER@$PROXMOX_HOST" \
        "systemctl is-active netnat 2>/dev/null || echo 'unknown'")

    if [ "$service_status" = "active" ]; then
        print_success "NetNAT service is currently running"
        return 0
    elif [ "$service_status" = "inactive" ]; then
        print_info "NetNAT service is currently stopped"
        return 1
    else
        print_info "NetNAT service not found or unknown status"
        return 2
    fi
}

# Stop NetNAT service
stop_service() {
    print_step "Stopping NetNAT service..."

    sshpass -p "$PROXMOX_PASSWORD" ssh -o StrictHostKeyChecking=no "$PROXMOX_USER@$PROXMOX_HOST" \
        "sudo systemctl stop netnat 2>/dev/null || sudo pkill -f netnat 2>/dev/null || true"

    print_success "NetNAT service stopped"
}

# Create backup of current binary
create_backup() {
    print_step "Creating backup of current binary..."

    sshpass -p "$PROXMOX_PASSWORD" ssh -o StrictHostKeyChecking=no "$PROXMOX_USER@$PROXMOX_HOST" \
        "sudo test -f $REMOTE_PATH && sudo cp $REMOTE_PATH $BACKUP_PATH || echo 'No existing binary to backup'"

    print_success "Backup created at $BACKUP_PATH"
}

# Upload new binary
upload_binary() {
    print_step "Uploading new binary..."

    # Upload to temporary location first
    temp_path="/tmp/netnat.new.$(date +%s)"
    sshpass -p "$PROXMOX_PASSWORD" scp -o StrictHostKeyChecking=no "$LOCAL_BINARY" "$PROXMOX_USER@$PROXMOX_HOST:$temp_path"

    # Move to final location with proper permissions
    sshpass -p "$PROXMOX_PASSWORD" ssh -o StrictHostKeyChecking=no "$PROXMOX_USER@$PROXMOX_HOST" \
        "sudo mv $temp_path $REMOTE_PATH && sudo chmod +x $REMOTE_PATH && sudo chown root:root $REMOTE_PATH"

    print_success "New binary uploaded successfully"
}

# Verify binary integrity
verify_binary() {
    print_step "Verifying binary integrity..."

    # Check if binary exists and is executable
    remote_check=$(sshpass -p "$PROXMOX_PASSWORD" ssh -o StrictHostKeyChecking=no "$PROXMOX_USER@$PROXMOX_HOST" \
        "test -x $REMOTE_PATH && echo 'OK' || echo 'FAIL'")

    if [ "$remote_check" = "OK" ]; then
        print_success "Binary verification passed"
    else
        print_error "Binary verification failed"
        print_info "Attempting to restore backup..."
        restore_backup
        exit 1
    fi
}

# Start NetNAT service
start_service() {
    print_step "Starting NetNAT service..."

    sshpass -p "$PROXMOX_PASSWORD" ssh -o StrictHostKeyChecking=no "$PROXMOX_USER@$PROXMOX_HOST" \
        "sudo systemctl start netnat 2>/dev/null || sudo nohup $REMOTE_PATH > /var/log/netnat.log 2>&1 &"

    sleep 2  # Give service time to start

    # Check if service started successfully
    service_status=$(sshpass -p "$PROXMOX_PASSWORD" ssh -o StrictHostKeyChecking=no "$PROXMOX_USER@$PROXMOX_HOST" \
        "systemctl is-active netnat 2>/dev/null || echo 'unknown'")

    if [ "$service_status" = "active" ]; then
        print_success "NetNAT service started successfully"
    else
        print_info "NetNAT service started (manual mode)"
    fi
}

# Restore backup if something goes wrong
restore_backup() {
    print_step "Restoring backup..."

    sshpass -p "$PROXMOX_PASSWORD" ssh -o StrictHostKeyChecking=no "$PROXMOX_USER@$PROXMOX_HOST" \
        "sudo test -f $BACKUP_PATH && sudo cp $BACKUP_PATH $REMOTE_PATH || echo 'No backup found'"

    print_success "Backup restored"
}

# Show final status
show_status() {
    print_step "Checking final service status..."

    # Get service status
    service_status=$(sshpass -p "$PROXMOX_PASSWORD" ssh -o StrictHostKeyChecking=no "$PROXMOX_USER@$PROXMOX_HOST" \
        "systemctl is-active netnat 2>/dev/null || echo 'unknown'")

    # Get binary info
    binary_info=$(sshpass -p "$PROXMOX_PASSWORD" ssh -o StrictHostKeyChecking=no "$PROXMOX_USER@$PROXMOX_HOST" \
        "ls -la $REMOTE_PATH 2>/dev/null || echo 'Binary not found'")

    echo
    print_success "=== Update Summary ==="
    print_info "Service Status: $service_status"
    print_info "Binary Info: $binary_info"
    print_info "Backup Location: $BACKUP_PATH"

    # Test if web interface is accessible
    print_step "Testing web interface accessibility..."
    if curl -s --connect-timeout 5 "http://$PROXMOX_HOST:8080" > /dev/null; then
        print_success "Web interface is accessible at http://$PROXMOX_HOST:8080"
    else
        print_info "Web interface test failed (may need more time to start)"
    fi
}

# Cleanup function on script exit
cleanup() {
    if [ $? -ne 0 ]; then
        print_error "Script failed! Checking service status..."
        # Try to start service if it was stopped
        sshpass -p "$PROXMOX_PASSWORD" ssh -o StrictHostKeyChecking=no "$PROXMOX_USER@$PROXMOX_HOST" \
            "sudo systemctl start netnat 2>/dev/null || true"
    fi
}

# Main execution
main() {
    print_header

    # Set up cleanup trap
    trap cleanup EXIT

    # Execute steps
    check_local_binary
    check_dependencies
    test_connection

    # Check current service status
    service_was_running=false
    if check_remote_service; then
        service_was_running=true
    fi

    # Stop service if it was running
    if [ "$service_was_running" = true ]; then
        stop_service
    fi

    # Perform update
    create_backup
    upload_binary
    verify_binary

    # Restart service if it was running
    if [ "$service_was_running" = true ]; then
        start_service
    fi

    # Show final status
    show_status

    echo
    print_success "NetNAT binary update completed successfully!"
    print_info "If you encounter any issues, you can restore from backup:"
    print_info "  ssh root@$PROXMOX_HOST"
    print_info "  sudo cp $BACKUP_PATH $REMOTE_PATH"
    print_info "  sudo systemctl restart netnat"
}

# Run main function
main "$@"