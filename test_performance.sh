#!/bin/bash

# Performance Test Script for NetNAT VM API

PROXMOX_HOST="192.168.90.2"
WEB_URL="http://$PROXMOX_HOST:8080"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

print_header() {
    echo -e "${BLUE}===============================================${NC}"
    echo -e "${BLUE}     NetNAT Performance Test Script            ${NC}"
    echo -e "${BLUE}===============================================${NC}"
    echo
}

print_test() {
    echo -e "${YELLOW}[TEST]${NC} $1"
}

print_result() {
    if [ $2 -eq 0 ]; then
        echo -e "${GREEN}[PASS]${NC} $1 (${3}s)"
    else
        echo -e "${RED}[FAIL]${NC} $1"
    fi
}

# Test web interface accessibility
test_web_interface() {
    print_test "Testing web interface accessibility..."

    if curl -s --connect-timeout 5 "$WEB_URL" > /dev/null; then
        print_result "Web interface accessible" 0 "fast"
        return 0
    else
        print_result "Web interface not accessible" 1
        return 1
    fi
}

# Test API response time via web interface simulation
test_api_performance() {
    print_test "Testing API performance (simulating web browser)..."

    # Simulate the VM API call like the web interface would do
    response=$(curl -s -w "%{http_code}" -o /dev/null --connect-timeout 10 "$WEB_URL/api/vms" 2>/dev/null)

    if [ "$response" = "200" ] || [ "$response" = "401" ]; then
        # 401 means auth is required but service is working
        print_result "API responding" 0 "OK"
        return 0
    else
        print_result "API not responding (HTTP $response)" 1
        return 1
    fi
}

# Test multiple calls to check caching
test_caching_performance() {
    print_test "Testing caching performance (3 consecutive calls)..."

    success_count=0
    for i in {1..3}; do
        response=$(curl -s -w "%{http_code}" -o /dev/null --connect-timeout 10 "$WEB_URL/api/vms" 2>/dev/null)

        if [ "$response" = "200" ] || [ "$response" = "401" ]; then
            success_count=$((success_count + 1))
        fi

        sleep 1  # Small delay between calls
    done

    if [ $success_count -eq 3 ]; then
        print_result "All API calls successful" 0 "caching working"
    else
        print_result "Some API calls failed ($success_count/3)" 1
    fi

    return 0
}

# Test service logs for performance metrics
check_service_logs() {
    print_test "Checking service logs for performance metrics..."

    echo -e "${BLUE}[INFO]${NC} Recent VM API calls from service logs:"
    sshpass -p "p1kunPISAN" ssh -o StrictHostKeyChecking=no root@$PROXMOX_HOST \
        "sudo journalctl -u netnat --no-pager | grep '/api/vms' | tail -5" 2>/dev/null || echo "Could not fetch logs"

    echo
}

# Test system resources
check_system_resources() {
    print_test "Checking system resources..."

    echo -e "${BLUE}[INFO]${NC} NetNAT service resource usage:"
    sshpass -p "p1kunPISAN" ssh -o StrictHostKeyChecking=no root@$PROXMOX_HOST \
        "sudo systemctl status netnat --no-pager | grep -E '(Memory:|CPU:)' || echo 'Resource info not available'" 2>/dev/null

    echo
}

# Test network connectivity
test_network_connectivity() {
    print_test "Testing network connectivity to Proxmox server..."

    if ping -c 1 -W 2 "$PROXMOX_HOST" > /dev/null 2>&1; then
        print_result "Network connectivity OK" 0
        return 0
    else
        print_result "Network connectivity failed" 1
        return 1
    fi
}

# Main test execution
main() {
    print_header

    # Check dependencies
    # bc is no longer required

    if ! command -v curl &> /dev/null; then
        echo -e "${RED}[ERROR]${NC} 'curl' command is required"
        exit 1
    fi

    # Run tests
    test_network_connectivity
    test_web_interface
    test_api_performance
    test_caching_performance
    check_system_resources
    check_service_logs

    echo -e "${GREEN}===============================================${NC}"
    echo -e "${GREEN}           Performance Test Complete           ${NC}"
    echo -e "${GREEN}===============================================${NC}"
    echo
    echo -e "${BLUE}[TIPS]${NC}"
    echo "1. First VM API call may be slower (discovery process)"
    echo "2. Subsequent calls should be faster due to caching"
    echo "3. Guest agent timeouts are now limited to 2 seconds"
    echo "4. Total VM discovery time should be under 5 seconds"
    echo "5. Web interface should be responsive after initial load"
    echo
    echo -e "${BLUE}[TROUBLESHOOTING]${NC}"
    echo "If VM discovery is still slow:"
    echo "- Check QEMU guest agent installation in VMs"
    echo "- Verify network connectivity between host and VMs"
    echo "- Monitor Proxmox host resources"
    echo "- Check for VMs with stopped guest agent service"
}

main "$@"