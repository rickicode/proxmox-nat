package discovery

import (
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strings"

	"proxmox-nat/internal/models"
)

// VMDiscovery handles VM and container discovery
type VMDiscovery struct {
	bridgeInterface string
}

// New creates a new VM discovery instance
func New(bridgeInterface string) *VMDiscovery {
	return &VMDiscovery{
		bridgeInterface: bridgeInterface,
	}
}

// DiscoverVMs discovers VMs and containers using hybrid approach
func (d *VMDiscovery) DiscoverVMs() ([]models.VM, error) {
	var allVMs []models.VM

	// 1. Try QEMU Guest Agent first (most accurate)
	if qemuVMs, err := d.discoverQEMUVMs(); err == nil {
		allVMs = append(allVMs, qemuVMs...)
	}

	// 2. Try LXC containers
	if lxcVMs, err := d.discoverLXCContainers(); err == nil {
		allVMs = append(allVMs, lxcVMs...)
	}

	// 3. Supplement with ARP table discovery
	arpVMs, err := d.discoverFromARP()
	if err == nil {
		allVMs = d.mergeVMData(allVMs, arpVMs)
	}

	// 4. Add manual entries if configured
	// This would be extended to read from config manual mappings

	return allVMs, nil
}

// discoverQEMUVMs discovers QEMU VMs using qm command and guest agent
func (d *VMDiscovery) discoverQEMUVMs() ([]models.VM, error) {
	var vms []models.VM

	// Get list of VMs
	cmd := exec.Command("qm", "list")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to execute qm list: %w", err)
	}

	lines := strings.Split(string(output), "\n")
	for i, line := range lines {
		if i == 0 { // Skip header
			continue
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		vmid := fields[0]
		name := fields[1]
		status := fields[2]

		vm := models.VM{
			ID:     vmid,
			Name:   name,
			Type:   "qemu",
			Status: status,
			Source: "qm",
		}

		// Try to get IP from guest agent
		if ip, err := d.getQEMUVMIP(vmid); err == nil && ip != "" {
			vm.IP = ip
			vm.Source = "agent"
		}

		vms = append(vms, vm)
	}

	return vms, nil
}

// getQEMUVMIP gets VM IP using QEMU guest agent
func (d *VMDiscovery) getQEMUVMIP(vmid string) (string, error) {
	cmd := exec.Command("qm", "guest", "cmd", vmid, "network-get-interfaces")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	// Parse JSON output from guest agent
	var interfaces map[string]interface{}
	if err := json.Unmarshal(output, &interfaces); err != nil {
		return "", err
	}

	// Look for non-loopback interfaces with IP addresses
	if result, ok := interfaces["result"].([]interface{}); ok {
		for _, iface := range result {
			if ifaceMap, ok := iface.(map[string]interface{}); ok {
				if name, ok := ifaceMap["name"].(string); ok && name != "lo" {
					if ipAddrs, ok := ifaceMap["ip-addresses"].([]interface{}); ok {
						for _, addr := range ipAddrs {
							if addrMap, ok := addr.(map[string]interface{}); ok {
								if ipType, ok := addrMap["ip-address-type"].(string); ok && ipType == "ipv4" {
									if ip, ok := addrMap["ip-address"].(string); ok {
										// Check if IP is in private range
										if d.isPrivateIP(ip) {
											return ip, nil
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	return "", fmt.Errorf("no private IP found")
}

// discoverLXCContainers discovers LXC containers
func (d *VMDiscovery) discoverLXCContainers() ([]models.VM, error) {
	var containers []models.VM

	// Get list of containers
	cmd := exec.Command("pct", "list")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to execute pct list: %w", err)
	}

	lines := strings.Split(string(output), "\n")
	for i, line := range lines {
		if i == 0 { // Skip header
			continue
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		ctid := fields[0]
		status := fields[1]
		// Skip Lock field (index 2) if present
		name := ""
		if len(fields) > 3 {
			name = fields[3] // Name is at index 3 after VMID, Status, Lock
		} else if len(fields) == 3 {
			name = fields[2] // Name is at index 2 if no lock field
		}

		container := models.VM{
			ID:     ctid,
			Name:   name,
			Type:   "lxc",
			Status: status,
			Source: "pct",
		}

		// Try to get IP from container config
		if ip, err := d.getLXCContainerIP(ctid); err == nil && ip != "" {
			container.IP = ip
			container.Source = "lxc"
		}

		containers = append(containers, container)
	}

	return containers, nil
}

// getLXCContainerIP gets container IP from configuration or runtime
func (d *VMDiscovery) getLXCContainerIP(ctid string) (string, error) {
	// Try to get IP from runtime first
	cmd := exec.Command("pct", "exec", ctid, "--", "ip", "addr", "show")
	if output, err := cmd.Output(); err == nil {
		if ip := d.extractIPFromOutput(string(output)); ip != "" {
			return ip, nil
		}
	}

	// Fallback to config file
	cmd = exec.Command("pct", "config", ctid)
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	// Parse network configuration
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "net") && strings.Contains(line, "ip=") {
			// Extract IP from network config like: net0: bridge=vmbr1,ip=192.168.1.100/24
			re := regexp.MustCompile(`ip=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)`)
			matches := re.FindStringSubmatch(line)
			if len(matches) > 1 {
				return matches[1], nil
			}
		}
	}

	return "", fmt.Errorf("no IP found in container config")
}

// discoverFromARP discovers VMs/containers from ARP table
func (d *VMDiscovery) discoverFromARP() ([]models.VM, error) {
	var vms []models.VM

	// Get ARP table
	cmd := exec.Command("arp", "-a")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get ARP table: %w", err)
	}

	// Parse ARP output
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}

		// Parse line like: hostname (192.168.1.100) at aa:bb:cc:dd:ee:ff [ether] on vmbr1
		re := regexp.MustCompile(`^(\S+)?\s*\(([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\)\s+at\s+([a-fA-F0-9:]+).*on\s+(\S+)`)
		matches := re.FindStringSubmatch(line)

		if len(matches) >= 5 {
			hostname := matches[1]
			ip := matches[2]
			_ = matches[3] // MAC address (unused for now)
			iface := matches[4]

			// Only include entries from our bridge interface
			if iface == d.bridgeInterface && d.isPrivateIP(ip) {
				vm := models.VM{
					ID:     ip, // Use IP as ID for ARP entries
					Name:   hostname,
					Type:   "unknown",
					Status: "unknown",
					IP:     ip,
					Source: "arp",
				}

				// Try to match with existing VMs by MAC or hostname
				if hostname != "" && hostname != "?" {
					vm.Name = hostname
				} else {
					vm.Name = fmt.Sprintf("Host-%s", ip)
				}

				vms = append(vms, vm)
			}
		}
	}

	return vms, nil
}

// mergeVMData merges VM data from different sources, avoiding duplicates
func (d *VMDiscovery) mergeVMData(existing, additional []models.VM) []models.VM {
	// Create map of existing VMs by IP and ID
	vmByIP := make(map[string]models.VM)
	vmByID := make(map[string]models.VM)

	// First, index all existing VMs
	for _, vm := range existing {
		vmByID[vm.ID] = vm
		if vm.IP != "" {
			vmByIP[vm.IP] = vm
		}
	}

	// Merge additional VMs (mainly from ARP), but avoid duplicates
	for _, vm := range additional {
		if vm.IP == "" {
			continue // Skip VMs without IP from additional sources
		}

		// Check if this IP already belongs to a VM/CT we know about
		if existingVM, exists := vmByIP[vm.IP]; exists {
			// IP already belongs to an existing VM/CT
			// Update the existing VM with better name if needed
			if existingVM.Name == "" && vm.Name != "" && vm.Name != fmt.Sprintf("Host-%s", vm.IP) {
				existingVM.Name = vm.Name
				vmByIP[vm.IP] = existingVM
				vmByID[existingVM.ID] = existingVM
			}
			// Don't add as separate entry
			continue
		}

		// Check if this is actually a VM/CT we know but without IP detected
		matched := false
		for id, existingVM := range vmByID {
			if existingVM.IP == "" && (existingVM.Name == vm.Name ||
				(vm.Name != "" && vm.Name != "?" && vm.Name != fmt.Sprintf("Host-%s", vm.IP) &&
					strings.Contains(strings.ToLower(existingVM.Name), strings.ToLower(vm.Name)))) {
				// This seems to be the same VM, update with IP
				existingVM.IP = vm.IP
				if existingVM.Source == "qm" || existingVM.Source == "pct" {
					existingVM.Source = "qm+arp" // Indicate mixed source
				}
				vmByID[id] = existingVM
				vmByIP[vm.IP] = existingVM
				matched = true
				break
			}
		}

		// Only add as new entry if it's truly unknown and has a reasonable name
		if !matched && vm.Source == "arp" && vm.Name != "" && vm.Name != "?" &&
			!strings.HasPrefix(vm.Name, "Host-") {
			vmByIP[vm.IP] = vm
		}
	}

	// Convert back to slice, preferring VMs with known IDs
	var result []models.VM
	addedIPs := make(map[string]bool)

	// Add all VMs from vmByID first (these are real VMs/CTs)
	for _, vm := range vmByID {
		result = append(result, vm)
		if vm.IP != "" {
			addedIPs[vm.IP] = true
		}
	}

	// Add any remaining ARP-only entries that weren't matched
	for ip, vm := range vmByIP {
		if !addedIPs[ip] && vm.Source == "arp" {
			result = append(result, vm)
		}
	}

	return result
}

// extractIPFromOutput extracts private IP addresses from command output
func (d *VMDiscovery) extractIPFromOutput(output string) string {
	re := regexp.MustCompile(`inet ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)`)
	matches := re.FindAllStringSubmatch(output, -1)

	for _, match := range matches {
		if len(match) > 1 {
			ip := match[1]
			if d.isPrivateIP(ip) && ip != "127.0.0.1" {
				return ip
			}
		}
	}

	return ""
}

// isPrivateIP checks if an IP address is in private range
func (d *VMDiscovery) isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// Private ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	}

	for _, cidr := range privateRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

// GetVMByID gets a specific VM by ID
func (d *VMDiscovery) GetVMByID(id string) (*models.VM, error) {
	vms, err := d.DiscoverVMs()
	if err != nil {
		return nil, err
	}

	for _, vm := range vms {
		if vm.ID == id {
			return &vm, nil
		}
	}

	return nil, fmt.Errorf("VM with ID %s not found", id)
}

// GetVMByIP gets a specific VM by IP address
func (d *VMDiscovery) GetVMByIP(ip string) (*models.VM, error) {
	vms, err := d.DiscoverVMs()
	if err != nil {
		return nil, err
	}

	for _, vm := range vms {
		if vm.IP == ip {
			return &vm, nil
		}
	}

	return nil, fmt.Errorf("VM with IP %s not found", ip)
}

// RefreshVMData forces a refresh of VM discovery data
func (d *VMDiscovery) RefreshVMData() ([]models.VM, error) {
	// This method can implement caching logic in the future
	return d.DiscoverVMs()
}

// ValidateVMIP checks if a VM IP is reachable
func (d *VMDiscovery) ValidateVMIP(ip string) bool {
	// Simple ping test
	cmd := exec.Command("ping", "-c", "1", "-W", "1", ip)
	return cmd.Run() == nil
}

// GetVMsByType returns VMs filtered by type
func (d *VMDiscovery) GetVMsByType(vmType string) ([]models.VM, error) {
	vms, err := d.DiscoverVMs()
	if err != nil {
		return nil, err
	}

	var filtered []models.VM
	for _, vm := range vms {
		if vm.Type == vmType {
			filtered = append(filtered, vm)
		}
	}

	return filtered, nil
}

// GetActiveVMs returns only running VMs
func (d *VMDiscovery) GetActiveVMs() ([]models.VM, error) {
	vms, err := d.DiscoverVMs()
	if err != nil {
		return nil, err
	}

	var active []models.VM
	for _, vm := range vms {
		if vm.Status == "running" || vm.Status == "unknown" {
			active = append(active, vm)
		}
	}

	return active, nil
}
