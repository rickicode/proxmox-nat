package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"proxmox-nat/internal/models"
)

// VMDiscovery handles VM and container discovery
type VMDiscovery struct {
	bridgeInterface string
	cache          *VMCache
	cacheTimeout   time.Duration
}

// VMCache stores cached VM data with timestamps
type VMCache struct {
	vms      []models.VM
	timestamp time.Time
	mutex    sync.RWMutex
}

// New creates a new VM discovery instance
func New(bridgeInterface string) *VMDiscovery {
	return &VMDiscovery{
		bridgeInterface: bridgeInterface,
		cache:          &VMCache{},
		cacheTimeout:   60 * time.Second, // Cache for 60 seconds
	}
}

// DiscoverVMs discovers VMs and containers using parallel approach with caching
func (d *VMDiscovery) DiscoverVMs() ([]models.VM, error) {
	// Check cache first
	d.cache.mutex.RLock()
	if time.Since(d.cache.timestamp) < d.cacheTimeout {
		cachedVMs := make([]models.VM, len(d.cache.vms))
		copy(cachedVMs, d.cache.vms)
		d.cache.mutex.RUnlock()
		return cachedVMs, nil
	}
	d.cache.mutex.RUnlock()

	var allVMs []models.VM
	var wg sync.WaitGroup
	var qemuVMs, lxcVMs, arpVMs []models.VM
	var qemuErr, lxcErr, arpErr error

	// Run discovery methods in parallel
	wg.Add(3)

	// QEMU VMs discovery
	go func() {
		defer wg.Done()
		qemuVMs, qemuErr = d.discoverQEMUVMs()
	}()

	// LXC containers discovery
	go func() {
		defer wg.Done()
		lxcVMs, lxcErr = d.discoverLXCContainers()
	}()

	// ARP table discovery
	go func() {
		defer wg.Done()
		arpVMs, arpErr = d.discoverFromARP()
	}()

	wg.Wait()

	// Collect results
	if qemuErr == nil {
		allVMs = append(allVMs, qemuVMs...)
	}
	if lxcErr == nil {
		allVMs = append(allVMs, lxcVMs...)
	}
	if arpErr == nil {
		allVMs = d.mergeVMData(allVMs, arpVMs)
	}

	// Update cache
	d.cache.mutex.Lock()
	d.cache.vms = make([]models.VM, len(allVMs))
	copy(d.cache.vms, allVMs)
	d.cache.timestamp = time.Now()
	d.cache.mutex.Unlock()

	return allVMs, nil
}

// discoverQEMUVMs discovers QEMU VMs using qm command and parallel guest agent calls
func (d *VMDiscovery) discoverQEMUVMs() ([]models.VM, error) {
	// Get list of VMs
	cmd := exec.Command("qm", "list")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to execute qm list: %w", err)
	}

	lines := strings.Split(string(output), "\n")
	var vmInfos []struct {
		vmid   string
		name   string
		status string
	}

	// Parse VM list first
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

		vmInfos = append(vmInfos, struct {
			vmid   string
			name   string
			status string
		}{
			vmid:   fields[0],
			name:   fields[1],
			status: fields[2],
		})
	}

	if len(vmInfos) == 0 {
		return []models.VM{}, nil
	}

	// Create VMs and get IPs in parallel
	vms := make([]models.VM, len(vmInfos))
	var wg sync.WaitGroup

	for i, vmInfo := range vmInfos {
		vms[i] = models.VM{
			ID:     vmInfo.vmid,
			Name:   vmInfo.name,
			Type:   "qemu",
			Status: vmInfo.status,
			Source: "qm",
		}

		// Get IP from guest agent in parallel for running VMs
		if vmInfo.status == "running" {
			wg.Add(1)
			go func(index int, vmid string) {
				defer wg.Done()
				if ip, err := d.getQEMUVMIP(vmid); err == nil && ip != "" {
					vms[index].IP = ip
					vms[index].Source = "agent"
				}
			}(i, vmInfo.vmid)
		}
	}

	wg.Wait()
	return vms, nil
}

// getQEMUVMIP gets VM IP using QEMU guest agent with timeout
func (d *VMDiscovery) getQEMUVMIP(vmid string) (string, error) {
	// First check if guest agent is enabled and running
	checkCmd := exec.Command("qm", "guest", "exec", vmid, "test", "echo", "test")
	if output, err := checkCmd.CombinedOutput(); err != nil {
		// Guest agent might not be running or not enabled
		fmt.Printf("VM %s: Guest agent not available: %v (output: %s)\n", vmid, err, string(output))

		// Try alternative check methods
		if d.checkGuestAgentAlternative(vmid) {
			fmt.Printf("VM %s: Guest agent available via alternative check\n", vmid)
		} else {
			return "", fmt.Errorf("guest agent not available")
		}
	}

	// Try to get IP address using fence agent first (more reliable)
	cmd := exec.Command("qm", "fence", "ack", vmid)
	if output, err := cmd.Output(); err == nil {
		if ip := d.extractIPFromOutput(string(output)); ip != "" {
			return ip, nil
		}
	}

	// Try multiple methods to get IP address

	// Method 1: network-get-interfaces (most reliable)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd = exec.CommandContext(ctx, "qm", "guest", "cmd", vmid, "network-get-interfaces")
	output, err := cmd.Output()
	if err == nil {
		if ip := d.parseGuestAgentInterfaces(output); ip != "" {
			return ip, nil
		}
	}

	// Method 2: Get IP from arp-scan of VM
	if ip := d.getVMIPFromARP(vmid); ip != "" {
		return ip, nil
	}

	// Method 3: Try to ping common VM names
	if ip := d.getVMIPFromProxmoxConfig(vmid); ip != "" {
		return ip, nil
	}

	return "", fmt.Errorf("no IP found for VM %s", vmid)
}

// parseGuestAgentInterfaces parses network-get-interfaces JSON output
func (d *VMDiscovery) parseGuestAgentInterfaces(output []byte) string {
	// Parse JSON output from guest agent
	var interfaces map[string]interface{}
	if err := json.Unmarshal(output, &interfaces); err != nil {
		return ""
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
										// Check if IP is in private range and not localhost
										if d.isPrivateIP(ip) && ip != "127.0.0.1" {
											fmt.Printf("Found IP %s for interface %s via guest agent\n", ip, name)
											return ip
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

	return ""
}

// getVMIPFromARP tries to find VM IP by looking at recent ARP entries
func (d *VMDiscovery) getVMIPFromARP(vmid string) string {
	// Get VM config to find MAC address
	cmd := exec.Command("qm", "config", vmid)
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	// Extract MAC address from VM config
	lines := strings.Split(string(output), "\n")
	var macAddr string
	for _, line := range lines {
		if strings.HasPrefix(line, "net0:") && strings.Contains(line, "hwaddr=") {
			re := regexp.MustCompile(`hwaddr=([a-fA-F0-9:]+)`)
			matches := re.FindStringSubmatch(line)
			if len(matches) > 1 {
				macAddr = matches[1]
				break
			}
		}
	}

	if macAddr == "" {
		return ""
	}

	// Look for this MAC in ARP table
	arpCmd := exec.Command("arp", "-a")
	arpOutput, err := arpCmd.Output()
	if err != nil {
		return ""
	}

	lines = strings.Split(string(arpOutput), "\n")
	for _, line := range lines {
		if strings.Contains(line, strings.ToLower(macAddr)) || strings.Contains(line, strings.ToUpper(macAddr)) {
			// Parse IP from ARP entry
			re := regexp.MustCompile(`\(([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\)`)
			matches := re.FindStringSubmatch(line)
			if len(matches) > 1 {
				ip := matches[1]
				if d.isPrivateIP(ip) {
					fmt.Printf("Found IP %s for VM %s via ARP (MAC: %s)\n", ip, vmid, macAddr)
					return ip
				}
			}
		}
	}

	return ""
}

// getVMIPFromProxmoxConfig tries to get IP from Proxmox VM config
func (d *VMDiscovery) getVMIPFromProxmoxConfig(vmid string) string {
	// Check if VM has IP set in config
	cmd := exec.Command("qm", "config", vmid)
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "ipconfig") && strings.Contains(line, "ip=") {
			// Extract IP from config like: ipconfig0: ip=192.168.1.100/24
			re := regexp.MustCompile(`ip=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)`)
			matches := re.FindStringSubmatch(line)
			if len(matches) > 1 {
				ip := matches[1]
				if d.isPrivateIP(ip) {
					fmt.Printf("Found IP %s for VM %s from Proxmox config\n", ip, vmid)
					return ip
				}
			}
		}
	}

	return ""
}

// checkGuestAgentAlternative tries alternative methods to check if guest agent is available
func (d *VMDiscovery) checkGuestAgentAlternative(vmid string) bool {
	// Method 1: Try qm guest ping
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "qm", "guest", "ping", vmid)
	if _, err := cmd.Output(); err == nil {
		return true
	}

	// Method 2: Try qm guest cmd with simpler command
	cmd = exec.Command("qm", "guest", "cmd", vmid, "ping")
	if _, err := cmd.Output(); err == nil {
		return true
	}

	// Method 3: Check VM config for guest agent enabled
	configCmd := exec.Command("qm", "config", vmid)
	output, err := configCmd.Output()
	if err != nil {
		return false
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "agent:") && strings.Contains(line, "1") {
			return true // Guest agent is enabled in config
		}
	}

	return false
}

// discoverLXCContainers discovers LXC containers using parallel IP discovery
func (d *VMDiscovery) discoverLXCContainers() ([]models.VM, error) {
	// Get list of containers
	cmd := exec.Command("pct", "list")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to execute pct list: %w", err)
	}

	lines := strings.Split(string(output), "\n")
	var containerInfos []struct {
		ctid   string
		status string
		name   string
	}

	// Parse container list first
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
		name := ""
		if len(fields) > 3 {
			name = fields[3] // Name is at index 3 after VMID, Status, Lock
		} else if len(fields) == 3 {
			name = fields[2] // Name is at index 2 if no lock field
		}

		containerInfos = append(containerInfos, struct {
			ctid   string
			status string
			name   string
		}{
			ctid:   ctid,
			status: status,
			name:   name,
		})
	}

	if len(containerInfos) == 0 {
		return []models.VM{}, nil
	}

	// Create containers and get IPs in parallel
	containers := make([]models.VM, len(containerInfos))
	var wg sync.WaitGroup

	for i, ctInfo := range containerInfos {
		containers[i] = models.VM{
			ID:     ctInfo.ctid,
			Name:   ctInfo.name,
			Type:   "lxc",
			Status: ctInfo.status,
			Source: "pct",
		}

		// Get IP from container config in parallel for running containers
		if ctInfo.status == "running" {
			wg.Add(1)
			go func(index int, ctid string) {
				defer wg.Done()
				if ip, err := d.getLXCContainerIP(ctid); err == nil && ip != "" {
					containers[index].IP = ip
					containers[index].Source = "lxc"
				}
			}(i, ctInfo.ctid)
		}
	}

	wg.Wait()
	return containers, nil
}

// getLXCContainerIP gets container IP from configuration or runtime with timeout
func (d *VMDiscovery) getLXCContainerIP(ctid string) (string, error) {
	// Try to get IP from runtime first with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "pct", "exec", ctid, "--", "ip", "addr", "show")
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

// RefreshVMData forces a refresh of VM discovery data by clearing cache
func (d *VMDiscovery) RefreshVMData() ([]models.VM, error) {
	// Clear cache to force fresh discovery
	d.cache.mutex.Lock()
	d.cache.vms = nil
	d.cache.timestamp = time.Time{} // Zero time
	d.cache.mutex.Unlock()

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
