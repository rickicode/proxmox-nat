package network

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"proxmox-nat/internal/models"
)

// Manager handles network operations (NAT, forwarding, DNAT rules)
type Manager struct {
	config            *models.Config
	interfaceDetector *InterfaceDetector
	publicInterface   string
	mutex             sync.RWMutex
}

// New creates a new network manager
func New(config *models.Config) (*Manager, error) {
	detector := NewInterfaceDetector()

	// Detect public interface
	publicInterface, err := detector.GetPublicInterface(config.Network.PublicInterface)
	if err != nil {
		return nil, fmt.Errorf("failed to detect public interface: %w", err)
	}

	fmt.Printf("Detected public interface: %s\n", publicInterface)

	manager := &Manager{
		config:            config,
		interfaceDetector: detector,
		publicInterface:   publicInterface,
	}

	// Configure vnstat for traffic monitoring
	if err := manager.configureVnstat(publicInterface); err != nil {
		fmt.Printf("Warning: Failed to configure vnstat: %v\n", err)
	}

	return manager, nil
}

// EnableIPForwarding enables IPv4 forwarding
func (m *Manager) EnableIPForwarding() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Check current status
	current, err := m.getIPForwardingStatus()
	if err != nil {
		return fmt.Errorf("failed to check IP forwarding status: %w", err)
	}

	if current {
		fmt.Println("IPv4 forwarding already enabled")
		return nil
	}

	// Enable via sysctl
	cmd := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to enable IP forwarding: %w", err)
	}

	// Make persistent by updating sysctl.conf
	if err := m.makePersistentIPForwarding(); err != nil {
		fmt.Printf("Warning: Failed to make IP forwarding persistent: %v\n", err)
	}

	fmt.Println("IPv4 forwarding enabled")
	return nil
}

// DisableIPForwarding disables IPv4 forwarding
func (m *Manager) DisableIPForwarding() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	cmd := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=0")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to disable IP forwarding: %w", err)
	}

	fmt.Println("IPv4 forwarding disabled")
	return nil
}

// getIPForwardingStatus checks if IPv4 forwarding is enabled
func (m *Manager) getIPForwardingStatus() (bool, error) {
	data, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		return false, err
	}

	return strings.TrimSpace(string(data)) == "1", nil
}

// makePersistentIPForwarding ensures IP forwarding survives reboot
func (m *Manager) makePersistentIPForwarding() error {
	sysctlConf := "/etc/sysctl.conf"

	// Read current sysctl.conf
	data, err := os.ReadFile(sysctlConf)
	if err != nil {
		// File might not exist, create it
		data = []byte{}
	}

	content := string(data)

	// Check if already configured
	if strings.Contains(content, "net.ipv4.ip_forward=1") {
		return nil
	}

	// Remove any existing ip_forward lines
	lines := strings.Split(content, "\n")
	var newLines []string
	for _, line := range lines {
		if !strings.Contains(line, "net.ipv4.ip_forward") {
			newLines = append(newLines, line)
		}
	}

	// Add our configuration
	newLines = append(newLines, "# NetNAT: Enable IPv4 forwarding")
	newLines = append(newLines, "net.ipv4.ip_forward=1")

	// Write back to file
	newContent := strings.Join(newLines, "\n")
	return os.WriteFile(sysctlConf, []byte(newContent), 0644)
}

// EnableNAT enables NAT masquerade
func (m *Manager) EnableNAT() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Check if NAT is already enabled
	if enabled, err := m.getNATStatus(); err == nil && enabled {
		fmt.Println("NAT masquerade already enabled")
		return nil
	}

	// Try nftables first, fallback to iptables
	if err := m.enableNATWithNftables(); err != nil {
		fmt.Printf("nftables failed, trying iptables: %v\n", err)
		if err := m.enableNATWithIptables(); err != nil {
			return fmt.Errorf("failed to enable NAT with both nftables and iptables: %w", err)
		}
	}

	fmt.Printf("NAT masquerade enabled on interface %s\n", m.publicInterface)
	return nil
}

// DisableNAT disables NAT masquerade
func (m *Manager) DisableNAT() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Try both nftables and iptables cleanup
	var lastErr error

	if err := m.disableNATWithNftables(); err != nil {
		lastErr = err
	}

	if err := m.disableNATWithIptables(); err != nil {
		lastErr = err
	}

	if lastErr != nil {
		return fmt.Errorf("errors during NAT cleanup: %w", lastErr)
	}

	fmt.Println("NAT masquerade disabled")
	return nil
}

// enableNATWithNftables enables NAT using nftables
func (m *Manager) enableNATWithNftables() error {
	commands := [][]string{
		{"nft", "add", "table", "ip", "netnat"},
		{"nft", "add", "chain", "ip", "netnat", "postrouting", "{", "type", "nat", "hook", "postrouting", "priority", "100", ";", "}"},
		{"nft", "add", "rule", "ip", "netnat", "postrouting", "oifname", m.publicInterface, "masquerade"},
	}

	for _, cmd := range commands {
		if err := exec.Command(cmd[0], cmd[1:]...).Run(); err != nil {
			return err
		}
	}

	return nil
}

// enableNATWithIptables enables NAT using iptables
func (m *Manager) enableNATWithIptables() error {
	cmd := exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-o", m.publicInterface, "-j", "MASQUERADE")
	return cmd.Run()
}

// disableNATWithNftables disables NAT using nftables
func (m *Manager) disableNATWithNftables() error {
	cmd := exec.Command("nft", "delete", "table", "ip", "netnat")
	return cmd.Run()
}

// disableNATWithIptables disables NAT using iptables
func (m *Manager) disableNATWithIptables() error {
	cmd := exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING", "-o", m.publicInterface, "-j", "MASQUERADE")
	return cmd.Run()
}

// getNATStatus checks if NAT is currently enabled
func (m *Manager) getNATStatus() (bool, error) {
	// Check nftables first
	if enabled, err := m.checkNftablesNAT(); err == nil {
		return enabled, nil
	}

	// Check iptables
	return m.checkIptablesNAT()
}

// checkNftablesNAT checks if NAT is enabled in nftables
func (m *Manager) checkNftablesNAT() (bool, error) {
	cmd := exec.Command("nft", "list", "table", "ip", "netnat")
	output, err := cmd.Output()
	if err != nil {
		return false, err
	}

	return strings.Contains(string(output), "masquerade"), nil
}

// checkIptablesNAT checks if NAT is enabled in iptables
func (m *Manager) checkIptablesNAT() (bool, error) {
	cmd := exec.Command("iptables", "-t", "nat", "-L", "POSTROUTING", "-n")
	output, err := cmd.Output()
	if err != nil {
		return false, err
	}

	return strings.Contains(string(output), "MASQUERADE") &&
		strings.Contains(string(output), m.publicInterface), nil
}

// ApplyRules applies DNAT rules
func (m *Manager) ApplyRules(rules []models.Rule) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Clear existing DNAT rules first
	if err := m.clearDNATRules(); err != nil {
		fmt.Printf("Warning: Failed to clear existing DNAT rules: %v\n", err)
	}

	// Apply new rules
	for _, rule := range rules {
		if rule.Enabled {
			if err := m.addDNATRule(rule); err != nil {
				return fmt.Errorf("failed to apply rule %s: %w", rule.ID, err)
			}
		}
	}

	fmt.Printf("Applied %d DNAT rules\n", len(rules))
	return nil
}

// AddDNATRule adds a single DNAT rule
func (m *Manager) AddDNATRule(rule models.Rule) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	return m.addDNATRule(rule)
}

// RemoveDNATRule removes a single DNAT rule
func (m *Manager) RemoveDNATRule(rule models.Rule) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	return m.removeDNATRule(rule)
}

// addDNATRule adds a DNAT rule using nftables or iptables
func (m *Manager) addDNATRule(rule models.Rule) error {
	// Try nftables first
	if err := m.addDNATRuleNftables(rule); err != nil {
		// Fallback to iptables
		return m.addDNATRuleIptables(rule)
	}
	return nil
}

// removeDNATRule removes a DNAT rule using nftables or iptables
func (m *Manager) removeDNATRule(rule models.Rule) error {
	// Try both nftables and iptables
	m.removeDNATRuleNftables(rule)
	m.removeDNATRuleIptables(rule)
	return nil
}

// addDNATRuleNftables adds DNAT rule using nftables
func (m *Manager) addDNATRuleNftables(rule models.Rule) error {
	// Ensure prerouting and forward chains exist
	commands := [][]string{
		{"nft", "add", "chain", "ip", "netnat", "prerouting", "{", "type", "nat", "hook", "prerouting", "priority", "-100", ";", "}"},
		{"nft", "add", "chain", "ip", "netnat", "forward", "{", "type", "filter", "hook", "forward", "priority", "0", ";", "}"},
	}

	for _, cmd := range commands {
		exec.Command(cmd[0], cmd[1:]...).Run() // Ignore errors for existing chains
	}

	// Add DNAT rule - bind to public interface for proper routing
	protocol := strings.ToLower(rule.Protocol)
	if protocol == "both" {
		// Add both TCP and UDP rules
		for _, proto := range []string{"tcp", "udp"} {
			// DNAT rule
			cmd := exec.Command("nft", "add", "rule", "ip", "netnat", "prerouting",
				"iifname", m.publicInterface, proto, "dport", fmt.Sprintf("%d", rule.ExternalPort),
				"dnat", "to", fmt.Sprintf("%s:%d", rule.InternalIP, rule.InternalPort))
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("failed to add nftables DNAT rule for %s: %w", proto, err)
			}

			// FORWARD rule to allow the forwarded traffic
			cmd = exec.Command("nft", "add", "rule", "ip", "netnat", "forward",
				"iifname", m.publicInterface, "oifname", m.config.Network.InternalBridge,
				proto, "dport", fmt.Sprintf("%d", rule.InternalPort),
				"ip", "daddr", rule.InternalIP, "ct", "state", "new,related,established", "accept")
			if err := cmd.Run(); err != nil {
				fmt.Printf("Warning: Failed to add nftables FORWARD rule for %s: %v\n", proto, err)
			}
		}
	} else {
		// DNAT rule
		cmd := exec.Command("nft", "add", "rule", "ip", "netnat", "prerouting",
			"iifname", m.publicInterface, protocol, "dport", fmt.Sprintf("%d", rule.ExternalPort),
			"dnat", "to", fmt.Sprintf("%s:%d", rule.InternalIP, rule.InternalPort))
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to add nftables DNAT rule for %s: %w", protocol, err)
		}

		// FORWARD rule to allow the forwarded traffic
		cmd = exec.Command("nft", "add", "rule", "ip", "netnat", "forward",
			"iifname", m.publicInterface, "oifname", m.config.Network.InternalBridge,
			protocol, "dport", fmt.Sprintf("%d", rule.InternalPort),
			"ip", "daddr", rule.InternalIP, "ct", "state", "new,related,established", "accept")
		if err := cmd.Run(); err != nil {
			fmt.Printf("Warning: Failed to add nftables FORWARD rule for %s: %v\n", protocol, err)
		}
	}

	return nil
}

// addDNATRuleIptables adds DNAT rule using iptables
func (m *Manager) addDNATRuleIptables(rule models.Rule) error {
	protocol := strings.ToLower(rule.Protocol)
	if protocol == "both" {
		// Add both TCP and UDP rules
		for _, proto := range []string{"tcp", "udp"} {
			// DNAT rule - bind to public interface
			cmd := exec.Command("iptables", "-t", "nat", "-A", "PREROUTING",
				"-i", m.publicInterface, "-p", proto, "--dport", fmt.Sprintf("%d", rule.ExternalPort),
				"-j", "DNAT", "--to-destination", fmt.Sprintf("%s:%d", rule.InternalIP, rule.InternalPort))
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("failed to add iptables DNAT rule for %s: %w", proto, err)
			}

			// FORWARD rule to allow the forwarded traffic
			cmd = exec.Command("iptables", "-A", "FORWARD",
				"-i", m.publicInterface, "-o", m.config.Network.InternalBridge,
				"-p", proto, "--dport", fmt.Sprintf("%d", rule.InternalPort),
				"-d", rule.InternalIP, "-m", "conntrack", "--ctstate", "NEW,RELATED,ESTABLISHED",
				"-j", "ACCEPT")
			if err := cmd.Run(); err != nil {
				fmt.Printf("Warning: Failed to add iptables FORWARD rule for %s: %v\n", proto, err)
			}
		}
	} else {
		// DNAT rule - bind to public interface
		cmd := exec.Command("iptables", "-t", "nat", "-A", "PREROUTING",
			"-i", m.publicInterface, "-p", protocol, "--dport", fmt.Sprintf("%d", rule.ExternalPort),
			"-j", "DNAT", "--to-destination", fmt.Sprintf("%s:%d", rule.InternalIP, rule.InternalPort))
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to add iptables DNAT rule for %s: %w", protocol, err)
		}

		// FORWARD rule to allow the forwarded traffic
		cmd = exec.Command("iptables", "-A", "FORWARD",
			"-i", m.publicInterface, "-o", m.config.Network.InternalBridge,
			"-p", protocol, "--dport", fmt.Sprintf("%d", rule.InternalPort),
			"-d", rule.InternalIP, "-m", "conntrack", "--ctstate", "NEW,RELATED,ESTABLISHED",
			"-j", "ACCEPT")
		if err := cmd.Run(); err != nil {
			fmt.Printf("Warning: Failed to add iptables FORWARD rule for %s: %v\n", protocol, err)
		}
	}

	return nil
}

// removeDNATRuleNftables removes DNAT rule using nftables
func (m *Manager) removeDNATRuleNftables(rule models.Rule) error {
	// This is more complex with nftables as we need to find the rule handle
	// For now, we'll rely on clearing all rules and re-applying
	return nil
}

// removeDNATRuleIptables removes DNAT rule using iptables
func (m *Manager) removeDNATRuleIptables(rule models.Rule) error {
	protocol := strings.ToLower(rule.Protocol)
	if protocol == "both" {
		for _, proto := range []string{"tcp", "udp"} {
			cmd := exec.Command("iptables", "-t", "nat", "-D", "PREROUTING",
				"-p", proto, "--dport", fmt.Sprintf("%d", rule.ExternalPort),
				"-j", "DNAT", "--to-destination", fmt.Sprintf("%s:%d", rule.InternalIP, rule.InternalPort))
			cmd.Run() // Ignore errors
		}
	} else {
		cmd := exec.Command("iptables", "-t", "nat", "-D", "PREROUTING",
			"-p", protocol, "--dport", fmt.Sprintf("%d", rule.ExternalPort),
			"-j", "DNAT", "--to-destination", fmt.Sprintf("%s:%d", rule.InternalIP, rule.InternalPort))
		cmd.Run() // Ignore errors
	}

	return nil
}

// clearDNATRules clears all DNAT rules
func (m *Manager) clearDNATRules() error {
	// Clear nftables DNAT and FORWARD rules
	exec.Command("nft", "flush", "chain", "ip", "netnat", "prerouting").Run()
	exec.Command("nft", "flush", "chain", "ip", "netnat", "forward").Run()

	// Clear iptables DNAT rules (only netnat-managed rules)
	// We'll use a more targeted approach to avoid clearing other rules
	cmd := exec.Command("iptables-save")
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			// Look for our DNAT rules and remove them
			if strings.Contains(line, "-A PREROUTING") && strings.Contains(line, "DNAT") && strings.Contains(line, m.publicInterface) {
				// Convert -A to -D for deletion
				deleteLine := strings.Replace(line, "-A PREROUTING", "-D PREROUTING", 1)
				parts := strings.Fields(deleteLine)
				if len(parts) > 2 {
					exec.Command("iptables", append([]string{"-t", "nat"}, parts[1:]...)...).Run()
				}
			}
		}
	}

	// Clear FORWARD rules for our port forwards
	cmd = exec.Command("iptables-save")
	output, err = cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			// Look for our FORWARD rules and remove them
			if strings.Contains(line, "-A FORWARD") && strings.Contains(line, m.publicInterface) && strings.Contains(line, m.config.Network.InternalBridge) {
				// Convert -A to -D for deletion
				deleteLine := strings.Replace(line, "-A FORWARD", "-D FORWARD", 1)
				parts := strings.Fields(deleteLine)
				if len(parts) > 1 {
					exec.Command("iptables", parts[1:]...).Run()
				}
			}
		}
	}

	return nil
}

// GetSystemStatus returns current system status
func (m *Manager) GetSystemStatus() (*models.SystemStatus, error) {
	ipForward, _ := m.getIPForwardingStatus()
	natEnabled, _ := m.getNATStatus()

	status := &models.SystemStatus{
		NATEnabled:       natEnabled,
		IPForwardEnabled: ipForward,
		PublicInterface:  m.publicInterface,
		InternalBridge:   m.config.Network.InternalBridge,
	}

	return status, nil
}

// GetPublicInterface returns the detected public interface
func (m *Manager) GetPublicInterface() string {
	return m.publicInterface
}

// RefreshPublicInterface re-detects the public interface
func (m *Manager) RefreshPublicInterface() error {
	newInterface, err := m.interfaceDetector.GetPublicInterface(m.config.Network.PublicInterface)
	if err != nil {
		return err
	}

	if newInterface != m.publicInterface {
		fmt.Printf("Public interface changed from %s to %s\n", m.publicInterface, newInterface)
		m.publicInterface = newInterface
	}

	return nil
}

// GetNetworkTraffic returns real-time network traffic data
func (m *Manager) GetNetworkTraffic() (*models.NetworkStats, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	stats := &models.NetworkStats{
		InterfaceStats: []models.NetworkTraffic{},
		LastUpdated:    time.Now(),
	}

	// Get traffic data for public interface
	publicTraffic, err := m.getInterfaceTraffic(m.publicInterface)
	if err == nil {
		stats.TotalTraffic = *publicTraffic
		stats.InterfaceStats = append(stats.InterfaceStats, *publicTraffic)
	}

	// Get traffic data for internal bridge if different
	if m.config.Network.InternalBridge != m.publicInterface {
		bridgeTraffic, err := m.getInterfaceTraffic(m.config.Network.InternalBridge)
		if err == nil {
			stats.InterfaceStats = append(stats.InterfaceStats, *bridgeTraffic)
		}
	}

	// Get active connections count
	connections, err := m.getActiveConnections()
	if err == nil {
		stats.TotalTraffic.ActiveConnections = connections
	}

	// Get port usage statistics
	portUsage, topPorts, err := m.getPortUsage()
	if err == nil {
		stats.TotalTraffic.PortUsage = portUsage
		stats.TotalTraffic.TopPorts = topPorts
	}

	return stats, nil
}

// getInterfaceTraffic gets traffic statistics for a specific interface using vnstat
func (m *Manager) getInterfaceTraffic(iface string) (*models.NetworkTraffic, error) {
	// Try vnstat first for permanent traffic data
	if traffic, err := m.getVnstatTraffic(iface); err == nil {
		return traffic, nil
	}

	// Fallback to /proc/net/dev for real-time statistics
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, iface+":") {
			fields := strings.Fields(line)
			if len(fields) >= 17 {
				// Parse RX and TX bytes
				rxBytes, _ := parseInt64(fields[1])
				txBytes, _ := parseInt64(fields[9])
				rxPackets, _ := parseInt64(fields[2])
				txPackets, _ := parseInt64(fields[10])

				traffic := &models.NetworkTraffic{
					Interface: iface,
					RXBytes:   rxBytes,
					TXBytes:   txBytes,
					RXPackets: rxPackets,
					TXPackets: txPackets,
					RXRate:    0, // Would need historical data for rate calculation
					TXRate:    0, // Would need historical data for rate calculation
					Timestamp: time.Now(),
				}

				// Format traffic data for display
				traffic.RXBytesFormatted = m.formatBytes(traffic.RXBytes)
				traffic.TXBytesFormatted = m.formatBytes(traffic.TXBytes)
				traffic.RXRateFormatted = m.formatRate(traffic.RXRate)
				traffic.TXRateFormatted = m.formatRate(traffic.TXRate)

				return traffic, nil
			}
		}
	}

	return nil, fmt.Errorf("interface %s not found in /proc/net/dev", iface)
}

// getVnstatTraffic gets permanent traffic data from vnstat
func (m *Manager) getVnstatTraffic(iface string) (*models.NetworkTraffic, error) {
	// Use vnstat to get monthly traffic data
	cmd := exec.Command("vnstat", "-i", iface, "--json", "m")
	output, err := cmd.Output()
	if err != nil {
		// Interface might not be monitored, try to add it
		addCmd := exec.Command("vnstat", "-i", iface, "--create")
		addCmd.Run()

		// Try again
		cmd = exec.Command("vnstat", "-i", iface, "--json", "m")
		output, err = cmd.Output()
		if err != nil {
			return nil, err
		}
	}

	// Parse vnstat JSON output
	var vnstatData map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(output))), &vnstatData); err != nil {
		return nil, err
	}

	traffic := &models.NetworkTraffic{
		Interface: iface,
		Timestamp: time.Now(),
	}

	// Extract monthly data
	if interfaces, ok := vnstatData["interfaces"].([]interface{}); ok && len(interfaces) > 0 {
		if ifaceData, ok := interfaces[0].(map[string]interface{}); ok {
			if trafficData, ok := ifaceData["traffic"].(map[string]interface{}); ok {
				// Try monthly data first
				if monthArray, ok := trafficData["month"].([]interface{}); ok && len(monthArray) > 0 {
					if latestMonth, ok := monthArray[0].(map[string]interface{}); ok {
						if rx, ok := latestMonth["rx"].(float64); ok {
							traffic.RXBytes = int64(rx) // Data is already in bytes
						}
						if tx, ok := latestMonth["tx"].(float64); ok {
							traffic.TXBytes = int64(tx) // Data is already in bytes
						}
					}
				}

				// Get daily average for rate calculation
				if dayArray, ok := trafficData["day"].([]interface{}); ok && len(dayArray) > 0 {
					if latestDay, ok := dayArray[0].(map[string]interface{}); ok {
						if rx, ok := latestDay["rx"].(float64); ok {
							traffic.RXRate = (rx * 1024 * 1024) / 86400 // MB/day to bytes/sec
						}
						if tx, ok := latestDay["tx"].(float64); ok {
							traffic.TXRate = (tx * 1024 * 1024) / 86400 // MB/day to bytes/sec
						}
					}
				}
			}
		}
	}

	// If vnstat returned zero data, try to get current session data
	if traffic.RXBytes == 0 && traffic.TXBytes == 0 {
		cmd = exec.Command("vnstat", "-i", iface, "--json", "h")
		output, err := cmd.Output()
		if err == nil {
			var hourData map[string]interface{}
			if json.Unmarshal([]byte(strings.TrimSpace(string(output))), &hourData) == nil {
				if interfaces, ok := hourData["interfaces"].([]interface{}); ok && len(interfaces) > 0 {
					if ifaceData, ok := interfaces[0].(map[string]interface{}); ok {
						if trafficData, ok := ifaceData["traffic"].(map[string]interface{}); ok {
							if hourArray, ok := trafficData["hour"].([]interface{}); ok && len(hourArray) > 0 {
								if latestHour, ok := hourArray[0].(map[string]interface{}); ok {
									if rx, ok := latestHour["rx"].(float64); ok {
										traffic.RXBytes = int64(rx) // Data is already in bytes
									}
									if tx, ok := latestHour["tx"].(float64); ok {
										traffic.TXBytes = int64(tx) // Data is already in bytes
									}
								}
							}
						}
					}
				}
			}
		}
	}

	// Format traffic data for display
	traffic.RXBytesFormatted = m.formatBytes(traffic.RXBytes)
	traffic.TXBytesFormatted = m.formatBytes(traffic.TXBytes)
	traffic.RXRateFormatted = m.formatRate(traffic.RXRate)
	traffic.TXRateFormatted = m.formatRate(traffic.TXRate)

	// Get daily history for the last 7 days
	dailyHistory, err := m.getDailyHistory(iface)
	if err == nil {
		traffic.DailyHistory = dailyHistory
	}

	return traffic, nil
}

// formatBytes formats bytes to human readable string
func (m *Manager) formatBytes(bytes int64) string {
	if bytes == 0 {
		return "0 B"
	}

	const unit = 1024
	units := []string{"B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"}

	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}

	exp := 0
	value := float64(bytes)
	for value >= unit && exp < len(units)-1 {
		value /= unit
		exp++
	}

	return fmt.Sprintf("%.1f %s", value, units[exp])
}

// formatRate formats bytes per second to human readable string
func (m *Manager) formatRate(bytesPerSec float64) string {
	if bytesPerSec == 0 {
		return "0 B/s"
	}

	const unit = 1024
	units := []string{"B/s", "KiB/s", "MiB/s", "GiB/s", "TiB/s", "PiB/s"}

	if bytesPerSec < unit {
		return fmt.Sprintf("%.1f B/s", bytesPerSec)
	}

	exp := 0
	value := bytesPerSec
	for value >= unit && exp < len(units)-1 {
		value /= unit
		exp++
	}

	return fmt.Sprintf("%.1f %s", value, units[exp])
}

// getDailyHistory gets daily traffic history for the last 7 days
func (m *Manager) getDailyHistory(iface string) ([]models.DailyTraffic, error) {
	// Use vnstat to get daily data for the last 7 days
	cmd := exec.Command("vnstat", "-i", iface, "--json", "d")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	// Parse vnstat JSON output
	var vnstatData map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(output))), &vnstatData); err != nil {
		return nil, err
	}

	var dailyHistory []models.DailyTraffic
	now := time.Now()
	today := now.Format("2006-01-02")
	yesterday := now.AddDate(0, 0, -1).Format("2006-01-02")

	if interfaces, ok := vnstatData["interfaces"].([]interface{}); ok && len(interfaces) > 0 {
		if ifaceData, ok := interfaces[0].(map[string]interface{}); ok {
			if trafficData, ok := ifaceData["traffic"].(map[string]interface{}); ok {
				if dayArray, ok := trafficData["day"].([]interface{}); ok {
					// Get last 7 days (or all available if less than 7)
					daysToShow := len(dayArray)
					if daysToShow > 7 {
						daysToShow = 7
					}

					// Start from the most recent (end of array)
					for i := daysToShow - 1; i >= 0 && len(dailyHistory) < 7; i-- {
						if dayData, ok := dayArray[i].(map[string]interface{}); ok {
							if dateObj, ok := dayData["date"].(map[string]interface{}); ok {
								if year, ok := dateObj["year"].(float64); ok {
									if month, ok := dateObj["month"].(float64); ok {
										if day, ok := dateObj["day"].(float64); ok {
											dateStr := fmt.Sprintf("%04d-%02d-%02d",
												int(year), int(month), int(day))

											rxBytes := int64(0)
											txBytes := int64(0)

											if rx, ok := dayData["rx"].(float64); ok {
												rxBytes = int64(rx) // Data is already in bytes
											}
											if tx, ok := dayData["tx"].(float64); ok {
												txBytes = int64(tx) // Data is already in bytes
											}

											daily := models.DailyTraffic{
												Date:              dateStr,
												RXBytes:           rxBytes,
												TXBytes:           txBytes,
												RXBytesFormatted:  m.formatBytes(rxBytes),
												TXBytesFormatted:  m.formatBytes(txBytes),
												IsToday:           dateStr == today,
												IsYesterday:       dateStr == yesterday,
											}

											dailyHistory = append(dailyHistory, daily)
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

	// If we have no data, create empty entries for the last 7 days
	if len(dailyHistory) == 0 {
		for i := 6; i >= 0; i-- {
			date := now.AddDate(0, 0, -i).Format("2006-01-02")
			daily := models.DailyTraffic{
				Date:              date,
				RXBytes:           0,
				TXBytes:           0,
				RXBytesFormatted:  "0 B",
				TXBytesFormatted:  "0 B",
				IsToday:           date == today,
				IsYesterday:       date == yesterday,
			}
			dailyHistory = append(dailyHistory, daily)
		}
	}

	return dailyHistory, nil
}

// configureVnstat configures vnstat to monitor interface and save statistics
func (m *Manager) configureVnstat(iface string) error {
	// Check if vnstat is installed
	if _, err := exec.LookPath("vnstat"); err != nil {
		return fmt.Errorf("vnstat is not installed")
	}

	// Create database for interface if it doesn't exist
	createCmd := exec.Command("vnstat", "-i", iface, "--create")
	if err := createCmd.Run(); err != nil {
		// Ignore if database already exists
	}

	// Set vnstat to save data every 5 minutes
	// First, try to update vnstat.conf
	configFile := "/etc/vnstat.conf"
	if _, err := os.Stat(configFile); err == nil {
		// Update configuration to save data more frequently
		updateCmd := exec.Command("sed", "-i", "s/^SaveInterval.*/SaveInterval 5/", configFile)
		updateCmd.Run() // Ignore errors

		updateCmd = exec.Command("sed", "-i", "s/^DatabaseDir.*/DatabaseDir \\/var\\/lib\\/vnstat/", configFile)
		updateCmd.Run() // Ignore errors
	}

	// Ensure vnstat service is enabled and running
	serviceCmd := exec.Command("systemctl", "enable", "vnstat")
	serviceCmd.Run() // Ignore errors

	serviceCmd = exec.Command("systemctl", "restart", "vnstat")
	serviceCmd.Run() // Ignore errors

	return nil
}

// getActiveConnections gets the count of active network connections
func (m *Manager) getActiveConnections() (int, error) {
	// Use netstat or ss to count active connections
	cmd := exec.Command("ss", "-tuln")
	output, err := cmd.Output()
	if err != nil {
		// Fallback to netstat
		cmd = exec.Command("netstat", "-tuln")
		output, err = cmd.Output()
		if err != nil {
			return 0, err
		}
	}

	lines := strings.Split(string(output), "\n")
	count := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "tcp") || strings.HasPrefix(line, "udp") {
			// Count listening ports
			if strings.Contains(line, "LISTEN") {
				count++
			}
		}
	}

	return count, nil
}

// getPortUsage gets port usage statistics with program information
func (m *Manager) getPortUsage() (map[string]int, []models.PortConnection, error) {
	portUsage := make(map[string]int)
	var topPorts []models.PortConnection

	// Use ss to get listening ports with process information
	cmd := exec.Command("ss", "-tulnp")
	output, err := cmd.Output()
	if err != nil {
		// Fallback to netstat with process info
		cmd = exec.Command("netstat", "-tulnp")
		output, err = cmd.Output()
		if err != nil {
			// Final fallback to netstat without process info
			cmd = exec.Command("netstat", "-tuln")
			output, err = cmd.Output()
			if err != nil {
				return portUsage, topPorts, err
			}
		}
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "tcp") || strings.HasPrefix(line, "udp") {
			fields := strings.Fields(line)
			if len(fields) >= 5 {
				localAddr := fields[4]
				if strings.Contains(localAddr, ":") {
					parts := strings.Split(localAddr, ":")
					if len(parts) == 2 {
						port := parts[1]
						protocol := "tcp"
						if strings.HasPrefix(line, "udp") {
							protocol = "udp"
						}

						key := fmt.Sprintf("%s:%s", protocol, port)
						portUsage[key]++

						// Add to top ports if listening
						if strings.Contains(line, "LISTEN") {
							description := "Listening port"
							program := ""

							// Extract program/process information
							if len(fields) > 6 {
								// ss format: ... "users":(("sshd",pid=1234,fd=3))
								processInfo := strings.Join(fields[6:], " ")

								// Extract program name from process info
								if strings.Contains(processInfo, "users:") {
									start := strings.Index(processInfo, "(\"")
									end := strings.Index(processInfo, "\",pid=")
									if start != -1 && end != -1 {
										program = processInfo[start+2 : end]
									}
								} else if strings.Contains(processInfo, "/") {
									// netstat format: ... sshd/1234
									parts := strings.Split(processInfo, "/")
									if len(parts) > 0 {
										program = parts[0]
									}
								}
							}

							// Set description based on port and program
							if port == "22" {
								description = "SSH"
								if program == "" || program == "-" {
									program = "sshd"
								}
							} else if port == "80" {
								description = "HTTP"
								if program == "" || program == "-" {
									program = "nginx/apache"
								}
							} else if port == "443" {
								description = "HTTPS"
								if program == "" || program == "-" {
									program = "nginx/apache"
								}
							} else if port == "53" {
								description = "DNS"
								if program == "" || program == "-" {
									program = "named/dnsmasq"
								}
							} else if port == "3306" {
								description = "MySQL/MariaDB"
								if program == "" || program == "-" {
									program = "mysqld"
								}
							} else if port == "5432" {
								description = "PostgreSQL"
								if program == "" || program == "-" {
									program = "postgres"
								}
							} else if port == "6379" {
								description = "Redis"
								if program == "" || program == "-" {
									program = "redis-server"
								}
							} else if port == "27017" {
								description = "MongoDB"
								if program == "" || program == "-" {
									program = "mongod"
								}
							} else {
								// For other ports, use program if available
								if program != "" && program != "-" {
									description = program
								}
							}

							topPorts = append(topPorts, models.PortConnection{
								Port:        port,
								Protocol:    protocol,
								Connections: 1,
								Description: description,
							})
						}
					}
				}
			}
		}
	}

	// Remove duplicates and sort by port number
	portMap := make(map[string]models.PortConnection)
	for _, port := range topPorts {
		key := fmt.Sprintf("%s:%s", port.Protocol, port.Port)
		if _, exists := portMap[key]; !exists {
			portMap[key] = port
		}
	}

	// Convert back to slice and sort
	var result []models.PortConnection
	for _, port := range portMap {
		result = append(result, port)
	}

	// Sort by port number and limit to top 8 (increased from 5)
	if len(result) > 8 {
		result = result[:8]
	}

	return portUsage, result, nil
}

// parseInt64 safely parses string to int64
func parseInt64(s string) (int64, error) {
	var result int64
	_, err := fmt.Sscanf(s, "%d", &result)
	return result, err
}
