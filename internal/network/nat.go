package network

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"

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

	return &Manager{
		config:            config,
		interfaceDetector: detector,
		publicInterface:   publicInterface,
	}, nil
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
