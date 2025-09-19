package network

import (
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strings"
)

// InterfaceDetector handles network interface detection
type InterfaceDetector struct{}

// NewInterfaceDetector creates a new interface detector
func NewInterfaceDetector() *InterfaceDetector {
	return &InterfaceDetector{}
}

// GetPublicInterface detects the public interface based on configuration
func (d *InterfaceDetector) GetPublicInterface(configInterface string) (string, error) {
	if configInterface != "auto" {
		// Validate specified interface exists
		if exists, err := d.interfaceExists(configInterface); err != nil {
			return "", fmt.Errorf("failed to check interface %s: %w", configInterface, err)
		} else if !exists {
			return "", fmt.Errorf("interface %s does not exist", configInterface)
		}
		return configInterface, nil
	}

	// Auto-detect via default route
	return d.detectPublicInterface()
}

// detectPublicInterface finds the interface used for default route
func (d *InterfaceDetector) detectPublicInterface() (string, error) {
	// Try ip route first (modern systems)
	if iface, err := d.getDefaultRouteInterface(); err == nil && iface != "" {
		return iface, nil
	}

	// Fallback to route command (older systems)
	if iface, err := d.getDefaultRouteInterfaceLegacy(); err == nil && iface != "" {
		return iface, nil
	}

	// Last resort: find first non-loopback interface with default route
	return d.getFirstNonLoopbackInterface()
}

// getDefaultRouteInterface uses 'ip route' to find default interface
func (d *InterfaceDetector) getDefaultRouteInterface() (string, error) {
	cmd := exec.Command("ip", "route", "show", "default")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	// Parse output like: "default via 192.168.1.1 dev eth0 proto dhcp metric 100"
	re := regexp.MustCompile(`default\s+via\s+\S+\s+dev\s+(\S+)`)
	matches := re.FindStringSubmatch(string(output))
	if len(matches) >= 2 {
		return matches[1], nil
	}

	return "", fmt.Errorf("no default route found")
}

// getDefaultRouteInterfaceLegacy uses legacy 'route' command
func (d *InterfaceDetector) getDefaultRouteInterfaceLegacy() (string, error) {
	cmd := exec.Command("route", "-n")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 8 && fields[0] == "0.0.0.0" {
			return fields[7], nil // Interface is the 8th field
		}
	}

	return "", fmt.Errorf("no default route found in route table")
}

// getFirstNonLoopbackInterface returns the first non-loopback interface
func (d *InterfaceDetector) getFirstNonLoopbackInterface() (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range interfaces {
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		// Check if interface has IP address
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil { // IPv4 address
					return iface.Name, nil
				}
			}
		}
	}

	return "", fmt.Errorf("no suitable network interface found")
}

// interfaceExists checks if a network interface exists
func (d *InterfaceDetector) interfaceExists(name string) (bool, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return false, err
	}

	for _, iface := range interfaces {
		if iface.Name == name {
			return true, nil
		}
	}

	return false, nil
}

// GetInterfaceIP gets the IP address of an interface
func (d *InterfaceDetector) GetInterfaceIP(interfaceName string) (string, error) {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return "", fmt.Errorf("interface %s not found: %w", interfaceName, err)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return "", fmt.Errorf("failed to get addresses for %s: %w", interfaceName, err)
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil { // IPv4 address
				return ipnet.IP.String(), nil
			}
		}
	}

	return "", fmt.Errorf("no IPv4 address found for interface %s", interfaceName)
}

// GetBridgeInterfaces lists bridge interfaces
func (d *InterfaceDetector) GetBridgeInterfaces() ([]string, error) {
	var bridges []string

	// Check for Linux bridges
	if bridgeList, err := d.getLinuxBridges(); err == nil {
		bridges = append(bridges, bridgeList...)
	}

	// Check for OVS bridges if available
	if ovsBridges, err := d.getOVSBridges(); err == nil {
		bridges = append(bridges, ovsBridges...)
	}

	return bridges, nil
}

// getLinuxBridges lists Linux bridges using brctl
func (d *InterfaceDetector) getLinuxBridges() ([]string, error) {
	cmd := exec.Command("brctl", "show")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var bridges []string
	lines := strings.Split(string(output), "\n")

	for i, line := range lines {
		if i == 0 { // Skip header
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 1 && !strings.Contains(fields[0], "\t") {
			bridges = append(bridges, fields[0])
		}
	}

	return bridges, nil
}

// getOVSBridges lists Open vSwitch bridges
func (d *InterfaceDetector) getOVSBridges() ([]string, error) {
	cmd := exec.Command("ovs-vsctl", "list-br")
	output, err := cmd.Output()
	if err != nil {
		return nil, err // OVS might not be installed
	}

	var bridges []string
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			bridges = append(bridges, line)
		}
	}

	return bridges, nil
}

// ValidateInterface checks if an interface is valid and up
func (d *InterfaceDetector) ValidateInterface(name string) error {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return fmt.Errorf("interface %s not found: %w", name, err)
	}

	if iface.Flags&net.FlagUp == 0 {
		return fmt.Errorf("interface %s is down", name)
	}

	return nil
}

// GetInterfaceInfo returns detailed information about an interface
func (d *InterfaceDetector) GetInterfaceInfo(name string) (map[string]interface{}, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, fmt.Errorf("interface %s not found: %w", name, err)
	}

	info := map[string]interface{}{
		"name":          iface.Name,
		"mtu":           iface.MTU,
		"hardware_addr": iface.HardwareAddr.String(),
		"flags":         iface.Flags.String(),
		"up":            iface.Flags&net.FlagUp != 0,
		"addresses":     []string{},
	}

	addrs, err := iface.Addrs()
	if err == nil {
		var addresses []string
		for _, addr := range addrs {
			addresses = append(addresses, addr.String())
		}
		info["addresses"] = addresses
	}

	return info, nil
}
