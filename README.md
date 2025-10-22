# NetNAT - NAT & Port Forwarding Manager

A simple yet powerful NAT and port forwarding management application designed for Proxmox environments. NetNAT provides an intuitive web interface to manage port forwarding rules, automatically discover VMs/containers, and maintain persistent NAT configurations.

## ✨ Features

- 🚀 **Easy NAT Management** - Enable/disable NAT with a single click
- 🔀 **Port Forwarding Rules** - Create, edit, and manage DNAT rules via web UI
- 🔍 **VM/CT Discovery** - Automatic discovery of VMs and containers with hybrid IP detection
- 💾 **Backup & Restore** - Automatic backups with manual restore capabilities
- 🔒 **Security** - Basic Auth, CSRF protection, and rate limiting
- 🛡️ **Dual Firewall Support** - Works with both nftables and iptables
- 📱 **Responsive UI** - Bootstrap-based dark theme interface that works on mobile devices
- ⚙️ **Systemd Integration** - Runs as a system service with proper capabilities

## 🏗️ Architecture

- **Backend**: Go (single binary)
- **Frontend**: Bootstrap + Vanilla JavaScript
- **Storage**: JSON files (no database required)
- **Network**: nftables (with iptables fallback)
- **Discovery**: qemu-guest-agent, lxc, arp, manual input

## 📋 Requirements

- Linux system (Debian/Ubuntu/Proxmox)
- Go 1.19+ (for building)
- iptables and/or nftables
- systemd (for service management)
- Root privileges (for network operations)

## 🚀 Quick Install

### Automated Installation (Recommended)

```bash
# Download and run the installer
curl -sSL https://raw.githubusercontent.com/rickicode/proxmox-nat/main/install.sh | sudo bash

# Or download first and then run
wget https://raw.githubusercontent.com/rickicode/proxmox-nat/main/install.sh
chmod +x install.sh
sudo ./install.sh
```

The installer will:
- Install all dependencies
- Create necessary users and directories
- Download or use the NetNAT binary
- Configure systemd service with proper capabilities
- Enable automatic startup on boot
- Configure IP forwarding

### Manual Installation

#### 1. Clone and Build

```bash
git clone https://github.com/rickicode/proxmox-nat.git
cd proxmox-nat

# Build the application
make build

# Or install system-wide
sudo make install
```

#### 2. Configuration

Edit the configuration file:

```bash
sudo nano /etc/netnat/config.yml
```

Default configuration:
```yaml
server:
  host: "0.0.0.0"
  port: 8080
  auth:
    username: "admin"
    password: "netnat123"  # CHANGE THIS!

network:
  public_interface: "auto"  # auto-detect via default route
  bridge_interface: "vmbr0"
  enable_ipv4_forward: true
  enable_nat: true

storage:
  rules_file: "/var/lib/netnat/rules.json"
  backup_dir: "/var/lib/netnat/backups"

logging:
  level: "info"
  file: "/var/log/netnat/netnat.log"
  max_size: 10
  max_backups: 5
  max_age: 30

security:
  csrf_key: "netnat-csrf-secret-key-change-this-in-production"
  rate_limit:
    requests_per_minute: 60
    burst: 10
```

#### 3. Start the Service

```bash
# Start the service
sudo systemctl start netnat

# Enable auto-start on boot
sudo systemctl enable netnat

# Check status
sudo systemctl status netnat
```

#### 4. Access Web Interface

Open your browser and navigate to:
```
http://localhost:8080
```

Login with:
- Username: `admin`
- Password: `netnat123` (or your configured password)

## 📖 Usage

### Dashboard

The dashboard provides an overview of your NAT configuration:

- **System Status**: Current NAT and IP forwarding status
- **Rule Counts**: Number of active and total rules
- **Network Info**: Public interface and internal bridge information
- **Quick Actions**: Enable/disable NAT, refresh VM list, create backups

### Port Forwarding Rules

Create and manage port forwarding rules:

1. Click "Add Rule" to create a new rule
2. Fill in the required information:
   - **Rule Name**: Descriptive name for the rule
   - **External Port**: Port on the public interface
   - **Internal IP**: Target VM/container IP address
   - **Internal Port**: Port on the target machine
   - **Protocol**: TCP, UDP, or both
3. Enable/disable rules individually
4. Edit or delete existing rules

### VM/Container Discovery

NetNAT automatically discovers VMs and containers using:

1. **QEMU Guest Agent** (most accurate for VMs)
2. **LXC commands** (for containers)
3. **ARP table** (fallback for any device on the bridge)
4. **Manual input** (for devices not auto-discovered)

Use the "Forward Port" button next to any discovered VM to quickly create a forwarding rule.

### Backup Management

NetNAT provides comprehensive backup functionality:

- **Automatic Backups**: Created before any rule changes
- **Manual Backups**: Create backups on demand
- **Export/Import**: Download backups or upload external backups
- **Preview**: See what changes a restore will make before applying

## 🔧 Command Line Usage

### Build Commands

```bash
# Build for current platform
make build

# Build for multiple architectures
make build-all

# Clean build artifacts
make clean

# Run tests
make test

# Format code
make fmt
```

### Installation Commands

```bash
# Install to system
sudo make install

# Uninstall from system
sudo make uninstall

# Create distribution packages
make package
```

### Development Commands

```bash
# Install dependencies
make deps

# Run development server
make dev

# Check system requirements
make check

# Show help
make help
```

## ⚙️ Configuration Reference

### Server Configuration

| Setting | Description | Default |
|---------|-------------|---------|
| `host` | Server listening address | `0.0.0.0` |
| `port` | Server listening port | `8080` |
| `auth.username` | Basic auth username | `admin` |
| `auth.password` | Basic auth password | `netnat123` |

### Network Configuration

| Setting | Description | Default |
|---------|-------------|---------|
| `public_interface` | Public network interface | `auto` |
| `bridge_interface` | Internal bridge interface | `vmbr0` |
| `enable_ipv4_forward` | Enable IP forwarding | `true` |
| `enable_nat` | Enable NAT masquerade | `true` |

### Storage Configuration

| Setting | Description | Default |
|---------|-------------|---------|
| `rules_file` | Path to rules JSON file | `/var/lib/netnat/rules.json` |
| `backup_dir` | Backup directory | `/var/lib/netnat/backups` |

### Security Configuration

| Setting | Description | Default |
|---------|-------------|---------|
| `csrf_key` | CSRF protection secret key | `(change-required)` |
| `rate_limit.requests_per_minute` | Requests per minute per IP | `60` |
| `rate_limit.burst` | Burst limit | `10` |

## 🐛 Troubleshooting

### Service Won't Start

1. Check service status:
   ```bash
   sudo systemctl status netnat
   ```

2. Check logs:
   ```bash
   sudo journalctl -u netnat -f
   ```

3. Verify configuration:
   ```bash
   sudo netnat --check-config
   ```

### NAT Not Working

1. Verify IP forwarding is enabled:
   ```bash
   cat /proc/sys/net/ipv4/ip_forward
   ```

2. Check iptables/nftables rules:
   ```bash
   # For iptables
   sudo iptables -t nat -L

   # For nftables
   sudo nft list table ip netnat
   ```

3. Verify interface configuration:
   ```bash
   ip route show default
   ```

### Port Forwarding Not Working

1. Check if rule is enabled in the web interface
2. Verify the target VM/container is running
3. Check if the internal port is actually listening:
   ```bash
   # From inside the VM/container
   netstat -ln | grep :80
   ```

4. Test connectivity:
   ```bash
   # From the Proxmox host
   telnet <vm_ip> <internal_port>
   ```

### Web Interface Issues

1. Verify the service is listening:
   ```bash
   sudo netstat -tlnp | grep :8080
   ```

2. Check authentication credentials in config
3. Try accessing from localhost first:
   ```bash
   curl -u admin:netnat123 http://localhost:8080/api/status
   ```

## 🔒 Security Considerations

1. **Change Default Password**: Always change the default password in the configuration
2. **Network Access**: By default, NetNAT listens on all interfaces. Consider firewall rules for access control
3. **Firewall Rules**: Ensure only authorized users can access the web interface
4. **Regular Backups**: Enable automatic backups to prevent configuration loss
5. **Log Monitoring**: Monitor systemd logs for suspicious activity

## 🛠️ Management Commands

```bash
# Service management
sudo systemctl start netnat        # Start service
sudo systemctl stop netnat         # Stop service
sudo systemctl restart netnat      # Restart service
sudo systemctl status netnat       # Check status

# Log viewing
sudo journalctl -u netnat -f       # Follow logs
sudo journalctl -u netnat --since "1 hour ago"  # Recent logs

# Configuration
sudo nano /etc/netnat/config.yml   # Edit config
sudo netnat --check-config         # Validate config
```

## 🗑️ Uninstallation

To completely remove NetNAT:

```bash
# Using the installer
sudo ./install.sh uninstall

# Or manually
sudo systemctl stop netnat
sudo systemctl disable netnat
sudo rm -rf /opt/netnat /etc/netnat /var/lib/netnat /var/log/netnat
sudo rm /etc/systemd/system/netnat.service
sudo userdel netnat
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

- **Issues**: Report bugs and feature requests on [GitHub](https://github.com/rickicode/proxmox-nat/issues)
- **Discussions**: Join the community discussions on GitHub
- **Documentation**: Check the wiki for additional documentation

---

**Note**: This software is designed for Proxmox environments but should work on any Linux system with the required dependencies. Always test in a development environment before deploying to production.

## 🔗 GitHub Repository

**Repository**: [https://github.com/rickicode/proxmox-nat](https://github.com/rickicode/proxmox-nat)

Clone with:
```bash
git clone https://github.com/rickicode/proxmox-nat.git
```
