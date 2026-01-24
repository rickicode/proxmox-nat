# NetNAT - NAT & Port Forwarding Manager

A simple yet powerful NAT and port forwarding management application designed for Proxmox environments. NetNAT provides an intuitive web interface to manage port forwarding rules, automatically discover VMs/containers, and maintain persistent NAT configurations.

![Dashboard Preview](https://raw.githubusercontent.com/rickicode/proxmox-nat/main/docs/dashboard.png)

## ✨ Key Features Explained

### 🚀 Zero-Config NAT Management
Enables NAT masquerading on your Proxmox host with a single toggle. No complex `iptables` commands needed. NetNAT manages the underlying `nftables` or `iptables` rules automatically, ensuring your VMs have internet access instantly via the host's public IP.

### 🔀 Smart Port Forwarding
Create and manage DNAT rules easily.
- **One-Click Rules**: create rules directly from the "Discovered VMs" list.
- **Protocol Support**: TCP, UDP, or Both.
- **Validation**: Prevents invalid port ranges or conflicting rules.
- **Persistence**: Rules are saved to disk and automatically restored on reboot.

### 🛡️ Dual-Stack Firewall Engine
Built for modern Linux systems, NetNAT prioritizes **nftables** for performance and atomic rule updates. It automatically falls back to **iptables** on older systems, ensuring broad compatibility across different Proxmox versions (7.x, 8.x) and Debian/Ubuntu releases.

### 🔍 Intelligent VM Discovery
Forget typing IP addresses manually. NetNAT scans your system to find VMs and containers:
- **QEMU Guest Agent**: Queries the guest agent for precise local IPs.
- **LXC Status**: Reads network state directly from LXC containers.
- **ARP Table**: Scans the bridge for active devices as a fallback.
This allows you to select a target VM by name ("Ubuntu-Webserver") instead of hunting for its IP.

### 📊 Real-time System Monitoring
The dashboard provides a live view of your server's health:
- **Network Traffic**: Visual charts showing real-time Upload/Download rates (requires `vnstat`).
- **System Health**: Live CPU load, Memory usage, and Uptime monitoring.
- **Rule Status**: Instant overview of active vs. total rules.

### 💾 Automated Backups
Never lose your configuration.
- **Auto-Backup**: Automatically creates a checkpoint before any rule change.
- **Retention Policy**: Keeps the last 30 backups to save space (configurable).
- **One-Click Restore**: Rollback to any previous state instantly if you make a mistake.

### 🔒 Built-in Security
- **Authentication**: Secure Basic Auth (configurable username/password).
- **CSRF Protection**: Prevents cross-site request forgery attacks.
- **Rate Limiting**: Protects the API from brute-force attempts.
- **Local-Only Mode**: Can be bound to localhost for use with SSH tunnels for maximum security.

## 🚀 Quick Install

### Automated Installation (Recommended)

Run the following command to download and install the latest release automatically:

```bash
curl -sSL https://raw.githubusercontent.com/rickicode/proxmox-nat/main/install.sh | sudo bash
```

The installer will:
- Detect your system architecture (amd64, arm64, armv7)
- Download the latest binary and configuration from GitHub
- Install dependencies (`iptables`, `nftables`, `vnstat`, etc.)
- Set up the systemd service
- Configure IP forwarding

### Manual Installation (From Source)

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/rickicode/proxmox-nat.git
    cd proxmox-nat
    ```

2.  **Build and Install**:
    ```bash
    # Requires Go 1.21+ and Node.js 18+
    sudo make install
    ```

## ⚙️ Configuration

The default configuration is located at `/opt/netnat/config.yml`.

```yaml
server:
  listen_addr: "0.0.0.0:8080"
  username: "admin"
  password: "netnat123" # CHANGE THIS!

network:
  public_interface: "auto" # or "eth0", "vmbr0"
  internal_bridge: "vmbr0" # Bridge for VMs/CTs
```

After changing configuration, restart the service:
```bash
sudo systemctl restart netnat
```

## 📖 Usage Guide

### Accessing the Dashboard
Open your browser and navigate to `http://<your-server-ip>:8080`.
Log in with the default credentials (`admin` / `netnat123`).

### Creating a Forwarding Rule
1.  Navigate to the **Rules** page.
2.  Click the **Add Rule** button.
3.  **Name**: Give it a recognizable name (e.g., "Web Server").
4.  **External Port**: The port on your Proxmox host (e.g., `80`).
5.  **Internal IP**: The IP of your VM (select from the dropdown if discovered).
6.  **Internal Port**: The port inside the VM (e.g., `80`).
7.  Click **Create**. The rule is applied instantly.

### Troubleshooting Network Issues
If rules aren't working:
1.  Check the **Dashboard** to see if "NAT Enabled" is green.
2.  Verify the VM IP hasn't changed.
3.  Ensure the VM's own firewall (ufw/firewalld) isn't blocking the port.

## 🛠️ Management Commands

```bash
# Check Service Status
sudo systemctl status netnat

# View Live Logs
sudo journalctl -u netnat -f

# Uninstall NetNAT
curl -sSL https://raw.githubusercontent.com/rickicode/proxmox-nat/main/install.sh | sudo bash -s uninstall
```

## ❓ FAQ & Support

**Q: Does this work with Proxmox VE 8?**
A: Yes, NetNAT is fully compatible with Proxmox VE 7 and 8.

**Q: Can I use this on a standard Debian server?**
A: Yes, as long as it acts as a gateway/router for other devices.

**Q: Where are the logs?**
A: Logs are managed by systemd. Use `journalctl -u netnat` to view them.

For bug reports or feature requests, please use the [GitHub Issues](https://github.com/rickicode/proxmox-nat/issues) page.

## 🤝 Contributing

Contributions are welcome!
1. Fork the repo
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

MIT License
