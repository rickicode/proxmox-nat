# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

NetNAT is a NAT and port forwarding management application designed for Proxmox environments. It provides a web interface to manage port forwarding rules, automatically discover VMs/containers, and maintain persistent NAT configurations.

**Architecture:**
- **Backend**: Go (single binary)
- **Frontend**: Bootstrap + Vanilla JavaScript
- **Storage**: JSON files (no database required)
- **Network**: nftables (with iptables fallback)
- **Discovery**: qemu-guest-agent, lxc, arp, manual input

## Common Development Commands

### Build Commands
```bash
# Build for current platform
make build

# Build for multiple architectures (amd64, arm64)
make build-all

# Clean build artifacts
make clean

# Run tests
make test

# Run tests with race detection
make test-race

# Format code
make fmt

# Lint code
make lint
```

### Development Workflow
```bash
# Install dependencies
make deps

# Run development server (requires sudo for network operations)
make dev

# Quick start (deps + build + run)
make start

# Check system requirements
make check
```

### Installation and System Management
```bash
# Install to system (creates systemd service, config files, etc.)
sudo make install

# Uninstall from system
sudo make uninstall

# Create distribution packages
make package
```

### Service Management (when installed)
```bash
# Start service
sudo systemctl start netnat

# Stop service
sudo systemctl stop netnat

# Restart service
sudo systemctl restart netnat

# Check status
sudo systemctl status netnat

# View logs
sudo journalctl -u netnat -f

# Enable autostart
sudo systemctl enable netnat
```

## Project Structure

```
cmd/netnat/main.go          # Application entry point
internal/                   # Internal packages
├── api/                    # HTTP API handlers and middleware
├── config/                 # Configuration management
├── backup/                 # Backup functionality
├── discovery/              # VM/container discovery
├── models/                 # Data models and types
├── network/                # NAT and network operations
├── storage/                # Rule persistence
└── web/                    # Embedded web interface
    ├── static/            # CSS, JS, images
    └── templates/         # HTML templates
configs/                   # Configuration files
systemd/                   # Systemd service file
install.sh                 # Installation script
Makefile                   # Build system
```

## Configuration

Configuration is managed through YAML files with these default locations:
1. `/etc/netnat/config.yml` (system installation)
2. `./configs/config.yml` (development)

Key configuration sections:
- **server**: Host, port, authentication
- **network**: Interface settings, NAT enablement
- **storage**: File paths for rules and backups
- **security**: CSRF protection, rate limiting

## Development Notes

### Running for Development
- Use `make dev` or run with sudo privileges as network operations require root access
- The application will automatically create default configuration if none exists
- Default web interface: http://localhost:8080
- Default credentials: admin/netnat123

### Testing Network Operations
- Most network functionality requires root privileges
- Test iptables/nftables rule creation carefully in development environment
- Use virtual machines or containers for safe testing

### Code Organization
- Handlers in `internal/api/` follow RESTful patterns
- Network operations in `internal/network/` abstract iptables/nftables differences
- Discovery mechanisms in `internal/discovery/` support multiple VM/container types
- All persistent data stored as JSON in `internal/storage/`

### Adding New Features
- API endpoints should follow existing patterns in handlers.go
- Frontend changes should maintain Bootstrap-based responsive design
- Network rule changes must support both iptables and nftables
- Configuration changes should update both models and default config

## Installation and Deployment

The project supports multiple installation methods:

1. **Automated Installation** (recommended):
   ```bash
   curl -sSL https://raw.githubusercontent.com/rickicode/proxmox-nat/main/install.sh | sudo bash
   ```

2. **Manual Installation**:
   ```bash
   git clone https://github.com/rickicode/proxmox-nat.git
   cd proxmox-nat
   sudo make install
   ```

The installer handles:
- Dependency installation (iptables, nftables, etc.)
- User and directory creation
- Systemd service configuration
- IP forwarding enablement
- Automatic startup configuration

## Security Considerations

- Default credentials should be changed in production
- The service runs as root for network operations
- Web interface listens on all interfaces by default
- CSRF protection and rate limiting are enabled by default
- Consider firewall rules for production deployments