# Changelog

All notable changes to NetNAT project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [1.1.0] - 2025-01-20

### Added
- Smart installer update system with version checking
- Multi-architecture binary support detection in installer
- Automatic backup during binary updates
- Enhanced installer with update, version, and help commands

### Changed
- Improved installer reliability with fallback mechanisms
- Enhanced error handling during updates
- Better version detection and comparison

### Fixed
- Embedded assets system for single binary distribution
- Template loading issues resolved with Go embed
- Configuration consistency between installer and application
- Service restart reliability during updates
### Added
- Embedded web assets for true single binary distribution
- Smart installer with automatic update capabilities
- Multi-architecture release support (AMD64, ARM64, ARMv7)
- Version checking and update notifications
- Enhanced installer commands (install, update, uninstall, version)

### Changed
- Web assets now embedded in binary using Go embed
- Installer automatically detects architecture and downloads appropriate binary
- Improved service management during updates
- Enhanced configuration file generation
- Default bridge interface changed to `vmbr1`

### Fixed
- Critical template loading issues with embedded filesystem
- Binary distribution problems resolved
- Service restart reliability improved
- Default configuration consistency across all files

## [1.0.0] - 2025-01-20

### Added
- Complete NAT & Port Forwarding management for Proxmox environments
- Web-based UI with professional dark theme
- Automated VM/CT discovery using hybrid approach (qemu-agent → lxc → arp → manual)
- Comprehensive backup & restore functionality with preview
- Dual firewall support (nftables with iptables fallback)
- Security features: Basic Auth, CSRF protection, and rate limiting
- Systemd service integration with proper capabilities
- One-line installer with curl support
- Multi-platform Linux builds (AMD64, ARM64, ARMv7)

### Features
- **Dashboard**: Real-time system status, NAT status, rule counts, network info
- **Port Forwarding**: Create, edit, delete, enable/disable DNAT rules
- **VM Discovery**: Automatic detection of VMs and containers
- **Quick Actions**: One-click NAT enable/disable, VM refresh, backup creation
- **Backup System**: Automatic backups before changes, manual backups, export/import
- **Network Management**: IPv4 forwarding, NAT masquerade, DNAT rules
- **Responsive UI**: Bootstrap-based interface with mobile support

### Technical
- **Backend**: Go (single binary) with comprehensive API
- **Frontend**: Bootstrap 5 + Vanilla JavaScript
- **Storage**: JSON files (no database required)
- **Network**: nftables (iptables fallback)
- **Service**: systemd with CAP_NET_ADMIN capabilities
- **Installation**: Automated installer script

### Security
- Basic Authentication with configurable credentials
- CSRF token protection for all mutating operations
- Rate limiting (60 requests/minute per IP by default)
- Secure file permissions and user isolation
- Input validation and sanitization

### Default Configuration
- Listen address: `0.0.0.0:8080`
- Username: `admin`
- Password: `netnat123` (⚠️ Must be changed after installation)
- Public interface: Auto-detected via default route
- Bridge interface: `vmbr1`

### Installation
```bash
# One-line installation
curl -sSL https://raw.githubusercontent.com/rickicode/proxmox-nat/main/install.sh | sudo bash

# Update to latest version
curl -sSL https://raw.githubusercontent.com/rickicode/proxmox-nat/main/install.sh | sudo bash -s update

# Check version
curl -sSL https://raw.githubusercontent.com/rickicode/proxmox-nat/main/install.sh | sudo bash -s version
```

### Supported Platforms
- Linux AMD64 (Primary target for Proxmox)
- Linux ARM64 (Raspberry Pi, ARM servers) 
- Linux ARMv7 (Older ARM devices)

[1.1.0]: https://github.com/rickicode/proxmox-nat/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/rickicode/proxmox-nat/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/rickicode/proxmox-nat/releases/tag/v1.0.0