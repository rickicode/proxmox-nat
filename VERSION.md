# NetNAT Version Information

This document describes how version information is managed in NetNAT.

## Version Format

NetNAT follows [Semantic Versioning](https://semver.org/):

```
vMAJOR.MINOR.PATCH
```

- **MAJOR**: Incompatible API changes
- **MINOR**: New functionality (backwards compatible)
- **PATCH**: Bug fixes (backwards compatible)

Examples: `v1.0.0`, `v1.2.3`, `v2.0.0`

## Version Information in Binary

The binary includes embedded version information:

```bash
./netnat --version
```

Output:
```
NetNAT v1.0.0
Build Time: 2024-01-23T10:30:00Z
Git Commit: abc1234
```

## Build with Version Info

### Using Makefile

```bash
# Build with automatic version detection
make build

# Build with specific version
VERSION=v1.2.3 make build
```

### Manual Build

```bash
VERSION="v1.0.0"
BUILD_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)
GIT_COMMIT=$(git rev-parse --short HEAD)

go build \
  -ldflags="-s -w \
    -X main.Version=${VERSION} \
    -X main.BuildTime=${BUILD_TIME} \
    -X main.GitCommit=${GIT_COMMIT}" \
  -o netnat \
  ./cmd/netnat
```

## Creating a Release

### 1. Update CHANGELOG.md

Add release notes for the new version:

```markdown
## [1.2.3] - 2024-01-23

### Added
- New feature X

### Fixed
- Bug Y
```

### 2. Create Git Tag

```bash
# Create annotated tag
git tag -a v1.2.3 -m "Release v1.2.3"

# Push tag to GitHub
git push origin v1.2.3
```

### 3. GitHub Actions Automatic Release

When you push a tag matching `v*.*.*`, GitHub Actions will automatically:

1. Build binaries for linux-amd64 and linux-arm64
2. Create release packages with:
   - Binary
   - install.sh
   - configs/
   - systemd/
   - README.md
3. Generate changelog from git commits
4. Create GitHub release with:
   - Release notes
   - Installation instructions
   - Checksums (SHA256)
   - Download links

### 4. Manual Release (if needed)

```bash
# Trigger manual release
gh workflow run release.yml -f version=v1.2.3
```

## Version Checking

### Check Installed Version

```bash
# Via binary
/opt/netnat/netnat --version

# Via systemd
systemctl status netnat | grep Version
```

### Check Latest Release

```bash
# Via GitHub API
curl -s https://api.github.com/repos/rickicode/proxmox-nat/releases/latest | jq -r .tag_name

# Via GitHub CLI
gh release view --repo rickicode/proxmox-nat
```

## Release Artifacts

Each release includes:

### Packages

- `netnat-v1.0.0-linux-amd64.tar.gz` - AMD64 binary package
- `netnat-v1.0.0-linux-arm64.tar.gz` - ARM64 binary package

### Checksums

- `netnat-v1.0.0-linux-amd64.tar.gz.sha256`
- `netnat-v1.0.0-linux-arm64.tar.gz.sha256`

### Verify Download

```bash
# Download package and checksum
wget https://github.com/rickicode/proxmox-nat/releases/download/v1.0.0/netnat-v1.0.0-linux-amd64.tar.gz
wget https://github.com/rickicode/proxmox-nat/releases/download/v1.0.0/netnat-v1.0.0-linux-amd64.tar.gz.sha256

# Verify checksum
sha256sum -c netnat-v1.0.0-linux-amd64.tar.gz.sha256
```

## Development Builds

Development builds use version format:

```
dev-{git-commit-hash}
```

Example: `dev-abc1234`

## CI/CD Workflows

### Build Workflow (`.github/workflows/build.yml`)

Runs on every push to `main` or `develop`:
- Lint code
- Run tests
- Build binaries for all platforms
- Upload artifacts (7 days retention)

### Release Workflow (`.github/workflows/release.yml`)

Runs on tag push (`v*.*.*`):
- Build release binaries
- Create packages
- Generate changelog
- Create GitHub release
- Upload release assets

## Version in API

The API exposes version information:

```bash
curl http://localhost:8080/api/version
```

Response:
```json
{
  "version": "v1.0.0",
  "build_time": "2024-01-23T10:30:00Z",
  "git_commit": "abc1234"
}
```

## Changelog Management

### Format

Follow [Keep a Changelog](https://keepachangelog.com/) format:

```markdown
## [Version] - YYYY-MM-DD

### Added
- New features

### Changed
- Changes in existing functionality

### Fixed
- Bug fixes

### Security
- Security improvements
```

### Auto-generated Changelog

GitHub Actions automatically generates changelog from:
- Git commits between tags
- Commit messages
- Pull request titles

### Manual Changelog

Update `CHANGELOG.md` before creating release tag for better release notes.

## Best Practices

1. **Always tag releases** - Use annotated tags with messages
2. **Update CHANGELOG.md** - Before creating release
3. **Test before release** - Ensure all tests pass
4. **Semantic versioning** - Follow semver strictly
5. **Sign releases** - Use GPG signing for tags (optional)
6. **Document breaking changes** - In CHANGELOG and release notes

## Troubleshooting

### Version shows "dev"

Binary was built without version flags. Use Makefile or set ldflags manually.

### GitHub Actions fails

Check:
- Go version compatibility (requires 1.21+)
- Node.js version (requires 20+)
- GitHub token permissions
- Tag format matches `v*.*.*`

### Release not created

Ensure:
- Tag is pushed to GitHub
- Tag format is correct (`v1.2.3`)
- GitHub Actions has write permissions
- No workflow errors in Actions tab
