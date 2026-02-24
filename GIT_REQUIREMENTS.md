# XeoKey Git Requirements Documentation

## Overview

XeoKey requires Git to be installed for the update feature to work. This document explains why Git is needed and how to install it on different systems.

## Why XeoKey Needs Git

### Update Feature Functionality
The update feature in XeoKey relies on Git for several critical operations:

1. **Update Detection**
   - `git fetch origin` - Checks for available updates
   - `git rev-parse HEAD` - Gets current commit hash
   - `git rev-parse origin/{branch}` - Gets remote commit hash

2. **Update Process**
   - `git pull origin master` - Downloads latest changes
   - `git log --pretty=format:%s` - Generates changelog/patch notes

3. **Version Management**
   - Branch detection and switching
   - Commit comparison between local and remote
   - Rollback capabilities

### Components That Use Git
- **Web Interface**: Update checking and patch notes display
- **Process Manager**: Automatic updates during restart
- **SystemD Service**: Update script for production deployments
- **CLI Tools**: Manual update commands

## System-Specific Installation

### Ubuntu/Debian Systems
```bash
# Update package index
sudo apt update

# Install Git
sudo apt install git

# Verify installation
git --version
```

### CentOS/RHEL Systems
```bash
# For CentOS 7/RHEL 7
sudo yum install git

# For CentOS 8/RHEL 8/Fedora
sudo dnf install git

# Verify installation
git --version
```

### Arch Linux Systems
```bash
# Install Git
sudo pacman -S git

# Verify installation
git --version
```

### openSUSE Systems
```bash
# Install Git
sudo zypper install git

# Verify installation
git --version
```

### Alpine Linux Systems
```bash
# Install Git
sudo apk add git

# Verify installation
git --version
```

### macOS Systems
```bash
# Using Homebrew (recommended)
brew install git

# Or download from https://git-scm.com/download/mac

# Verify installation
git --version
```

### Windows Systems
```powershell
# Using winget (Windows 10/11)
winget install Git.Git

# Or download from https://git-scm.com/download/win

# Verify installation
git --version
```

## Auto-Installation Script

XeoKey includes an auto-installation script that detects your system and installs Git automatically:

```bash
# Run the auto-install script
sudo ./install-git.sh
```

The script will:
- Detect your operating system
- Choose the appropriate package manager
- Install Git using the correct command
- Verify the installation
- Provide feedback on success/failure

## Troubleshooting

### Git Not Found Error
If you see this error:
```
Error: Git command not found. Please install Git to use the update feature.
```

**Solution**: Run the auto-install script or install Git manually using the commands above.

### Permission Denied Error
```bash
sudo: command not found
```

**Solution**: You need sudo privileges. Contact your system administrator or use a user account with sudo access.

### Network Issues
```bash
Failed to download package information
```

**Solution**: Check your internet connection and package manager configuration.

### Git Installation Verification
After installation, verify Git is working:

```bash
# Check Git version
git --version

# Test Git commands
git --help

# Check if in a git repository
git status
```

## Manual Installation Fallback

If the auto-install script fails, you can install Git manually:

### 1. Download Git Source
```bash
wget https://github.com/git/git/archive/v2.40.0.tar.gz
tar -xzf v2.40.0.tar.gz
cd git-2.40.0
```

### 2. Install Dependencies
```bash
# Ubuntu/Debian
sudo apt install build-essential libssl-dev libcurl4-openssl-dev zlib1g-dev

# CentOS/RHEL
sudo yum groupinstall "Development Tools"
sudo yum install openssl-devel libcurl-devel zlib-devel
```

### 3. Compile and Install
```bash
make configure
./configure --prefix=/usr/local
make
sudo make install
```

## Git Configuration

After installation, configure Git for XeoKey:

```bash
# Configure user name (required for commits)
git config --global user.name "XeoKey Server"

# Configure user email (required for commits)
git config --global user.email "server@xeokey.local"

# Configure default branch name
git config --global init.defaultBranch master

# Verify configuration
git config --list
```

## Security Considerations

### Git Repository Access
- Ensure the XeoKey directory has proper Git permissions
- The service user should have read/write access to the Git repository
- Consider using a dedicated deployment key for production

### Update Security
- Git updates are signed using GitHub's security features
- Always verify updates come from the official repository
- Consider using Git's commit signing for additional security

## Alternative: No-Git Mode

If you cannot install Git, XeoKey can run without the update feature:

1. **Disable Update UI**: Remove update-related code from the web interface
2. **Manual Updates Only**: Download and replace files manually
3. **Package Manager**: Use system package manager for updates (if available)

## Support

For Git installation issues:

1. Check the [Git documentation](https://git-scm.com/doc)
2. Verify system compatibility
3. Check network connectivity
4. Ensure proper permissions
5. Contact your system administrator if needed

## Quick Start Summary

```bash
# One-command installation (recommended)
sudo ./install-git.sh

# Or manual installation based on system:
# Ubuntu/Debian: sudo apt install git
# CentOS/RHEL: sudo yum install git  # or dnf install git
# Arch Linux: sudo pacman -S git
# macOS: brew install git
# Windows: winget install Git.Git

# Verify installation
git --version

# Configure for XeoKey
git config --global user.name "XeoKey Server"
git config --global user.email "server@xeokey.local"
```

After Git is installed, XeoKey's update feature will work automatically through the web interface or command line.
