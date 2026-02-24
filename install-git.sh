#!/bin/bash
# XeoKey Git Auto-Installation Script
# Detects system type and installs Git automatically

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "This script must be run as root or with sudo"
        echo "Usage: sudo $0"
        exit 1
    fi
}

# Function to detect operating system
detect_os() {
    print_status "Detecting operating system..."
    
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
        ID=$ID
        ID_LIKE=$ID_LIKE
    elif type lsb_release >/dev/null 2>&1; then
        OS=$(lsb_release -si)
        VER=$(lsb_release -sr)
        ID=$(lsb_release -si | tr '[:upper:]' '[:lower:]')
    elif [ -f /etc/lsb-release ]; then
        . /etc/lsb-release
        OS=$DISTRIB_ID
        VER=$DISTRIB_RELEASE
        ID=$(echo "$DISTRIB_ID" | tr '[:upper:]' '[:lower:]')
    elif [ -f /etc/debian_version ]; then
        OS=Debian
        VER=$(cat /etc/debian_version)
        ID=debian
    else
        print_error "Cannot detect operating system"
        exit 1
    fi
    
    print_success "Detected: $OS $VER (ID: $ID)"
}

# Function to check if Git is already installed
check_git_installed() {
    print_status "Checking if Git is already installed..."
    
    if command -v git >/dev/null 2>&1; then
        GIT_VERSION=$(git --version | awk '{print $3}')
        print_success "Git is already installed: $GIT_VERSION"
        
        # Check if Git version is adequate (>= 2.0)
        if git --version | grep -qE "git version [2-9]\."; then
            print_success "Git version is adequate"
            return 0
        else
            print_warning "Git version is old. Consider upgrading."
            return 1
        fi
    else
        print_status "Git is not installed"
        return 1
    fi
}

# Function to install Git on Ubuntu/Debian
install_git_debian() {
    print_status "Installing Git on Ubuntu/Debian system..."
    
    # Update package index
    print_status "Updating package index..."
    apt update || {
        print_error "Failed to update package index"
        return 1
    }
    
    # Install Git
    print_status "Installing Git package..."
    apt install -y git || {
        print_error "Failed to install Git"
        return 1
    }
    
    return 0
}

# Function to install Git on CentOS/RHEL
install_git_rhel() {
    print_status "Installing Git on CentOS/RHEL system..."
    
    # Check if dnf is available (CentOS 8+, RHEL 8+, Fedora)
    if command -v dnf >/dev/null 2>&1; then
        print_status "Using dnf package manager..."
        dnf install -y git || {
            print_error "Failed to install Git with dnf"
            return 1
        }
    # Fallback to yum (CentOS 7, RHEL 7)
    elif command -v yum >/dev/null 2>&1; then
        print_status "Using yum package manager..."
        yum install -y git || {
            print_error "Failed to install Git with yum"
            return 1
        }
    else
        print_error "Neither dnf nor yum package manager found"
        return 1
    fi
    
    return 0
}

# Function to install Git on Arch Linux
install_git_arch() {
    print_status "Installing Git on Arch Linux..."
    
    # Update package database
    pacman -Sy || {
        print_warning "Failed to update package database (may be normal)"
    }
    
    # Install Git
    pacman -S --noconfirm git || {
        print_error "Failed to install Git"
        return 1
    }
    
    return 0
}

# Function to install Git on openSUSE
install_git_suse() {
    print_status "Installing Git on openSUSE..."
    
    # Install Git
    zypper install -y git || {
        print_error "Failed to install Git"
        return 1
    }
    
    return 0
}

# Function to install Git on Alpine Linux
install_git_alpine() {
    print_status "Installing Git on Alpine Linux..."
    
    # Update package index
    apk update || {
        print_error "Failed to update package index"
        return 1
    }
    
    # Install Git
    apk add git || {
        print_error "Failed to install Git"
        return 1
    }
    
    return 0
}

# Function to install Git from source (fallback)
install_git_source() {
    print_status "Installing Git from source (fallback method)..."
    
    # Install build dependencies
    print_status "Installing build dependencies..."
    
    if command -v apt >/dev/null 2>&1; then
        apt update && apt install -y build-essential libssl-dev libcurl4-openssl-dev zlib1g-dev gettext
    elif command -v yum >/dev/null 2>&1 || command -v dnf >/dev/null 2>&1; then
        yum groupinstall -y "Development Tools" && yum install -y openssl-devel libcurl-devel zlib-devel gettext
    elif command -v pacman >/dev/null 2>&1; then
        pacman -S --noconfirm base-devel openssl libcurl zlib gettext
    else
        print_error "Cannot install build dependencies automatically"
        return 1
    fi
    
    # Download Git source
    GIT_VERSION="2.40.0"
    print_status "Downloading Git source code..."
    cd /tmp
    wget "https://github.com/git/git/archive/v${GIT_VERSION}.tar.gz" || {
        print_error "Failed to download Git source"
        return 1
    }
    
    # Extract and compile
    print_status "Extracting and compiling Git..."
    tar -xzf "v${GIT_VERSION}.tar.gz"
    cd "git-${GIT_VERSION}"
    
    make configure || {
        print_error "Failed to configure Git build"
        return 1
    }
    
    ./configure --prefix=/usr/local || {
        print_error "Failed to configure Git"
        return 1
    }
    
    make || {
        print_error "Failed to compile Git"
        return 1
    }
    
    make install || {
        print_error "Failed to install Git"
        return 1
    }
    
    # Clean up
    cd /tmp
    rm -rf "git-${GIT_VERSION}" "v${GIT_VERSION}.tar.gz"
    
    return 0
}

# Function to verify Git installation
verify_git() {
    print_status "Verifying Git installation..."
    
    if command -v git >/dev/null 2>&1; then
        GIT_VERSION=$(git --version)
        print_success "Git installation verified: $GIT_VERSION"
        
        # Test basic Git functionality
        cd /tmp
        git --help >/dev/null 2>&1 || {
            print_warning "Git installed but --help command failed"
        }
        
        return 0
    else
        print_error "Git installation verification failed"
        return 1
    fi
}

# Function to configure Git for XeoKey
configure_git() {
    print_status "Configuring Git for XeoKey..."
    
    # Configure user name and email
    git config --global user.name "XeoKey Server" || {
        print_warning "Failed to configure Git user name"
    }
    
    git config --global user.email "server@xeokey.local" || {
        print_warning "Failed to configure Git user email"
    }
    
    # Configure default branch
    git config --global init.defaultBranch master || {
        print_warning "Failed to configure default branch"
    }
    
    print_success "Git configured for XeoKey"
}

# Function to show next steps
show_next_steps() {
    echo ""
    print_success "Git installation completed successfully!"
    echo ""
    echo "Next steps for XeoKey:"
    echo "1. Restart XeoKey service: sudo systemctl restart xeokey"
    echo "2. Check update feature in XeoKey web interface"
    echo "3. Verify Git is working: git --version"
    echo ""
    echo "For more information, see: GIT_REQUIREMENTS.md"
    echo ""
}

# Main installation function
main() {
    echo "========================================"
    echo "XeoKey Git Auto-Installation Script"
    echo "========================================"
    echo ""
    
    # Check if running as root
    check_root
    
    # Detect operating system
    detect_os
    
    # Check if Git is already installed
    if check_git_installed; then
        show_next_steps
        exit 0
    fi
    
    # Install Git based on system type
    INSTALL_SUCCESS=false
    
    case "$ID" in
        ubuntu|debian|linuxmint|pop)
            print_status "Detected Debian-based system"
            if install_git_debian; then
                INSTALL_SUCCESS=true
            fi
            ;;
        centos|rhel|fedora|rocky|almalinux)
            print_status "Detected RHEL-based system"
            if install_git_rhel; then
                INSTALL_SUCCESS=true
            fi
            ;;
        arch)
            print_status "Detected Arch Linux"
            if install_git_arch; then
                INSTALL_SUCCESS=true
            fi
            ;;
        opensuse*|suse)
            print_status "Detected openSUSE"
            if install_git_suse; then
                INSTALL_SUCCESS=true
            fi
            ;;
        alpine)
            print_status "Detected Alpine Linux"
            if install_git_alpine; then
                INSTALL_SUCCESS=true
            fi
            ;;
        *)
            print_warning "Unknown system: $ID"
            print_status "Attempting source installation..."
            if install_git_source; then
                INSTALL_SUCCESS=true
            fi
            ;;
    esac
    
    # Verify installation
    if [ "$INSTALL_SUCCESS" = true ]; then
        if verify_git; then
            configure_git
            show_next_steps
            exit 0
        else
            print_error "Git installation verification failed"
            exit 1
        fi
    else
        print_error "Git installation failed"
        echo ""
        echo "Manual installation options:"
        echo "1. Ubuntu/Debian: sudo apt install git"
        echo "2. CentOS/RHEL: sudo yum install git"
        echo "3. Arch Linux: sudo pacman -S git"
        echo "4. Download from: https://git-scm.com/download"
        exit 1
    fi
}

# Run main function
main "$@"
