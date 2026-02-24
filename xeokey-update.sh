#!/bin/bash
# XeoKey SystemD Update Script

set -e

echo "🔄 XeoKey SystemD Update Script"
echo "================================"

# Check if running as root or with sudo
if [ "$EUID" -ne 0 ]; then
    echo "❌ This script must be run as root or with sudo"
    echo "Usage: sudo ./xeokey-update.sh"
    exit 1
fi

# Get service status before update
echo "📋 Checking current service status..."
if systemctl is-active --quiet xeokey; then
    echo "✅ XeoKey service is running"
    SERVICE_WAS_RUNNING=true
else
    echo "⚠️  XeoKey service is not running"
    SERVICE_WAS_RUNNING=false
fi

# Navigate to project directory
cd /home/xeo/XeoKey || {
    echo "❌ Cannot find XeoKey directory at /home/xeo/XeoKey"
    exit 1
}

# Check if we're in a git repository
if [ ! -d ".git" ]; then
    echo "❌ Not a git repository. Cannot update."
    exit 1
fi

# Show current version
echo "📝 Current version:"
git log --oneline -1

# Fetch latest changes
echo "📡 Fetching latest changes..."
git fetch origin master

# Check if updates are available
if [ "$(git rev-parse HEAD)" = "$(git rev-parse origin/master)" ]; then
    echo "✅ Already up to date"
    exit 0
fi

# Show what will be updated
echo "📋 Changes to be applied:"
git log --oneline HEAD..origin/master

# Confirm update
read -p "🔄 Do you want to apply these updates? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "❌ Update cancelled"
    exit 0
fi

# Stop the service
if [ "$SERVICE_WAS_RUNNING" = true ]; then
    echo "⏹️  Stopping XeoKey service..."
    systemctl stop xeokey || {
        echo "❌ Failed to stop XeoKey service"
        exit 1
    }
fi

# Pull latest changes
echo "⬇️  Pulling latest changes..."
git pull origin master || {
    echo "❌ Failed to pull latest changes"
    if [ "$SERVICE_WAS_RUNNING" = true ]; then
        echo "🔄 Restarting service..."
        systemctl start xeokey
    fi
    exit 1
fi

# Install dependencies
echo "📦 Installing dependencies..."
cd src
bun install || {
    echo "❌ Failed to install dependencies"
    if [ "$SERVICE_WAS_RUNNING" = true ]; then
        echo "🔄 Restarting service..."
        systemctl start xeokey
    fi
    exit 1
fi

# Run typecheck to ensure everything is working
echo "🔍 Running type check..."
bun run typecheck || {
    echo "❌ Type check failed"
    if [ "$SERVICE_WAS_RUNNING" = true ]; then
        echo "🔄 Restarting service..."
        systemctl start xeokey
    fi
    exit 1
fi

# Start the service if it was running before
if [ "$SERVICE_WAS_RUNNING" = true ]; then
    echo "▶️  Starting XeoKey service..."
    systemctl start xeokey || {
        echo "❌ Failed to start XeoKey service"
        exit 1
    }

    # Wait a moment for service to start
    sleep 3

    # Check if service started successfully
    if systemctl is-active --quiet xeokey; then
        echo "✅ XeoKey service started successfully"
    else
        echo "❌ XeoKey service failed to start"
        echo "📋 Service status:"
        systemctl status xeokey --no-pager
        echo "📋 Recent logs:"
        journalctl -u xeokey --since "1 minute ago" --no-pager
        exit 1
    fi
fi

# Show new version
echo "📝 Updated to version:"
cd /home/xeo/XeoKey
git log --oneline -1

echo "✅ XeoKey update completed successfully!"

# Show final status
if [ "$SERVICE_WAS_RUNNING" = true ]; then
    echo "📊 Final service status:"
    systemctl status xeokey --no-pager -l
fi
