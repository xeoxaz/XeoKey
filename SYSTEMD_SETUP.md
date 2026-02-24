# XeoKey SystemD Service Setup Guide

## Quick Setup

1. **Copy the service file**:
   ```bash
   sudo cp xeokey.service /etc/systemd/system/
   ```

2. **Create production environment file**:
   ```bash
   cp .env.example .env.production
   nano .env.production
   ```

3. **Update service file paths** (if needed):
   ```bash
   sudo nano /etc/systemd/system/xeokey.service
   # Update User, Group, WorkingDirectory, and EnvironmentFile paths
   ```

4. **Enable and start the service**:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable xeokey
   sudo systemctl start xeokey
   ```

## Service Configuration

### User and Permissions
```bash
# Create xeokey user (if not exists)
sudo useradd -r -s /bin/false xeokey
sudo usermod -d /home/xeo/XeoKey xeokey

# Set ownership
sudo chown -R xeokey:xeokey /home/xeo/XeoKey
chmod 750 /home/xeo/XeoKey
```

### Environment Variables
Create `/home/xeo/XeoKey/.env`:
```env
NODE_ENV=production
PORT=3000
MONGODB_URI=mongodb://localhost:27017
SESSION_SECRET=your-secure-session-secret-32-chars-minimum
ENCRYPTION_KEY=your-secure-encryption-key-generate-with-openssl
LOG_LEVEL=info
DEBUG=false
```

## Update Feature Compatibility

The update feature needs special handling for systemd:

### Method 1: Automatic Updates (Recommended)
```bash
# Create update script
sudo nano /usr/local/bin/xeokey-update
```

```bash
#!/bin/bash
# XeoKey SystemD Update Script

echo "🔄 Updating XeoKey..."

# Stop service
sudo systemctl stop xeokey

# Navigate to project directory
cd /home/xeo/XeoKey

# Pull latest changes
git pull origin master

# Install dependencies
cd src
bun install

# Restart service
sudo systemctl start xeokey

echo "✅ XeoKey updated and restarted"
```

```bash
sudo chmod +x /usr/local/bin/xeokey-update
```

### Method 2: Manual Updates
```bash
# Update commands
sudo systemctl stop xeokey
cd /home/xeo/XeoKey
git pull origin master
cd src && bun install
sudo systemctl start xeokey
```

## Service Management

### Check Status
```bash
sudo systemctl status xeokey
```

### View Logs
```bash
# Live logs
sudo journalctl -u xeokey -f

# Recent logs
sudo journalctl -u xeokey --since "1 hour ago"

# All logs
sudo journalctl -u xeokey
```

### Service Control
```bash
sudo systemctl start xeokey
sudo systemctl stop xeokey
sudo systemctl restart xeokey
sudo systemctl reload xeokey
```

### Enable/Disable
```bash
sudo systemctl enable xeokey    # Start on boot
sudo systemctl disable xeokey   # Don't start on boot
```

## Troubleshooting

### Service Won't Start
```bash
# Check status for errors
sudo systemctl status xeokey

# Check detailed logs
sudo journalctl -u xeokey -n 50

# Check configuration
sudo systemd-analyze verify xeokey.service
```

### Permission Issues
```bash
# Fix ownership
sudo chown -R xeokey:xeokey /home/xeo/XeoKey

# Fix permissions
sudo chmod 750 /home/xeo/XeoKey
sudo chmod 640 /home/xeo/XeoKey/.env
```

### Update Feature Issues
The web-based update feature has limitations with systemd. Use the update script instead:
```bash
sudo /usr/local/bin/xeokey-update
```

## Security Considerations

1. **Environment File Security**:
   ```bash
   sudo chmod 640 /home/xeo/XeoKey/.env
   sudo chown root:xeokey /home/xeo/XeoKey/.env
   ```

2. **Service Isolation**: The service file includes security restrictions:
   - `NoNewPrivileges=true`: Prevents privilege escalation
   - `ProtectSystem=strict`: Read-only system access
   - `PrivateTmp=true`: Isolated temporary directory

3. **Resource Limits**: Configured limits prevent resource exhaustion

## Integration with Web Interface

To make the web update feature work with systemd, modify the process manager:

```javascript
// In utils/process-manager.ts, add systemd detection
function isSystemdService(): boolean {
  return process.env.SYSTEMD_SERVICE === 'true' || 
         process.env.INVOCATION_ID !== undefined;
}

// Update triggerRestart to handle systemd
export async function triggerRestart(): Promise<void> {
  if (isSystemdService()) {
    logger.info('Running under systemd, requesting service restart...');
    // Signal systemd to restart the service
    process.kill(process.pid, 'SIGHUP');
    return;
  }
  // ... existing restart logic
}
```

## Monitoring

### Health Check Script
```bash
#!/bin/bash
# /usr/local/bin/xeokey-health

if curl -f http://localhost:3000/api/server/status > /dev/null 2>&1; then
    echo "✅ XeoKey is healthy"
    exit 0
else
    echo "❌ XeoKey is not responding"
    sudo systemctl restart xeokey
    exit 1
fi
```

### SystemD Timer for Health Checks
```ini
# /etc/systemd/system/xeokey-health.timer
[Unit]
Description=Check XeoKey health every 5 minutes

[Timer]
OnCalendar=*:*/5
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
sudo systemctl enable xeokey-health.timer
sudo systemctl start xeokey-health.timer
```
