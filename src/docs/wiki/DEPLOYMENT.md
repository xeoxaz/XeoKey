# Deployment Guide

Complete guide for deploying XeoKey to production.

**Navigation**: [Home](Home) | [Installation](Installation) | [Configuration](Configuration) | [Security](Security)

## Pre-Deployment Checklist

- [ ] All environment variables configured
- [ ] Strong `SESSION_SECRET` generated (32+ characters)
- [ ] Strong `ENCRYPTION_KEY` generated
- [ ] MongoDB configured and accessible
- [ ] HTTPS certificate obtained
- [ ] Reverse proxy configured (if using)
- [ ] Firewall rules configured
- [ ] Backup strategy in place
- [ ] Monitoring set up
- [ ] Log rotation configured

## Environment Setup

### 1. Set All Environment Variables

Create a `.env` file or set system environment variables:

```env
NODE_ENV=production
PORT=3000
SESSION_SECRET=<strong-random-32-char-key>
ENCRYPTION_KEY=<strong-random-key>
MONGODB_URI=<your-mongodb-connection-string>
```

**Important**: Generate strong random keys for production. See [Configuration Guide](Configuration) for key generation.

### 2. Use HTTPS

HTTPS is required for secure cookies and encrypted communication.

#### Option A: Reverse Proxy (Recommended)

Use nginx, Caddy, or another reverse proxy:

**nginx example:**
```nginx
server {
    listen 443 ssl http2;
    server_name your-domain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

**Caddy example:**
```
your-domain.com {
    reverse_proxy localhost:3000
}
```

#### Option B: Direct HTTPS

Configure Bun to use HTTPS directly (requires SSL certificates).

### 3. Database Security

#### MongoDB Authentication

Enable authentication in MongoDB:

```javascript
use admin
db.createUser({
  user: "xeokey",
  pwd: "strong-password",
  roles: [ { role: "readWrite", db: "XeoKey" } ]
})
```

Update `MONGODB_URI`:
```
MONGODB_URI=mongodb://xeokey:strong-password@localhost:27017/XeoKey
```

#### Network Restrictions

- Restrict MongoDB to localhost or private network
- Use firewall rules to limit access
- Use VPN for remote database access

#### Encryption at Rest

Enable MongoDB encryption at rest for sensitive data.

## Deployment Methods

### Method 1: Direct Deployment

1. **Install dependencies:**
   ```bash
   bun install
   ```

2. **Set environment variables**

3. **Start the server:**
   ```bash
   bun run start
   ```

4. **Use process manager** (recommended):
   ```bash
   # Using built-in process manager (recommended)
   bun run host

   # Or using systemd (Linux)
   # Create /etc/systemd/system/xeokey.service
   ```

### Method 2: Docker Deployment

Create a `Dockerfile`:

```dockerfile
FROM oven/bun:latest

WORKDIR /app

COPY package.json bun.lock ./
RUN bun install

COPY . .

EXPOSE 3000

CMD ["bun", "run", "start"]
```

Build and run:
```bash
docker build -t xeokey .
docker run -d -p 3000:3000 --env-file .env xeokey
```

### Method 3: Cloud Platform

#### Vercel / Netlify
Not recommended for this application (requires persistent server).

#### Railway / Render
1. Connect your repository
2. Set environment variables
3. Configure build command: `bun install`
4. Configure start command: `bun run start`

#### DigitalOcean / AWS / GCP
1. Create a VM instance
2. Install Bun
3. Clone repository
4. Set environment variables
5. Use process manager (built-in manager or systemd)
6. Configure reverse proxy

## Process Management

### Using Built-in Process Manager (Recommended)

XeoKey includes a built-in process manager that handles automatic restarts, health monitoring, and crash recovery. This is the recommended method for production deployment.

```bash
# Start with process manager (from project root)
bun run host

# Or from src/ directory
cd src
bun run host
```

**Features:**
- ✅ Automatic restart on crashes
- ✅ Health check monitoring (every 30 seconds)
- ✅ Startup verification
- ✅ Crash recovery with exponential backoff
- ✅ Git pull integration for updates
- ✅ No external dependencies required

**Windows:**
```bash
# Use the batch file
Start-Host.bat
```

See [HOST_README.md](../../HOST_README.md) for detailed documentation.

### Using systemd (Linux)

Create `/etc/systemd/system/xeokey.service`:

```ini
[Unit]
Description=XeoKey Password Manager
After=network.target

[Service]
Type=simple
User=your-user
WorkingDirectory=/path/to/XeoKey
Environment="NODE_ENV=production"
EnvironmentFile=/path/to/.env
ExecStart=/usr/local/bin/bun run start
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable xeokey
sudo systemctl start xeokey
```

## Monitoring

### Log Monitoring

1. **Check logs regularly:**
   ```bash
   tail -f logs/server.log
   ```

2. **Set up log rotation:**
   ```bash
   # Using logrotate
   /path/to/XeoKey/logs/*.log {
       daily
       rotate 7
       compress
       missingok
       notifempty
   }
   ```

3. **Monitor for errors:**
   ```bash
   grep -i error logs/server.log
   ```

### Health Checks

Monitor the `/api/status` endpoint:
```bash
curl http://localhost:3000/api/status
```

### Uptime Monitoring

Use services like:
- UptimeRobot
- Pingdom
- StatusCake

## ⚠️ CRITICAL: Backup Strategy

**Your passwords are stored in MongoDB. Without regular backups, you risk losing all your passwords permanently if:**
- Your database server crashes or fails
- Your hard drive fails
- Your system is compromised or corrupted
- You accidentally delete the database
- Your MongoDB instance is corrupted

**Set up regular MongoDB backups immediately. Without backups, you will lose all your passwords if your database is lost. This is irreversible.**

### MongoDB Backups

1. **Regular backups (REQUIRED):**
   ```bash
   mongodump --uri="mongodb://localhost:27017" --out=/backup/path
   ```
   - **Recommended frequency:** Daily backups minimum
   - **Store backups in multiple locations:** Local + remote (cloud storage)
   - **Test restore procedures regularly** to ensure backups work

2. **Automated backups (HIGHLY RECOMMENDED):**
   ```bash
   # Add to crontab (runs daily at 2 AM)
   0 2 * * * mongodump --uri="mongodb://localhost:27017" --out=/backup/path/$(date +\%Y-\%m-\%d)
   ```
   - Automate backups to prevent human error
   - Keep multiple backup copies (last 7-30 days)
   - Rotate old backups to save space

3. **Backup encryption keys:**
   - Store `SESSION_SECRET` and `ENCRYPTION_KEY` securely
   - Use secrets management (HashiCorp Vault, AWS Secrets Manager)
   - **Never store keys in the same location as database backups**
   - Without encryption keys, you cannot decrypt your passwords even with a database backup

4. **Test restore procedures (REQUIRED):**
   ```bash
   mongorestore --uri="mongodb://localhost:27017" /backup/path
   ```
   - **Test backups monthly** to ensure they work
   - A backup that can't be restored is useless
   - Document your restore procedure

5. **Backup Storage Best Practices:**
   - Store backups in at least 2 different locations
   - Use cloud storage (AWS S3, Google Cloud Storage, etc.) for off-site backups
   - Encrypt backups if storing in cloud storage
   - Verify backup integrity regularly

## Performance Optimization

1. **Enable gzip compression** (in reverse proxy)
2. **Use CDN** for static assets (if applicable)
3. **Optimize MongoDB indexes**
4. **Monitor database performance**
5. **Use connection pooling**

## Security Hardening

1. **Firewall rules:**
   - Only allow necessary ports (80, 443)
   - Restrict MongoDB port (27017) to localhost

2. **Keep dependencies updated:**
   ```bash
   bun update
   ```

3. **Regular security audits:**
   - Review logs for suspicious activity
   - Monitor failed login attempts
   - Check for unusual patterns

4. **SSL/TLS configuration:**
   - Use strong cipher suites
   - Enable HSTS
   - Use TLS 1.2 or higher

## Troubleshooting

See the [Troubleshooting Guide](./TROUBLESHOOTING.md) for common deployment issues.

## Post-Deployment

1. **Verify functionality:**
   - Test login/registration
   - Test password creation
   - Test password retrieval
   - Check analytics dashboard

2. **Monitor logs:**
   - Check for errors
   - Verify database connections
   - Monitor performance

3. **Set up alerts:**
   - Server downtime
   - Database connection failures
   - High error rates

## Maintenance

### Regular Tasks

- [ ] Review logs weekly
- [ ] Check for updates monthly
- [ ] Test backups monthly
- [ ] Review security settings quarterly
- [ ] Rotate keys annually (or as needed)

### Updates

1. **Pull latest changes:**
   ```bash
   git pull
   ```

2. **Update dependencies:**
   ```bash
   bun install
   ```

3. **Restart server:**
   ```bash
   pm2 restart xeokey
   # or
   sudo systemctl restart xeokey
   ```

## Additional Resources

- [Configuration Guide](Configuration)
- [Security Guide](Security)
- [Troubleshooting Guide](Troubleshooting)

---

**Navigation**: [Home](Home) | [Installation](Installation) | [Configuration](Configuration) | [Security](Security)

