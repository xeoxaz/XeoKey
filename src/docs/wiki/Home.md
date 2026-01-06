# XeoKey Wiki

Welcome to the XeoKey documentation wiki! This wiki contains comprehensive guides and documentation for installing, configuring, deploying, and using XeoKey.

## 📚 Documentation Pages

### Getting Started
- **[Installation Guide](Installation)** - Step-by-step installation instructions
- **[Configuration Guide](Configuration)** - Environment variables and configuration options
- **[First-Time Setup](Installation#first-time-setup)** - Setting up your first account

### Deployment & Operations
- **[Deployment Guide](Deployment)** - Production deployment instructions
- **[Backup Strategy](Deployment#critical-backup-strategy)** - MongoDB backup procedures
- **[Troubleshooting Guide](Troubleshooting)** - Common issues and solutions

### Development & API
- **[API Documentation](API)** - Complete API endpoint reference
- **[Security Guide](Security)** - Security features and best practices

## 🚀 Quick Start

1. **Install XeoKey** - Follow the [Installation Guide](Installation)
2. **Configure Environment** - See the [Configuration Guide](Configuration)
3. **Deploy to Production** - Read the [Deployment Guide](Deployment)
4. **Set Up Backups** - **CRITICAL**: Configure backups immediately (see [Deployment Guide](Deployment#critical-backup-strategy))

## ⚠️ Important Notes

### Database Backups
**Your passwords are stored in MongoDB. Without regular backups, you risk losing all your passwords permanently if your database is lost.**

- Set up regular MongoDB backups immediately after installation
- See the [Deployment Guide](Deployment#critical-backup-strategy) for detailed backup instructions
- Test restore procedures regularly
- Store backups in multiple locations (local + remote)

### Security
- Always use strong, unique keys for `SESSION_SECRET` and `ENCRYPTION_KEY`
- Enable HTTPS in production
- Use MongoDB authentication
- See the [Security Guide](Security) for complete security best practices

## 📖 Project Information

- **Repository**: [github.com/xeoxaz/XeoKey](https://github.com/xeoxaz/XeoKey)
- **Issues**: [Report a bug or request a feature](https://github.com/xeoxaz/XeoKey/issues)
- **License**: ISC

## 🔗 External Resources

- [Bun Documentation](https://bun.sh/docs)
- [MongoDB Documentation](https://docs.mongodb.com)
- [OWASP Security Guidelines](https://owasp.org)

---

**Need help?** Check the [Troubleshooting Guide](Troubleshooting) or [open an issue](https://github.com/xeoxaz/XeoKey/issues).

