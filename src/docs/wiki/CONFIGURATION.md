# Configuration Guide

This guide covers all configuration options available in XeoKey.

**Navigation**: [Home](Home) | [Installation](Installation) | [Deployment](Deployment) | [Security](Security)

## Environment Variables

XeoKey uses environment variables for configuration. You can set these in a `.env` file in the project root, or as system environment variables.

### Server Configuration

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `PORT` | Server port number | `3000` | No |
| `NODE_ENV` | Environment mode (`production` or `development`) | `development` | No |

### Database Configuration

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `MONGODB_URI` | MongoDB connection string | `mongodb://localhost:27017` | No* |
| `MONGO_URI` | Alternative MongoDB URI variable | Same as above | No |

\* MongoDB is optional - the server will run without it, but password storage won't work.

**Example MongoDB URIs:**
- Local: `mongodb://localhost:27017`
- With authentication: `mongodb://username:password@localhost:27017`
- Remote: `mongodb://user:pass@host:27017/dbname`
- MongoDB Atlas: `mongodb+srv://username:password@cluster.mongodb.net/dbname`

**⚠️ CRITICAL WARNING: Database Backups**

**Your passwords are stored in MongoDB. Without regular backups, you risk losing all your passwords permanently.**

**You MUST set up regular MongoDB backups to protect your data.** See the [Deployment Guide](./DEPLOYMENT.md#backup-strategy) for backup instructions.

**Without backups, you will lose all your passwords if your database is lost. This is irreversible.**

### Security Configuration

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `SESSION_SECRET` | Secret key for session signing | `change-this-secret-key-in-production` | Yes (production) |
| `ENCRYPTION_KEY` | Key for password encryption | `default-encryption-key-change-in-production` | Yes (production) |

**Security Requirements:**
- `SESSION_SECRET`: Must be at least 32 characters long. Used for session cookie signing.
- `ENCRYPTION_KEY`: Used to encrypt passwords. Must be set in production.
- Generate strong random keys for production use.

**Generating Secure Keys:**

```bash
# Using OpenSSL
openssl rand -base64 32  # For SESSION_SECRET
openssl rand -base64 32  # For ENCRYPTION_KEY

# Using Node.js/Bun
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
```

### Logging Configuration

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `DEBUG` | Enable debug logging (`true` or `1`) | `false` | No |
| `LOG_LEVEL` | Log level (`debug`, `info`, `warn`, `error`) | `info` | No |

For detailed logging information, see [Debug Logging](../DEBUG_LOGGING.md).

## Example .env File

```env
# Server Configuration
PORT=3000
NODE_ENV=production

# Database Configuration
MONGODB_URI=mongodb://localhost:27017

# Security (REQUIRED for production)
SESSION_SECRET=your-super-secret-session-key-at-least-32-characters-long
ENCRYPTION_KEY=your-super-secret-encryption-key-for-password-storage

# Logging Configuration
DEBUG=false
LOG_LEVEL=info
```

## Environment-Specific Configuration

### Development

```env
NODE_ENV=development
PORT=3000
MONGODB_URI=mongodb://localhost:27017
DEBUG=true
LOG_LEVEL=debug
```

### Production

```env
NODE_ENV=production
PORT=3000
MONGODB_URI=mongodb://your-production-db:27017
SESSION_SECRET=<strong-random-32-char-key>
ENCRYPTION_KEY=<strong-random-key>
DEBUG=false
LOG_LEVEL=info
```

## Configuration Validation

The server will:
- Warn if `SESSION_SECRET` is not set in production
- Warn if `ENCRYPTION_KEY` is not set in production
- Continue running without MongoDB (but password features won't work)
- Use default values for optional variables

## Security Best Practices

1. **Never commit `.env` files** to version control
2. **Use different keys** for development and production
3. **Rotate keys** periodically in production
4. **Use strong random keys** (at least 32 characters)
5. **Restrict database access** to trusted networks
6. **Use MongoDB authentication** in production

For more security information, see the [Security Guide](Security).

---

**Navigation**: [Home](Home) | [Installation](Installation) | [Deployment](Deployment) | [Security](Security)

