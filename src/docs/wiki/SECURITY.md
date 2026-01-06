# Security Guide

Comprehensive security documentation for XeoKey.

**Navigation**: [Home](Home) | [Installation](Installation) | [Configuration](Configuration) | [Deployment](Deployment)

## Security Features

XeoKey implements multiple layers of security to protect your passwords and data:

### ✅ Password Encryption
- **AES-256-CBC encryption** for all stored passwords
- Encryption keys stored separately from encrypted data
- Passwords are encrypted before being stored in the database
- Decryption only occurs when passwords are retrieved for authenticated users

### ✅ Session Management
- Secure session cookies with expiration
- Session IDs are randomly generated
- Sessions expire after a period of inactivity
- Session data is stored securely

### ✅ CSRF Protection
- All forms protected with CSRF tokens
- Tokens are unique per session
- Tokens expire after use or after a time period
- Invalid tokens result in request rejection

### ✅ Rate Limiting
- Protection against brute force attacks
- 5 attempts per 15 minutes for login/registration
- Per-IP address tracking
- Automatic reset after time window

### ✅ Input Sanitization
- All user inputs sanitized and validated
- XSS (Cross-Site Scripting) prevention
- SQL injection prevention (MongoDB uses parameterized queries)
- Website names, usernames, emails, and notes are sanitized

### ✅ Security Headers
Comprehensive security headers on all responses:
- `Content-Security-Policy` - Prevents XSS attacks
- `X-Frame-Options: DENY` - Prevents clickjacking
- `X-Content-Type-Options: nosniff` - Prevents MIME sniffing
- `Strict-Transport-Security` - Enforces HTTPS (when configured)
- `X-XSS-Protection: 1; mode=block` - Additional XSS protection

### ✅ Password Strength Analysis
- Automatic detection of weak passwords
- Identifies passwords that are too short
- Warns about common patterns
- Helps users create stronger passwords

### ✅ Duplicate Detection
- Identifies reused passwords across accounts
- Warns users about password reuse
- Helps maintain unique passwords per account

### ✅ TOTP/HOTP Support
- Two-factor authentication code generation
- Support for TOTP (Time-based) and HOTP (Counter-based) codes
- Encrypted storage of TOTP secrets
- Automatic code refresh for TOTP entries
- Backup code generation for account recovery

### ✅ Error Logging Sanitization
- Sensitive data filtered from logs
- Passwords never logged
- Session tokens never logged
- User credentials never logged

## Security Best Practices

### For Administrators

1. **Use Strong Keys**
   - Generate random keys for `SESSION_SECRET` and `ENCRYPTION_KEY`
   - Use at least 32 characters for `SESSION_SECRET`
   - Never reuse keys across environments
   - Rotate keys periodically

2. **Enable HTTPS**
   - Use HTTPS in production
   - Set up reverse proxy (nginx, Caddy, etc.)
   - Configure SSL/TLS certificates
   - Secure cookies only work over HTTPS

3. **Database Security**
   - Use MongoDB authentication
   - Restrict network access to database
   - Enable MongoDB encryption at rest
   - Use strong database passwords
   - Limit database user permissions

4. **Environment Variables**
   - Never commit `.env` files
   - Use different keys for dev/prod
   - Store keys securely (use secrets management)
   - Restrict access to `.env` files

5. **Network Security**
   - Use firewall rules
   - Restrict database access to application server
   - Use VPN for remote access
   - Monitor network traffic

6. **Monitoring**
   - Check logs regularly (`./logs/server.log`)
   - Monitor for security events
   - Set up log rotation
   - Alert on suspicious activity

7. **Backups (CRITICAL)**
   - **⚠️ Set up regular MongoDB backups immediately** - Without backups, you will lose all your passwords if the database is lost
   - Regular MongoDB backups (daily recommended)
   - Backup encryption keys securely (separate from database backups)
   - Test restore procedures regularly
   - Store backups securely in multiple locations (local + remote)
   - **Without backups, data loss is permanent and irreversible**

### For Users

1. **Strong Passwords**
   - Use unique passwords for each account
   - Use long, complex passwords
   - Avoid common patterns
   - Use password generator

2. **Account Security**
   - Use strong master password
   - Don't share your account
   - Log out when done
   - Report suspicious activity

3. **Browser Security**
   - Keep browser updated
   - Use secure browser settings
   - Clear cookies if compromised
   - Use private browsing when needed

## Security Configuration

### Required Environment Variables

```env
# Production - REQUIRED
SESSION_SECRET=<strong-random-32-char-key>
ENCRYPTION_KEY=<strong-random-key>
```

### Generating Secure Keys

```bash
# Using OpenSSL
openssl rand -base64 32  # For SESSION_SECRET
openssl rand -base64 32  # For ENCRYPTION_KEY

# Using Node.js/Bun
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
```

## Security Headers Configuration

Security headers are automatically applied to all responses. In production with HTTPS, additional headers like `Strict-Transport-Security` are enabled.

## Rate Limiting Configuration

Rate limits are configured per endpoint:
- Login: 5 attempts per 15 minutes
- Registration: 5 attempts per 15 minutes

These limits can be adjusted in `security/rateLimit.ts`.

## CSRF Token Configuration

CSRF tokens are:
- Generated per session
- Valid for a limited time
- Single-use (optional, can be configured)
- Validated on all POST requests

## Encryption Details

- **Algorithm**: AES-256-CBC
- **Key Derivation**: Uses `ENCRYPTION_KEY` environment variable
- **IV Generation**: Random IV for each encryption
- **Storage**: Encrypted passwords stored in MongoDB

## Security Audit Checklist

- [ ] Strong `SESSION_SECRET` set (32+ characters)
- [ ] Strong `ENCRYPTION_KEY` set
- [ ] HTTPS enabled in production
- [ ] MongoDB authentication enabled
- [ ] Database access restricted
- [ ] Firewall rules configured
- [ ] Log monitoring set up
- [ ] Backups configured
- [ ] Keys stored securely
- [ ] `.env` file not in version control
- [ ] Different keys for dev/prod
- [ ] Regular security updates

## Reporting Security Issues

If you discover a security vulnerability:

1. **Do not** open a public issue
2. Contact the maintainers privately
3. Provide detailed information
4. Allow time for fix before disclosure

## Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [MongoDB Security Checklist](https://docs.mongodb.com/manual/administration/security-checklist/)
- [Bun Security](https://bun.sh/docs/security)

For deployment security, see the [Deployment Guide](Deployment).

---

**Navigation**: [Home](Home) | [Installation](Installation) | [Configuration](Configuration) | [Deployment](Deployment)

