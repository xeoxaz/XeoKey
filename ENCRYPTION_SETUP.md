# XeoKey Encryption Setup Guide

## Critical Issue: ENCRYPTION_KEY Environment Variable

### The Problem
If you're seeing this error:
```
Decryption failed for entry [ID]: ENCRYPTION_KEY environment variable must be set in production
```

This means your XeoKey server is running in production mode but using the default encryption key, which is not allowed for security reasons.

### Quick Fix (Development/Testing)

1. **Edit your `.env` file** (located in `src/.env`):
   ```bash
   # Change this line:
   ENCRYPTION_KEY=default-encryption-key-change-in-production
   
   # To something like this:
   ENCRYPTION_KEY=XeoKey-Dev-Key-2024-Change-In-Production-Use-Strong-Key
   ```

2. **Restart your server**:
   ```bash
   # If using direct start:
   ./Start.bat
   
   # Or if using process manager:
   ./Start-Host.bat
   ```

### Production Setup (Required for Live Deployment)

1. **Generate a secure encryption key**:
   ```bash
   # Using OpenSSL (recommended):
   openssl rand -base64 32
   
   # Or use any secure random string generator
   # Must be at least 32 characters long
   ```

2. **Set up production environment variables**:
   ```bash
   # Option 1: Environment variables
   export NODE_ENV=production
   export ENCRYPTION_KEY="your-generated-secure-key-here"
   export SESSION_SECRET="your-secure-session-secret-32-chars-minimum"
   
   # Option 2: Production .env file
   cp .env.example .env.production
   # Edit .env.production with your secure keys
   ```

3. **Update your production .env file**:
   ```env
   NODE_ENV=production
   PORT=3000
   MONGODB_URI=mongodb://your-production-mongodb-url
   SESSION_SECRET=your-secure-session-secret-32-chars-minimum
   ENCRYPTION_KEY=your-generated-secure-key-here
   ```

### Important Notes

⚠️ **CRITICAL**: Once you set an ENCRYPTION_KEY and create passwords, **you cannot change it** without losing access to existing encrypted data. The encryption key is used to encrypt/decrypt all passwords and notes.

🔐 **Security**: Never commit your actual ENCRYPTION_KEY to version control. Always use environment variables or secure configuration management in production.

💾 **Backup**: Before changing encryption keys, always backup your database. If you lose the encryption key, you lose access to all encrypted data.

### Troubleshooting

**Error: "ENCRYPTION_KEY environment variable must be set in production"**
- Solution: Set a non-default ENCRYPTION_KEY in your environment or .env file

**Error: "Decryption failed for entry [ID]"**
- This usually means the ENCRYPTION_KEY used during encryption is different from the current key
- Solution: Use the original ENCRYPTION_KEY that was used when the passwords were created

**Lost ENCRYPTION_KEY?**
- Unfortunately, encrypted data cannot be recovered without the original key
- This is by design for security
- You'll need to delete the encrypted entries and recreate them

### Migration Guide

If you need to change encryption keys:

1. Export all passwords using the old key
2. Set new ENCRYPTION_KEY
3. Import passwords with new encryption
4. Verify all data is accessible

### Security Best Practices

- Use a cryptographically secure random key (32+ characters)
- Store keys in secure environment variable management
- Rotate keys only when absolutely necessary
- Always backup before key changes
- Never log or expose encryption keys

For additional help, check the main README.md or create an issue on GitHub.
