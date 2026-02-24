# BAD_DECRYPT Error Recovery Guide

## Understanding BAD_DECRYPT Errors

The error `error:1e000065:Cipher functions:OPENSSL_internal:BAD_DECRYPT` indicates that XeoKey cannot decrypt password entries because the encryption key used during decryption doesn't match the key used during encryption.

### Common Causes

1. **ENCRYPTION_KEY was changed** after passwords were encrypted
2. **Environment variables are different** between encryption and decryption
3. **Default encryption key** being used in production
4. **Data corruption** in encrypted password format
5. **SystemD service** using different environment than expected

## Immediate Diagnosis

### 1. Check Current Encryption Key
```bash
# Check current key (without exposing it)
curl http://localhost:3000/api/encryption/key-info

# Or check environment variable
echo $ENCRYPTION_KEY
```

### 2. Run Encryption Diagnostics
```bash
# Run comprehensive diagnostics
curl http://localhost:3000/api/encryption/diagnostics

# This will show:
# - Current key hash
# - Success rate of decryption
# - Sample errors
# - Specific recommendations
```

### 3. Check SystemD Service Environment
```bash
# Check service environment
sudo systemctl show xeokey --property=Environment
sudo systemctl cat xeokey | grep Environment
```

## Recovery Strategies

### Strategy 1: Restore Original ENCRYPTION_KEY (Recommended)

If you know the original ENCRYPTION_KEY:

1. **Stop XeoKey service:**
   ```bash
   sudo systemctl stop xeokey
   ```

2. **Set the original key:**
   ```bash
   # Edit environment file
   sudo nano /home/xeo/XeoKey/.env
   
   # Set ENCRYPTION_KEY to the original value
   ENCRYPTION_KEY=your-original-encryption-key-here
   ```

3. **Restart service:**
   ```bash
   sudo systemctl start xeokey
   ```

4. **Verify recovery:**
   ```bash
   curl http://localhost:3000/api/encryption/diagnostics
   ```

### Strategy 2: Password Recovery Feature

If you don't know the original key but remember the master password:

1. **Access password recovery:**
   - Navigate to `/recovery` in XeoKey web interface
   - Enter the master password used when passwords were created
   - The recovery feature uses the master password as the encryption key

2. **Export and re-import:**
   - Recover all passwords using the original master password
   - Export them to a secure format
   - Re-import with the current ENCRYPTION_KEY

### Strategy 3: Database Backup Restore

If you have database backups from when encryption worked:

1. **Find the right backup:**
   ```bash
   ls -la /home/xeo/XeoKey/src/backups/
   ```

2. **Restore from backup:**
   ```bash
   # Stop service
   sudo systemctl stop xeokey
   
   # Restore database
   mongorestore --db XeoKey --drop /path/to/backup
   
   # Start service
   sudo systemctl start xeokey
   ```

### Strategy 4: Manual Data Recreation (Last Resort)

If all else fails, you'll need to recreate the encrypted data:

1. **Identify affected entries** using diagnostics
2. **Manually recreate** each password entry
3. **Update all passwords** to use current encryption key

## Prevention

### 1. Backup Your ENCRYPTION_KEY
```bash
# Create a secure backup
echo "ENCRYPTION_KEY=$(echo $ENCRYPTION_KEY)" > ~/xeokey-key-backup.txt
chmod 600 ~/xeokey-key-backup.txt

# Or store in secure password manager
```

### 2. Environment Management
```bash
# Create production environment file
sudo nano /home/xeo/XeoKey/.env.production

# Add secure key
ENCRYPTION_KEY=your-secure-generated-key-here
NODE_ENV=production

# Set proper permissions
sudo chmod 640 /home/xeo/XeoKey/.env.production
sudo chown root:xeokey /home/xeo/XeoKey/.env.production
```

### 3. SystemD Service Configuration
```ini
# In /etc/systemd/system/xeokey.service
[Service]
Environment=NODE_ENV=production
Environment=SYSTEMD_SERVICE=true
EnvironmentFile=/home/xeo/XeoKey/.env.production
```

### 4. Regular Diagnostics
```bash
# Create a cron job for regular checks
echo "0 */6 * * * curl -s http://localhost:3000/api/encryption/diagnostics | jq .diagnostic.recommendations" | sudo crontab -
```

## Advanced Troubleshooting

### Check Key History
```bash
# Check if key changed recently
sudo journalctl -u xeokey --since "1 week ago" | grep -i encryption

# Check environment changes
sudo git log -p --follow src/.env | grep -A5 -B5 ENCRYPTION_KEY
```

### Verify Database Integrity
```bash
# Check MongoDB directly
mongo XeoKey --eval "
  db.passwords.find({}).limit(5).forEach(function(doc) {
    print('Entry ' + doc._id + ' password length: ' + doc.password.length);
  });
"
```

### Test Encryption Manually
```bash
# Create test encryption
node -e "
const crypto = require('crypto');
const key = crypto.createHash('sha256').update(process.env.ENCRYPTION_KEY || 'default').digest();
const iv = crypto.randomBytes(16);
const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
let encrypted = cipher.update('test', 'utf8', 'hex');
encrypted += cipher.final('hex');
console.log('Test encrypted:', iv.toString('hex') + ':' + encrypted);
"
```

## Emergency Procedures

### Complete Key Loss
If you've completely lost the ENCRYPTION_KEY:

1. **Accept data loss** - encrypted passwords cannot be recovered
2. **Clear encrypted data:**
   ```bash
   mongo XeoKey --eval "
     db.passwords.updateMany({}, {\$set: {password: ''}});
     db.notes.updateMany({}, {\$set: {content: ''}});
   "
   ```
3. **Start fresh** with a new ENCRYPTION_KEY
4. **Notify users** to reset their passwords

### Migration to New Key
If you need to change ENCRYPTION_KEY:

1. **Export all data** using current key
2. **Set new ENCRYPTION_KEY**
3. **Re-import all data** with new key
4. **Verify everything works**
5. **Backup new key securely**

## Support

### Log Analysis
```bash
# Check for BAD_DECRYPT errors
sudo journalctl -u xeokey | grep "BAD_DECRYPT\|decryption failed"

# Check encryption-related logs
sudo journalctl -u xeokey | grep -i "encryption\|decrypt\|key"
```

### Get Help
- Check diagnostics: `curl http://localhost:3000/api/encryption/diagnostics`
- Review logs: `sudo journalctl -u xeokey -f`
- Check environment: `sudo systemctl show xeokey`

## Quick Reference

| Symptom | Cause | Solution |
|---------|-------|----------|
| BAD_DECRYPT errors | Wrong ENCRYPTION_KEY | Restore original key |
| Some passwords work | Key changed recently | Use password recovery |
| No passwords work | Default key in production | Set proper ENCRYPTION_KEY |
| SystemD issues | Environment mismatch | Check service environment |

## Recovery Checklist

- [ ] Run encryption diagnostics
- [ ] Identify current vs original key
- [ ] Stop XeoKey service
- [ ] Restore original ENCRYPTION_KEY
- [ ] Restart service
- [ ] Verify decryption works
- [ ] Backup current key
- [ ] Update documentation
- [ ] Monitor for future issues

Remember: **The ENCRYPTION_KEY is critical. Lose it, lose all encrypted data.**
