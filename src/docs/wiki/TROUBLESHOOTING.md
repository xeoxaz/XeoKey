# Troubleshooting Guide

Common issues and solutions for XeoKey.

> **🐛 Found a bug, error, or graphical problem?** [Report it on GitHub Issues](https://github.com/xeoxaz/XeoKey/issues)

**Navigation**: [Home](Home) | [Installation](Installation) | [Configuration](Configuration) | [Deployment](Deployment)

## Server Issues

### Server won't start

**Symptoms:**
- Server fails to start
- Error messages about port or runtime

**Solutions:**
1. **Check if port is already in use:**
   ```bash
   # Windows
   netstat -ano | findstr :3000

   # Linux/Mac
   lsof -i :3000
   ```
   - If port is in use, either stop the other process or change `PORT` in `.env`

2. **Verify Bun is installed:**
   ```bash
   bun --version
   ```
   - Should show version 1.3.4 or later
   - Install from [bun.sh](https://bun.sh) if missing

3. **Check for syntax errors:**
   ```bash
   bun run typecheck
   ```
   - Fix any TypeScript errors reported

4. **Check dependencies:**
   ```bash
   bun install
   ```
   - Reinstall dependencies if needed

### Server crashes or restarts unexpectedly

**Solutions:**
1. **Check logs:**
   ```bash
   tail -f logs/server.log
   ```
   - Look for error messages or stack traces

2. **Check environment variables:**
   - Ensure all required variables are set
   - Verify `.env` file is in the root directory
   - Check for typos in variable names

3. **Check system resources:**
   - Verify sufficient memory and disk space
   - Check system logs for resource issues

## Database Issues

### Database connection fails

**Symptoms:**
- Dashboard shows "Database: Disconnected"
- Passwords not saving or loading
- Error messages about MongoDB

**Solutions:**
1. **Ensure MongoDB is running:**
   ```bash
   # Windows (check services)
   services.msc
   # Look for MongoDB service

   # Linux/Mac
   sudo systemctl status mongod
   # or
   ps aux | grep mongod
   ```

2. **Check MongoDB connection string:**
   - Verify `MONGODB_URI` in `.env` is correct
   - Format: `mongodb://localhost:27017` (or your MongoDB server)
   - For MongoDB Atlas: `mongodb+srv://username:password@cluster.mongodb.net/dbname`

3. **Test MongoDB connection:**
   ```bash
   # Using MongoDB shell
   mongosh mongodb://localhost:27017

   # Or test from command line
   mongosh "mongodb://localhost:27017" --eval "db.adminCommand('ping')"
   ```

4. **Check network connectivity:**
   - Verify firewall allows MongoDB port (default: 27017)
   - For remote databases, check network access

5. **Check MongoDB authentication:**
   - If MongoDB requires authentication, include credentials in URI
   - Format: `mongodb://username:password@host:port/database`

6. **Note:** Server will continue without database, but password features won't work

### Passwords not saving

**Symptoms:**
- "Save Password" button doesn't work
- No error message but password doesn't appear in list

**Solutions:**
1. **Check database connection status:**
   - Visit dashboard and check "Database" status
   - Should show "Connected"

2. **Verify MongoDB is running and accessible:**
   - See "Database connection fails" section above

3. **Check server logs:**
   ```bash
   tail -f logs/server.log
   ```
   - Look for database-related errors

4. **Check user authentication:**
   - Ensure you're logged in
   - Try logging out and back in

5. **Check form data:**
   - Verify all required fields are filled
   - Check browser console for JavaScript errors

### Passwords not loading

**Symptoms:**
- Password list is empty
- "No passwords found" message

**Solutions:**
1. **Check database connection** (see above)

2. **Verify user account:**
   - Ensure you're logged in with the correct account
   - Check if passwords exist in database for your user

3. **Check server logs for errors**

4. **Try refreshing the page**

### Data Loss Prevention

**⚠️ CRITICAL: If you lose your database, you will lose all your passwords permanently unless you have backups.**

**Prevention:**
1. **Set up regular MongoDB backups immediately** (see [Deployment Guide](./DEPLOYMENT.md#backup-strategy))
2. **Test restore procedures regularly** - A backup that can't be restored is useless
3. **Store backups in multiple locations** - Local + remote (cloud storage)
4. **Backup encryption keys separately** - Without keys, you cannot decrypt passwords even with a database backup

**If you've lost data:**
1. **Check if you have backups:**
   - Look for `mongodump` backup files
   - Check cloud storage if configured
   - Check automated backup locations

2. **Restore from backup:**
   ```bash
   mongorestore --uri="mongodb://localhost:27017" /backup/path
   ```

3. **If no backups exist:**
   - **Your passwords are permanently lost**
   - This is why backups are critical
   - Start fresh and set up backups immediately

## Authentication Issues

### Cannot log in

**Symptoms:**
- Login form doesn't accept credentials
- "Invalid username or password" error

**Solutions:**
1. **Verify credentials:**
   - Check username and password are correct
   - Ensure no extra spaces

2. **Check rate limiting:**
   - If too many failed attempts, wait 15 minutes
   - Rate limit: 5 attempts per 15 minutes per IP

3. **Check if account exists:**
   - Try registering a new account
   - If registration works, original account may not exist

4. **Check session settings:**
   - Clear browser cookies
   - Try incognito/private browsing mode
   - Check if cookies are enabled

5. **Check server logs:**
   - Look for authentication errors
   - Check for rate limiting messages

### Session expires too quickly

**Symptoms:**
- Logged out unexpectedly
- Need to log in frequently

**Solutions:**
1. **Check session expiration settings:**
   - Default session timeout is configured in code
   - Check `auth/session.ts` for session settings

2. **Check browser settings:**
   - Ensure cookies are enabled
   - Check cookie expiration settings
   - Don't use "Clear cookies on exit"

3. **Check `SESSION_SECRET`:**
   - Ensure `SESSION_SECRET` is set and stable
   - Changing `SESSION_SECRET` invalidates all sessions

### Cannot register new account

**Symptoms:**
- Registration form shows errors
- "Username already exists" or validation errors

**Solutions:**
1. **Check username requirements:**
   - 3-20 characters
   - Letters, numbers, underscores, and hyphens only
   - No spaces or special characters

2. **Check password requirements:**
   - Minimum 8 characters
   - At least one letter and one number

3. **Check rate limiting:**
   - Wait 15 minutes if rate limited
   - Try from different IP if possible

4. **Check if username already exists:**
   - Try a different username
   - Usernames must be unique

## Security Issues

### CSRF token errors

**Symptoms:**
- "Invalid CSRF token" error
- Forms not submitting

**Solutions:**
1. **Refresh the page:**
   - CSRF tokens are generated per session
   - Refresh to get a new token

2. **Check session:**
   - Ensure you're logged in
   - Try logging out and back in

3. **Check browser settings:**
   - Ensure cookies are enabled
   - Don't block third-party cookies

### Rate limiting issues

**Symptoms:**
- "Too many requests" error
- Cannot log in or register

**Solutions:**
1. **Wait for rate limit to expire:**
   - Default: 15 minutes
   - Limit: 5 attempts per 15 minutes per IP

2. **Check if using shared IP:**
   - If multiple users share IP, limit applies to all
   - Consider adjusting rate limits in `security/rateLimit.ts`

3. **Contact administrator:**
   - If legitimate use is blocked, contact admin
   - Admin can adjust rate limit settings

## Performance Issues

### Slow response times

**Symptoms:**
- Pages load slowly
- Actions take time to complete

**Solutions:**
1. **Check database performance:**
   - Verify MongoDB is running efficiently
   - Check database indexes
   - Monitor database connection

2. **Check server resources:**
   - Monitor CPU and memory usage
   - Ensure sufficient resources available

3. **Check network:**
   - Verify network connectivity
   - Check for network latency

4. **Check logs:**
   - Look for slow queries or operations
   - Identify bottlenecks

### High memory usage

**Solutions:**
1. **Check for memory leaks:**
   - Monitor memory usage over time
   - Restart server if memory grows continuously

2. **Check log file size:**
   - Large log files can consume memory
   - Set up log rotation (see Deployment Guide)

3. **Check database connections:**
   - Ensure connections are properly closed
   - Monitor connection pool size

## Logging Issues

### No logs appearing

**Solutions:**
1. **Check log file location:**
   - Default: `./logs/server.log`
   - Ensure `logs/` directory exists and is writable

2. **Check log level:**
   - Verify `LOG_LEVEL` in `.env`
   - Set to `debug` for more verbose logging

3. **Check file permissions:**
   - Ensure application has write permissions to `logs/` directory

### Too many log entries

**Solutions:**
1. **Adjust log level:**
   - Set `LOG_LEVEL=warn` or `LOG_LEVEL=error` in `.env`
   - Set `DEBUG=false` to disable debug logs

2. **Set up log rotation:**
   - See Deployment Guide for log rotation setup
   - Prevents log files from growing too large

## Environment Variable Issues

### Environment variables not working

**Symptoms:**
- Changes to `.env` not taking effect
- Default values being used instead

**Solutions:**
1. **Restart server:**
   - Environment variables are loaded at startup
   - Restart after changing `.env`

2. **Check `.env` file location:**
   - Must be in project root directory
   - Check for typos in filename (should be `.env`, not `env` or `.env.txt`)

3. **Check variable names:**
   - Ensure exact spelling (case-sensitive)
   - No extra spaces around `=`

4. **Check file format:**
   ```env
   # Correct format
   PORT=3000
   NODE_ENV=production

   # Wrong format (no spaces around =)
   PORT = 3000
   ```

## Getting Help

If you're still experiencing issues:

1. **Check the logs:**
   ```bash
   tail -n 100 logs/server.log
   ```

2. **Enable debug logging:**
   ```env
   DEBUG=true
   LOG_LEVEL=debug
   ```
   Restart server and reproduce the issue, then check logs.

3. **Check documentation:**
   - [Installation Guide](Installation)
   - [Configuration Guide](Configuration)
   - [Security Guide](Security)
   - [Deployment Guide](Deployment)

4. **Open an issue:**
   - Include error messages from logs
   - Describe steps to reproduce
   - Include environment details (OS, Bun version, MongoDB version)

## Common Error Messages

### "Port 3000 is already in use"
- **Solution:** Change `PORT` in `.env` or stop the process using port 3000

### "MongoServerError: connection refused"
- **Solution:** Start MongoDB or check `MONGODB_URI`

### "Invalid CSRF token"
- **Solution:** Refresh the page to get a new token

### "Rate limit exceeded"
- **Solution:** Wait 15 minutes or adjust rate limit settings

### "Session secret must be at least 32 characters"
- **Solution:** Set `SESSION_SECRET` to at least 32 characters in `.env`

### "Encryption key not set"
- **Solution:** Set `ENCRYPTION_KEY` in `.env` (required for production)

---

**Navigation**: [Home](Home) | [Installation](Installation) | [Configuration](Configuration) | [Deployment](Deployment)

