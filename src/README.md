# XeoKey - Secure Password Manager

A secure, self-hosted password manager built with Bun and MongoDB. Features include password encryption, analytics tracking, and a modern web interface.

## Features

- 🔐 **Secure Password Storage** - AES-256 encryption for all passwords
- 🔑 **TOTP/HOTP Support** - Two-factor authentication code generation and management
- 👤 **User Authentication** - Secure session management with bcrypt password hashing
- 📊 **Analytics Dashboard** - Track password views, copies, additions, and more with interactive charts
- 🔍 **Password Strength Analysis** - Automatic detection of weak and duplicate passwords
- 📱 **Modern UI** - Clean, responsive interface with dark theme
- 🛡️ **Security Features** - CSRF protection, rate limiting, input sanitization
- 📝 **File Logging** - Comprehensive built-in logging system
- ⚡ **Fast Performance** - Built with Bun runtime for optimal speed

## Prerequisites

- **[Bun](https://bun.sh)** - JavaScript runtime (v1.3.4 or later)
- **[MongoDB](https://www.mongodb.com/)** - Database server (optional, but recommended)

## Installation

1. **Clone or download the repository:**
   ```bash
   cd XeoKey
   ```

2. **Install dependencies:**
   ```bash
   bun install
   ```

   Dependencies will be automatically installed by Bun.

3. **Set up environment variables:**

   Create a `.env` file in the root directory (optional, but recommended for production):
   ```env
   # Server Configuration
   PORT=3000
   NODE_ENV=production

   # Database Configuration
   MONGODB_URI=mongodb://localhost:27017

   # Security (REQUIRED for production)
   SESSION_SECRET=your-super-secret-session-key-at-least-32-characters-long
   ENCRYPTION_KEY=your-super-secret-encryption-key-for-password-storage
   ```

   **Important Security Notes:**
   - `SESSION_SECRET`: Must be at least 32 characters long. Used for session cookie signing.
   - `ENCRYPTION_KEY`: Used to encrypt passwords. Must be set in production.
   - Generate strong random keys for production use.

4. **Start MongoDB (if using local database):**
   ```bash
   # On Windows (if installed as service, it should start automatically)
   # Or use MongoDB Compass or start manually

   # On Linux/Mac
   mongod
   ```

## Running the Server

### Development Mode (with auto-reload):
```bash
bun run dev
```

### Production Mode (Direct):
```bash
bun run start
```

Or use the provided batch file on Windows:
```bash
Start.bat
```

### Production Mode (with Process Manager - Recommended):
```bash
bun run host
```

Or use the provided batch file on Windows:
```bash
Start-Host.bat
```

The process manager provides automatic restarts, health monitoring, and crash recovery. See [HOST_README.md](HOST_README.md) for details.

The server will start on `http://localhost:3000` by default (or the port specified in `PORT` environment variable).

## First-Time Setup

1. **Start the server** (see above)

2. **Navigate to** `http://localhost:3000`

3. **Register a new account:**
   - Click "Register" or navigate to `/register`
   - Create your first user account
   - Username requirements:
     - 3-20 characters
     - Letters, numbers, underscores, and hyphens only
   - Password requirements:
     - Minimum 8 characters
     - At least one letter and one number

4. **Login** with your new account

5. **Add your first password:**
   - Click "+ Add Password" or navigate to `/passwords/add`
   - Fill in the website, username, email (optional), password, and notes (optional)
   - Click "Save Password"

**⚠️ IMPORTANT: Database Backups**

**Your passwords are stored in MongoDB. Without regular backups, you risk losing all your passwords permanently if:**
- Your database server crashes or fails
- Your hard drive fails
- Your system is compromised or corrupted
- You accidentally delete the database

**Set up regular MongoDB backups immediately after installation.** See the [Deployment Guide](https://github.com/xeoxaz/XeoKey/wiki/Deployment#critical-backup-strategy) for backup instructions. **Without backups, you will lose all your passwords if your database is lost.**

## Project Structure

```
XeoKey/
├── auth/              # Authentication & session management
│   ├── session.ts     # Session handling
│   └── users.ts       # User management
├── db/                # Database connection
│   └── mongodb.ts     # MongoDB client
├── models/            # Data models
│   ├── analytics.ts   # Analytics tracking
│   └── password.ts    # Password management
├── public/            # Static files
│   ├── script.js      # Client-side JavaScript
│   ├── styles.css     # Stylesheet
│   └── favicon.ico    # Favicon
├── security/          # Security features
│   ├── csrf.ts        # CSRF protection
│   └── rateLimit.ts   # Rate limiting
├── templates/         # HTML templates
│   ├── header.html    # Page header
│   └── footer.html    # Page footer
├── utils/             # Utilities
│   ├── logger.ts      # Logging system
│   └── sanitize.ts    # Input sanitization
├── logs/              # Log files (auto-created)
│   └── server.log     # Application logs
├── server.ts          # Main server file
├── package.json       # Dependencies
└── README.md          # This file
```

## Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `PORT` | Server port number | `3000` | No |
| `MONGODB_URI` | MongoDB connection string | `mongodb://localhost:27017` | No* |
| `MONGO_URI` | Alternative MongoDB URI variable | Same as above | No |
| `SESSION_SECRET` | Secret key for session signing | `change-this-secret-key-in-production` | Yes (production) |
| `ENCRYPTION_KEY` | Key for password encryption | `default-encryption-key-change-in-production` | Yes (production) |
| `NODE_ENV` | Environment mode (`production` or `development`) | `development` | No |

\* MongoDB is optional - the server will run without it, but password storage won't work.

## API Endpoints

### Authentication
- `GET /login` - Login page
- `POST /login` - Authenticate user
- `GET /register` - Registration page
- `POST /register` - Create new user
- `POST /logout` - Logout user

### Password Management
- `GET /passwords` - List all passwords (sorted by most viewed/copied)
- `GET /passwords/add` - Add password form
- `POST /passwords/add` - Create new password entry
- `GET /passwords/:id` - View password details (increments view count)
- `POST /passwords/:id/update` - Update password entry
- `POST /passwords/:id/delete` - Delete password entry
- `POST /passwords/:id/copy` - Track password copy (increments copy count)

### Analytics
- `GET /api/analytics` - Get analytics data (last 30 days)
- `GET /api/status` - Get server and database status

### Dashboard
- `GET /` - Dashboard with analytics, charts, and recent passwords

## Security Features

- ✅ **Password Encryption** - AES-256-CBC encryption for all stored passwords
- ✅ **Session Management** - Secure session cookies with expiration
- ✅ **CSRF Protection** - All forms protected with CSRF tokens
- ✅ **Rate Limiting** - Protection against brute force attacks (5 attempts per 15 minutes)
- ✅ **Input Sanitization** - All user inputs sanitized and validated
- ✅ **Security Headers** - Comprehensive security headers (CSP, HSTS, X-Frame-Options, etc.)
- ✅ **Password Strength Analysis** - Automatic detection of weak passwords
- ✅ **Duplicate Detection** - Identifies reused passwords across accounts
- ✅ **Error Logging Sanitization** - Sensitive data filtered from logs

## Analytics & Monitoring

The dashboard provides comprehensive analytics:

- **Activity Tracking**: Views, copies, additions, edits, deletions, and errors
- **Interactive Charts**:
  - Line chart showing activity trends over the last 30 days
  - Doughnut chart showing event distribution
- **System Status**:
  - Server uptime
  - Database connection status
  - Database uptime
- **Real-time Updates**: Dashboard refreshes every 30 seconds

## Logging

The application uses a built-in logger for structured logging:

- **Console Output**: Color-coded logs with timestamps
- **File Logging**: All logs written to `./logs/server.log`
- **Log Levels**: Debug, Info, Warn, Error
- **Module-Specific Loggers**: Separate loggers for Server, Database, Password, and Analytics modules

## Development

### Running in Development Mode

```bash
bun run dev
```

This will:
- Auto-reload on file changes
- Show detailed error messages
- Use development security settings

### Building for Production

1. Set `NODE_ENV=production`
2. Set all required environment variables
3. Run `bun run start`

## Troubleshooting

> **🐛 Found a bug or issue?** [Report it on GitHub](https://github.com/xeoxaz/XeoKey/issues)

### Server won't start
- Check if port 3000 is already in use
- Verify Bun is installed: `bun --version`
- Check for syntax errors in `server.ts`

### Database connection fails
- Ensure MongoDB is running
- Check `MONGODB_URI` is correct
- Verify network connectivity to MongoDB server
- Server will continue without database, but password features won't work

### Passwords not saving
- Check database connection status on dashboard
- Verify MongoDB is running and accessible
- Check server logs in `./logs/server.log`

### Session issues
- Ensure `SESSION_SECRET` is set (required in production)
- Check cookie settings in browser
- Verify session expiration settings

## Production Deployment

1. **Set all environment variables:**
   ```env
   NODE_ENV=production
   SESSION_SECRET=<strong-random-32-char-key>
   ENCRYPTION_KEY=<strong-random-key>
   MONGODB_URI=<your-mongodb-connection-string>
   PORT=3000
   ```

2. **Use HTTPS:**
   - Set up reverse proxy (nginx, Caddy, etc.)
   - Configure SSL/TLS certificates
   - Secure cookies will only work over HTTPS

3. **Database Security:**
   - Use MongoDB authentication
   - Restrict network access to database
   - Enable MongoDB encryption at rest

4. **Monitor Logs:**
   - Check `./logs/server.log` regularly
   - Set up log rotation
   - Monitor for security events

5. **Backup (CRITICAL):**
   - **⚠️ Set up regular MongoDB backups immediately** - Without backups, you will lose all your passwords if the database is lost
   - Regular MongoDB backups (daily recommended)
   - Backup encryption keys securely
   - Test restore procedures regularly
   - Store backups in multiple locations (local + remote)

## License

### Source Code

The source code of XeoKey is licensed under the **ISC License** - a permissive open source license that allows you to use, modify, and distribute the code freely. See the [LICENSE](../LICENSE) file for full details.

### Design Assets

**The visual design, user interface, styling, and design elements are Copyright (c) 2026, xeoxaz. All rights reserved.**

This means:
- ✅ **You can**: Use, modify, and distribute the source code
- ✅ **You can**: Create your own designs and styling
- ❌ **You cannot**: Copy or reproduce the visual design, UI, CSS, or design elements without permission

The code is open source, but the design is protected by copyright. If you want to use the design, please contact the project maintainer.

## Support

For any problems, bugs, errors, or graphical issues, please report them on GitHub:

**🐛 [Report Issues](https://github.com/xeoxaz/XeoKey/issues)**

For questions or contributions, please refer to the project repository.

---

**⚠️ Security Warning**: Never commit `.env` files or expose your `SESSION_SECRET` and `ENCRYPTION_KEY` in version control or public locations.
