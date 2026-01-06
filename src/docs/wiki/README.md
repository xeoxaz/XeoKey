# Wiki Documentation

This directory contains the source files for the GitHub wiki. These files need to be synced to the GitHub wiki repository manually.

## Syncing to GitHub Wiki

GitHub wikis are separate git repositories. To sync these files to your GitHub wiki:

### Option 1: Use the Sync Scripts

**Windows (PowerShell):**
```powershell
.\sync-wiki.ps1
```

**Linux/Mac (Bash):**
```bash
chmod +x sync-wiki.sh
./sync-wiki.sh
```

### Option 2: Manual Sync

1. **Clone the wiki repository:**
   ```bash
   git clone https://github.com/xeoxaz/XeoKey.wiki.git
   cd XeoKey.wiki
   ```

2. **Copy files from docs/wiki/:**
   ```bash
   # From the XeoKey root directory
   cp docs/wiki/*.md XeoKey.wiki/
   ```

3. **Commit and push:**
   ```bash
   cd XeoKey.wiki
   git add -A
   git commit -m "Update wiki documentation"
   git push origin master
   ```

## Prerequisites

Before syncing, make sure:
1. The wiki feature is enabled in your GitHub repository settings
2. You have at least one wiki page created (even if empty) - this initializes the wiki repository
3. You have push access to the repository

## Wiki Pages

- **Home.md** - Main landing page
- **Installation.md** - Installation guide
- **Configuration.md** - Configuration options
- **Deployment.md** - Deployment guide
- **Security.md** - Security documentation
- **API.md** - API reference
- **Troubleshooting.md** - Troubleshooting guide

## Notes

- GitHub wiki links use simple page names (e.g., `[Home](Home)`) not file paths
- The wiki repository URL format is: `https://github.com/USERNAME/REPO.wiki.git`
- Wiki pages are stored in a separate git repository from your main code

