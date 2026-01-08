# PM2 Reset Steps

## Issue
PM2 is detected but the path found is incorrect or doesn't exist.

## Steps to Reset PM2

### Option 1: Reinstall PM2 (Recommended)

1. **Uninstall PM2 globally:**
   ```bash
   npm uninstall -g pm2
   ```

2. **Clear npm cache (optional but recommended):**
   ```bash
   npm cache clean --force
   ```

3. **Reinstall PM2 globally:**
   ```bash
   npm install -g pm2
   ```

4. **Verify PM2 installation:**
   ```bash
   pm2 --version
   ```

5. **Verify PM2 is in PATH:**
   ```bash
   where pm2
   ```
   (On Windows) or
   ```bash
   which pm2
   ```
   (On Linux/Mac)

### Option 2: Fix PM2 Path Manually

1. **Find where PM2 is installed:**
   ```bash
   where pm2
   ```
   (Windows) or
   ```bash
   which pm2
   ```
   (Linux/Mac)

2. **If PM2 is not in PATH, add it:**
   - Windows: Add the PM2 directory to your system PATH environment variable
   - Linux/Mac: Add to your shell profile (`.bashrc`, `.zshrc`, etc.)

### Option 3: Use Bun's PM2 (if available)

If you have PM2 installed via Bun:
```bash
bun pm2 --version
```

### Option 4: Clear PM2 Daemon and Restart

1. **Stop all PM2 processes:**
   ```bash
   pm2 stop all
   pm2 delete all
   ```

2. **Kill PM2 daemon:**
   ```bash
   pm2 kill
   ```

3. **Restart PM2 daemon:**
   ```bash
   pm2 list
   ```

### Verification

After resetting, verify PM2 works:
```bash
pm2 --version
pm2 list
```

## Current PM2 Locations Found

Based on your system, PM2 might be at:
- `C:\Users\Xeoxa\.bun\bin\pm2.exe` (Bun installation)
- `C:\Users\Xeoxa\AppData\Roaming\npm\pm2.cmd` (npm global)
- `C:\Users\Xeoxa\AppData\Roaming\npm\pm2` (npm global)

The code has been updated to check all these locations and verify files exist before using them.
