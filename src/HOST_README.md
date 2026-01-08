# XeoKey Process Manager (Host)

## Overview

The internal process manager replaces PM2 with a built-in solution. The host process manages the server lifecycle without requiring external process managers.

## How It Works

1. **Host Process**: Runs continuously and manages the server
2. **Server Process**: Spawned as a child process by the host
3. **Restart Mechanism**: Server signals host via a flag file when restart is needed
4. **Auto-Restart**: Host automatically restarts the server if it crashes

## Usage

### Start with Process Manager

```bash
# From src/ directory
bun run host.ts

# Or use the batch file (Windows)
Start-Host.bat

# Or from package.json
bun run host
```

### Benefits

- ✅ No external dependencies (no PM2 required)
- ✅ Automatic restart on crashes
- ✅ Graceful shutdown handling
- ✅ Update handling with git pull
- ✅ Process never truly stops (only server restarts)

## How Restarts Work

1. When an update is available, the server creates `.restart-requested` file
2. Host process watches this file
3. When file is detected, host:
   - Pulls latest changes from git
   - Stops the current server process
   - Starts a new server process
4. Server continues running without interruption

## Environment Variable

When running under the process manager, the server sets `XEOKEY_MANAGED=true` so it knows to use the flag file method for restarts.

## Stopping

Press `Ctrl+C` to stop both the host and server processes gracefully.

## Fallback

If the process manager is not available, the system falls back to:
1. PM2 (if installed)
2. Script-based restart (restart-server.bat/sh)
