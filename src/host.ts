#!/usr/bin/env bun
/**
 * XeoKey Host/Manager Process
 * 
 * This is the main entry point that manages the server process lifecycle.
 * Run this instead of server.ts directly to get automatic process management.
 * 
 * Usage:
 *   bun run host.ts
 *   or
 *   bun src/host.ts
 */

import { ProcessManager, getProcessManager } from './utils/process-manager';
import { logger } from './utils/logger';
import { existsSync, watchFile, unlink } from 'fs';
import { writeFile as writeFileAsync } from 'fs/promises';
import { join } from 'path';

const RESTART_FLAG_FILE = join(process.cwd(), '.restart-requested');

logger.info('🚀 XeoKey Process Manager Starting...');
logger.info('This process will manage the server lifecycle');

// Create process manager
const manager = getProcessManager();

// Watch for restart requests
let restartWatcher: ReturnType<typeof watchFile> | null = null;

function setupRestartWatcher() {
  if (restartWatcher) {
    return; // Already watching
  }

  // Create the file if it doesn't exist (watchFile needs it to exist)
  if (!existsSync(RESTART_FLAG_FILE)) {
    writeFileAsync(RESTART_FLAG_FILE, '', 'utf-8').catch(() => {});
  }

  restartWatcher = watchFile(RESTART_FLAG_FILE, async (curr, prev) => {
    // Check if file was just created or modified
    if (curr.mtimeMs > prev.mtimeMs && curr.size > 0) {
      logger.info('Restart flag detected, restarting server with updates...');
      
      // Remove the flag file
      try {
        if (existsSync(RESTART_FLAG_FILE)) {
          unlink(RESTART_FLAG_FILE, () => {});
        }
      } catch (error) {
        // Ignore errors
      }

      // Restart the server with git pull
      await manager.restart(true);
    }
  });

  logger.info('Watching for restart requests...');
}

// Start the server
async function main() {
  try {
    // Start server
    const startResult = await manager.start();
    if (!startResult.success) {
      logger.error(`Failed to start server: ${startResult.error}`);
      process.exit(1);
    }

    // Setup restart watcher
    setupRestartWatcher();

    logger.info('✅ Process Manager is running');
    logger.info('Server is managed by this process');
    logger.info('Press Ctrl+C to stop');

    // Keep the process alive
    // The manager will handle server restarts automatically
  } catch (error: any) {
    logger.error(`Fatal error: ${error.message || error}`);
    process.exit(1);
  }
}

// Handle shutdown
process.on('SIGINT', async () => {
  logger.info('\nShutting down process manager...');
  if (restartWatcher) {
    restartWatcher.close();
  }
  await manager.stop();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  logger.info('Shutting down process manager...');
  if (restartWatcher) {
    restartWatcher.close();
  }
  await manager.stop();
  process.exit(0);
});

// Start
main();
