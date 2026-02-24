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
import { existsSync, watchFile, unlink, unwatchFile } from 'fs';
import { writeFile as writeFileAsync } from 'fs/promises';
import { join } from 'path';

// Determine project root - if we're in src/, go up one level
function getProjectRoot(): string {
  const cwd = process.cwd();
  if (cwd.endsWith('src') || cwd.endsWith('src\\') || cwd.endsWith('src/')) {
    return join(cwd, '..');
  }
  return cwd;
}

const projectRoot = getProjectRoot();
const RESTART_FLAG_FILE = join(projectRoot, '.restart-requested');

logger.info('🚀 Process Manager starting...');

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
      logger.info('Restart flag detected, restarting with updates...');

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

  logger.info('Watching for restart flags...');
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

    logger.info('✅ Process Manager ready');

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
  if (restartWatcher && RESTART_FLAG_FILE) {
    unwatchFile(RESTART_FLAG_FILE);
  }
  await manager.stop();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  logger.info('Shutting down process manager...');
  if (restartWatcher && RESTART_FLAG_FILE) {
    unwatchFile(RESTART_FLAG_FILE);
  }
  await manager.stop();
  process.exit(0);
});

// Start
main();
