#!/usr/bin/env bun
/**
 * XeoKey Host/Manager Process
 *
 * Optional host wrapper for managing the server process lifecycle.
 *
 * Usage:
 *   bun run host.ts
 */

import { ProcessManager, getProcessManager } from './utils/process-manager';
import { logger } from './utils/logger';
import { existsSync, watchFile, unlink, unwatchFile } from 'fs';
import { writeFile as writeFileAsync } from 'fs/promises';
import { join } from 'path';
import { spawn } from 'bun';

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

function setConsoleTitle(title: string): void {
  process.title = title;
  if (process.stdout?.isTTY) {
    process.stdout.write(`\x1b]0;${title}\x07`);
  }
}

setConsoleTitle('Xeokey');

logger.info('Host wrapper starting...');

// Create host wrapper controller
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

function shouldNotifySystemd(): boolean {
  return process.env.NOTIFY_SOCKET !== undefined ||
    process.env.SYSTEMD_SERVICE === 'true' ||
    process.env.INVOCATION_ID !== undefined;
}

async function notifySystemdReady(): Promise<void> {
  if (!shouldNotifySystemd()) {
    return;
  }

  try {
    const proc = spawn(['/usr/bin/systemd-notify', '--ready'], {
      stdout: 'ignore',
      stderr: 'ignore',
      env: {
        ...process.env,
      },
    });

    const exitCode = await proc.exited;
    if (exitCode === 0) {
      logger.info('Sent systemd ready notification');
    } else {
      logger.warn(`systemd-notify --ready exited with code ${exitCode}`);
    }
  } catch (error: any) {
    logger.warn(`Failed to send systemd ready notification: ${error.message || error}`);
  }
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

    // Signal readiness to systemd when running as a service
    await notifySystemdReady();

    logger.info('Host wrapper ready');

    // Keep the process alive
    // The manager will handle server restarts automatically
  } catch (error: any) {
    logger.error(`Fatal error: ${error.message || error}`);
    process.exit(1);
  }
}

// Handle shutdown
process.on('SIGINT', async () => {
  logger.info('\nShutting down host wrapper...');
  if (restartWatcher && RESTART_FLAG_FILE) {
    unwatchFile(RESTART_FLAG_FILE);
  }
  await manager.stop();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  logger.info('Shutting down host wrapper...');
  if (restartWatcher && RESTART_FLAG_FILE) {
    unwatchFile(RESTART_FLAG_FILE);
  }
  await manager.stop();
  process.exit(0);
});

// Start
main();
