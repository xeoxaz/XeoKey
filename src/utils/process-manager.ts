import { logger } from './logger';
import { spawn, Process } from 'bun';
import { existsSync } from 'fs';
import { join } from 'path';

let serverProcess: Process | null = null;
let isShuttingDown = false;
let restartRequested = false;

/**
 * Internal Process Manager
 * Manages the server process lifecycle without requiring PM2
 */
export class ProcessManager {
  private serverPath: string;
  private projectRoot: string;
  private serverDir: string;

  constructor(serverPath: string = 'server.ts', projectRoot?: string) {
    this.serverPath = serverPath;

    // Detect project root - if we're in src/, go up one level
    const cwd = process.cwd();
    if (cwd.endsWith('src') || cwd.endsWith('src\\') || cwd.endsWith('src/')) {
      // We're already in src directory
      this.projectRoot = projectRoot || join(cwd, '..');
      this.serverDir = cwd; // Server is in current directory
    } else {
      // We're in project root
      this.projectRoot = projectRoot || cwd;
      this.serverDir = join(this.projectRoot, 'src');
    }
  }

  /**
   * Start the server process
   */
  async start(): Promise<{ success: boolean; error?: string }> {
    if (serverProcess && !serverProcess.killed) {
      logger.warn('Server process is already running');
      return { success: true };
    }

    try {
      const serverFullPath = join(this.serverDir, this.serverPath);

      if (!existsSync(serverFullPath)) {
        return { success: false, error: `Server file not found: ${serverFullPath}` };
      }

      logger.info(`Starting ${this.serverPath}`);

      // Spawn server process
      serverProcess = spawn(['bun', 'run', this.serverPath], {
        cwd: this.serverDir,
        stdout: 'pipe',
        stderr: 'pipe',
        env: {
          ...process.env,
          XEOKEY_MANAGED: 'true', // Signal that we're running under process manager
        },
      });

      // Handle server output
      serverProcess.stdout?.pipeTo(
        new WritableStream({
          write(chunk) {
            const text = new TextDecoder().decode(chunk);
            process.stdout.write(text);
          },
        })
      );

      serverProcess.stderr?.pipeTo(
        new WritableStream({
          write(chunk) {
            const text = new TextDecoder().decode(chunk);
            process.stderr.write(text);
          },
        })
      );

      // Monitor process exit
      serverProcess.exited.then((exitCode) => {
        if (!isShuttingDown && !restartRequested) {
          logger.error(`Server exited (code ${exitCode}), restarting in 2s...`);

          // Auto-restart after delay
          setTimeout(() => {
            if (!isShuttingDown && !restartRequested) {
              this.start().catch((error) => {
                logger.error(`Failed to restart server: ${error}`);
              });
            }
          }, 2000);
        }
        serverProcess = null;
      });

      // Wait a moment to see if process starts successfully
      await new Promise(resolve => setTimeout(resolve, 1000));

      if (serverProcess && !serverProcess.killed) {
        logger.info('Server started');
        return { success: true };
      } else {
        return { success: false, error: 'Server failed to start' };
      }
    } catch (error: any) {
      logger.error(`Start failed: ${error.message || error}`);
      return { success: false, error: error.message || 'Unknown error' };
    }
  }

  /**
   * Stop the server process
   */
  async stop(): Promise<{ success: boolean; error?: string }> {
    if (!serverProcess) {
      logger.warn('Server not running');
      return { success: true };
    }

    // Check if already killed
    if (serverProcess.killed) {
      serverProcess = null;
      return { success: true };
    }

    try {
      isShuttingDown = true;
      logger.info('Stopping server...');

      // Store reference to avoid null issues
      const process = serverProcess;

      // Try graceful shutdown first (SIGTERM)
      process.kill('SIGTERM');

      // Wait up to 5 seconds for graceful shutdown
      let waited = 0;
      while (process && !process.killed && waited < 5000) {
        await new Promise(resolve => setTimeout(resolve, 100));
        waited += 100;
      }

      // Force kill if still running
      if (process && !process.killed) {
        logger.warn('Force killing server...');
        process.kill('SIGKILL');
      }

      serverProcess = null;
      logger.info('Server stopped');
      return { success: true };
    } catch (error: any) {
      // Clear serverProcess on error
      serverProcess = null;
      logger.error(`Stop failed: ${error.message || error}`);
      return { success: false, error: error.message || 'Unknown error' };
    }
  }

  /**
   * Restart the server process (with optional git pull)
   */
  async restart(pullUpdates: boolean = false): Promise<{ success: boolean; error?: string }> {
    restartRequested = true;
    logger.info('Restarting server...');

    // Pull updates if requested
    if (pullUpdates) {
      logger.info('Pulling git updates...');
      try {
        const { spawn } = await import('bun');
        const pullProc = spawn(['git', 'pull', 'origin', 'master'], {
          stdout: 'pipe',
          stderr: 'pipe',
          cwd: this.projectRoot, // Git operations should be from project root
        });

        const pullOutput = await new Response(pullProc.stdout).text();
        const pullError = await new Response(pullProc.stderr).text();
        const pullExitCode = await pullProc.exited;

        if (pullExitCode !== 0) {
          logger.error(`Git pull failed: ${pullError || pullOutput}`);
          restartRequested = false;
          return { success: false, error: pullError || 'Git pull failed' };
        }

        logger.info('Git pull complete');
      } catch (error: any) {
        logger.error(`Git pull error: ${error.message || error}`);
        restartRequested = false;
        return { success: false, error: error.message || 'Git pull failed' };
      }
    }

    const stopResult = await this.stop();
    if (!stopResult.success) {
      restartRequested = false;
      return stopResult;
    }

    // Wait a moment before starting
    await new Promise(resolve => setTimeout(resolve, 500));

    restartRequested = false;
    return await this.start();
  }

  /**
   * Check if server is running
   */
  isRunning(): boolean {
    return serverProcess !== null && serverProcess && !serverProcess.killed;
  }

  /**
   * Get server process info
   */
  getStatus(): { running: boolean; pid?: number } {
    return {
      running: this.isRunning(),
      pid: serverProcess?.pid,
    };
  }
}

// Global instance
let processManager: ProcessManager | null = null;

/**
 * Get or create the process manager instance
 */
export function getProcessManager(): ProcessManager {
  if (!processManager) {
    processManager = new ProcessManager();
  }
  return processManager;
}

/**
 * Start server using internal process manager
 */
export async function startWithProcessManager(): Promise<{ success: boolean; error?: string }> {
  const manager = getProcessManager();
  return await manager.start();
}

/**
 * Restart server using internal process manager
 */
export async function restartWithProcessManager(pullUpdates: boolean = false): Promise<{ success: boolean; error?: string }> {
  const manager = getProcessManager();
  return await manager.restart(pullUpdates);
}

/**
 * Stop server using internal process manager
 */
export async function stopWithProcessManager(): Promise<{ success: boolean; error?: string }> {
  const manager = getProcessManager();
  return await manager.stop();
}

// Handle parent process signals
process.on('SIGINT', async () => {
  logger.info('Shutting down (SIGINT)...');
  isShuttingDown = true;
  if (processManager) {
    await processManager.stop();
  }
  process.exit(0);
});

process.on('SIGTERM', async () => {
  logger.info('Shutting down (SIGTERM)...');
  isShuttingDown = true;
  if (processManager) {
    await processManager.stop();
  }
  process.exit(0);
});
