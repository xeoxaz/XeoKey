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

  constructor(serverPath: string = 'server.ts', projectRoot?: string) {
    this.serverPath = serverPath;
    this.projectRoot = projectRoot || process.cwd();
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
      const serverFullPath = join(this.projectRoot, 'src', this.serverPath);
      
      if (!existsSync(serverFullPath)) {
        return { success: false, error: `Server file not found: ${serverFullPath}` };
      }

      logger.info(`Starting server: ${this.serverPath}`);

      // Spawn server process
      serverProcess = spawn(['bun', 'run', this.serverPath], {
        cwd: join(this.projectRoot, 'src'),
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
          logger.error(`Server process exited unexpectedly with code ${exitCode}`);
          logger.info('Attempting to restart server in 2 seconds...');
          
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
        logger.info('Server process started successfully');
        return { success: true };
      } else {
        return { success: false, error: 'Server process failed to start' };
      }
    } catch (error: any) {
      logger.error(`Error starting server: ${error.message || error}`);
      return { success: false, error: error.message || 'Unknown error' };
    }
  }

  /**
   * Stop the server process
   */
  async stop(): Promise<{ success: boolean; error?: string }> {
    if (!serverProcess || serverProcess.killed) {
      logger.warn('Server process is not running');
      return { success: true };
    }

    try {
      isShuttingDown = true;
      logger.info('Stopping server process...');

      // Try graceful shutdown first (SIGTERM)
      serverProcess.kill('SIGTERM');

      // Wait up to 5 seconds for graceful shutdown
      let waited = 0;
      while (!serverProcess.killed && waited < 5000) {
        await new Promise(resolve => setTimeout(resolve, 100));
        waited += 100;
      }

      // Force kill if still running
      if (!serverProcess.killed) {
        logger.warn('Server did not stop gracefully, forcing kill...');
        serverProcess.kill('SIGKILL');
      }

      serverProcess = null;
      logger.info('Server process stopped');
      return { success: true };
    } catch (error: any) {
      logger.error(`Error stopping server: ${error.message || error}`);
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
      logger.info('Pulling updates from git...');
      try {
        const { spawn } = await import('bun');
        const pullProc = spawn(['git', 'pull', 'origin', 'master'], {
          stdout: 'pipe',
          stderr: 'pipe',
          cwd: this.projectRoot,
        });

        const pullOutput = await new Response(pullProc.stdout).text();
        const pullError = await new Response(pullProc.stderr).text();
        const pullExitCode = await pullProc.exited;

        if (pullExitCode !== 0) {
          logger.error(`Git pull failed: ${pullError || pullOutput}`);
          restartRequested = false;
          return { success: false, error: pullError || 'Git pull failed' };
        }

        logger.info('Git pull successful');
      } catch (error: any) {
        logger.error(`Error pulling updates: ${error.message || error}`);
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
    return serverProcess !== null && !serverProcess.killed;
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
  logger.info('Received SIGINT, shutting down...');
  isShuttingDown = true;
  if (processManager) {
    await processManager.stop();
  }
  process.exit(0);
});

process.on('SIGTERM', async () => {
  logger.info('Received SIGTERM, shutting down...');
  isShuttingDown = true;
  if (processManager) {
    await processManager.stop();
  }
  process.exit(0);
});
