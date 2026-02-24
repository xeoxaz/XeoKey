import { logger } from './logger';
import { spawn } from 'bun';
import { existsSync } from 'fs';
import { join } from 'path';

let serverProcess: any = null;
let isShuttingDown = false;
let restartRequested = false;
let consecutiveCrashes = 0;
let lastRestartTime = 0;
let healthCheckInterval: ReturnType<typeof setInterval> | null = null;

/**
 * Internal Process Manager
 * Manages the server process lifecycle without requiring PM2
 */
export class ProcessManager {
  private serverPath: string;
  private projectRoot: string;
  private serverDir: string;
  private serverPort: number;
  private maxConsecutiveCrashes = 5;
  private healthCheckInterval = 30000; // 30 seconds

  constructor(serverPath: string = 'server.ts', projectRoot?: string) {
    this.serverPath = serverPath;
    this.serverPort = parseInt(process.env.PORT || '3000', 10);

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
   * Check if server is actually responding (health check)
   */
  private async checkServerHealth(): Promise<boolean> {
    try {
      const response = await fetch(`http://localhost:${this.serverPort}/api/server/status`, {
        method: 'GET',
        signal: AbortSignal.timeout(5000), // 5 second timeout
      });

      if (!response.ok) {
        return false;
      }

      const data = await response.json() as any;
      return data.status === 'ready' || data.status === 'running';
    } catch (error) {
      return false; // Server not responding
    }
  }

  /**
   * Wait for server to be ready (with timeout)
   */
  private async waitForServerReady(timeoutMs: number = 30000): Promise<boolean> {
    const startTime = Date.now();
    const checkInterval = 1000; // Check every second

    while (Date.now() - startTime < timeoutMs) {
      if (await this.checkServerHealth()) {
        return true;
      }
      await new Promise(resolve => setTimeout(resolve, checkInterval));
    }

    return false; // Timeout
  }

  /**
   * Start health check monitoring
   */
  private startHealthMonitoring(): void {
    // Clear existing interval if any
    if (healthCheckInterval) {
      clearInterval(healthCheckInterval);
      healthCheckInterval = null;
    }

    // Start new health check interval
    healthCheckInterval = setInterval(async () => {
      if (isShuttingDown || restartRequested || !serverProcess) {
        return;
      }

      // Check if process is still alive
      if (serverProcess.killed) {
        logger.warn('Server process died, restarting...');
        consecutiveCrashes++;
        this.handleCrash();
        return;
      }

      // Check if server is responding
      const isHealthy = await this.checkServerHealth();
      if (!isHealthy) {
        logger.warn('Server not responding to health checks, restarting...');
        consecutiveCrashes++;
        this.handleCrash();
      } else {
        // Reset crash counter on successful health check
        if (consecutiveCrashes > 0) {
          logger.info(`Server recovered after ${consecutiveCrashes} crash(es)`);
          consecutiveCrashes = 0;
        }
      }
    }, this.healthCheckInterval);
  }

  /**
   * Stop health check monitoring
   */
  private stopHealthMonitoring(): void {
    if (healthCheckInterval) {
      clearInterval(healthCheckInterval);
      healthCheckInterval = null;
    }
  }

  /**
   * Handle server crash with exponential backoff
   */
  private async handleCrash(): Promise<void> {
    if (consecutiveCrashes >= this.maxConsecutiveCrashes) {
      logger.error(`Server crashed ${consecutiveCrashes} times consecutively. Stopping auto-restart.`);
      this.stopHealthMonitoring();
      return;
    }

    // Exponential backoff: 2s, 4s, 8s, 16s, 32s
    const backoffDelay = Math.min(2000 * Math.pow(2, consecutiveCrashes - 1), 32000);
    logger.info(`Restarting in ${backoffDelay / 1000}s (crash #${consecutiveCrashes})...`);

    await new Promise(resolve => setTimeout(resolve, backoffDelay));

    if (!isShuttingDown && !restartRequested) {
      await this.start();
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
      serverProcess.exited.then((exitCode: any) => {
        if (!isShuttingDown && !restartRequested) {
          consecutiveCrashes++;
          logger.error(`Server exited (code ${exitCode})`);
          this.handleCrash();
        }
        serverProcess = null;
      });

      // Wait for process to start
      await new Promise(resolve => setTimeout(resolve, 1000));

      if (!serverProcess || serverProcess.killed) {
        return { success: false, error: 'Server process failed to start' };
      }

      // Wait for server to be ready (health check)
      logger.info('Waiting for server to be ready...');
      const isReady = await this.waitForServerReady(30000);

      if (!isReady) {
        logger.warn('Server started but not responding to health checks');
        // Don't fail - server might be slow to start
      }

      // Start health monitoring
      this.startHealthMonitoring();

      logger.info('Server started and ready');
      lastRestartTime = Date.now();
      consecutiveCrashes = 0; // Reset on successful start
      return { success: true };
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
      this.stopHealthMonitoring();
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
  getStatus(): {
    running: boolean;
    pid?: number;
    consecutiveCrashes: number;
    lastRestartTime: number;
    uptime?: number;
  } {
    return {
      running: this.isRunning(),
      pid: serverProcess?.pid,
      consecutiveCrashes,
      lastRestartTime,
      uptime: lastRestartTime > 0 ? Math.floor((Date.now() - lastRestartTime) / 1000) : undefined,
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
  if (healthCheckInterval) {
    clearInterval(healthCheckInterval);
    healthCheckInterval = null;
  }
  if (processManager) {
    await processManager.stop();
  }
  process.exit(0);
});

process.on('SIGTERM', async () => {
  logger.info('Shutting down (SIGTERM)...');
  isShuttingDown = true;
  if (healthCheckInterval) {
    clearInterval(healthCheckInterval);
    healthCheckInterval = null;
  }
  if (processManager) {
    await processManager.stop();
  }
  process.exit(0);
});
