import { logger } from './logger';
import { spawn } from 'bun';
import { existsSync } from 'fs';

export interface PM2Status {
  installed: boolean;
  available: boolean;
  processName?: string;
  running?: boolean;
}

/**
 * Check if PM2 is installed globally
 */
export async function checkPM2Installed(): Promise<boolean> {
  try {
    const proc = spawn(['pm2', '--version'], {
      stdout: 'pipe',
      stderr: 'pipe',
    });

    const output = await new Response(proc.stdout).text();
    const exitCode = await proc.exited;

    if (exitCode === 0 && output.trim()) {
      logger.info(`PM2 detected: version ${output.trim()}`);
      return true;
    }
    return false;
  } catch (error) {
    logger.debug(`PM2 check failed: ${error}`);
    return false;
  }
}

/**
 * Install PM2 globally using npm
 */
export async function installPM2(): Promise<{ success: boolean; error?: string }> {
  try {
    logger.info('Installing PM2 globally...');
    const proc = spawn(['npm', 'install', '-g', 'pm2'], {
      stdout: 'pipe',
      stderr: 'pipe',
    });

    const output = await new Response(proc.stdout).text();
    const error = await new Response(proc.stderr).text();
    const exitCode = await proc.exited;

    if (exitCode !== 0) {
      logger.error(`PM2 installation failed: ${error || output}`);
      return { success: false, error: error || 'Installation failed' };
    }

    logger.info('PM2 installed successfully');
    return { success: true };
  } catch (error: any) {
    logger.error(`Error installing PM2: ${error.message || error}`);
    return { success: false, error: error.message || 'Unknown error' };
  }
}

/**
 * Get PM2 process status for XeoKey
 */
export async function getPM2ProcessStatus(processName: string = 'xeokey'): Promise<PM2Status> {
  const installed = await checkPM2Installed();

  if (!installed) {
    return { installed: false, available: false };
  }

  try {
    // Check if process is running in PM2
    const proc = spawn(['pm2', 'list'], {
      stdout: 'pipe',
      stderr: 'pipe',
    });

    const output = await new Response(proc.stdout).text();
    const exitCode = await proc.exited;

    if (exitCode !== 0) {
      return { installed: true, available: false };
    }

    // Check if our process name exists in the output
    const running = output.includes(processName) && (output.includes('online') || output.includes('starting'));

    return {
      installed: true,
      available: true,
      processName,
      running,
    };
  } catch (error) {
    logger.debug(`PM2 status check failed: ${error}`);
    return { installed: true, available: false };
  }
}

/**
 * Start server with PM2
 */
export async function startWithPM2(processName: string = 'xeokey', scriptPath: string = 'src/server.ts'): Promise<{ success: boolean; error?: string }> {
  try {
    const installed = await checkPM2Installed();
    if (!installed) {
      return { success: false, error: 'PM2 is not installed' };
    }

    logger.info(`Starting XeoKey with PM2 as process: ${processName}`);

    // Get the project root directory and src directory
    const projectRoot = process.cwd();
    const srcDir = `${projectRoot}/src`;

    // Extract just the filename from scriptPath (e.g., "src/server.ts" -> "server.ts")
    const scriptFile = scriptPath.includes('/') ? scriptPath.split('/').pop() : scriptPath;

    // Use bun to run the server via PM2
    // Command: pm2 start bun --name xeokey -- server.ts
    // Run from src directory so relative paths (templates, etc.) work correctly
    const proc = spawn(['pm2', 'start', 'bun', '--name', processName, '--', scriptFile || 'server.ts'], {
      stdout: 'pipe',
      stderr: 'pipe',
      cwd: srcDir, // Run from src directory so templates and other relative paths work
    });

    const output = await new Response(proc.stdout).text();
    const error = await new Response(proc.stderr).text();
    const exitCode = await proc.exited;

    if (exitCode !== 0) {
      logger.error(`PM2 start failed: ${error || output}`);
      return { success: false, error: error || 'PM2 start failed' };
    }

    logger.info(`XeoKey started with PM2: ${processName}`);
    logger.info(`PM2 output: ${output}`);
    if (error) {
      logger.debug(`PM2 stderr: ${error}`);
    }

    // Wait a moment and verify the process is actually running
    await new Promise(resolve => setTimeout(resolve, 1000));
    const status = await getPM2ProcessStatus(processName);
    if (!status.running) {
      logger.warn(`PM2 process ${processName} may not have started correctly. Status: ${JSON.stringify(status)}`);
      // Still return success as PM2 command succeeded, but log warning
    } else {
      logger.info(`PM2 process ${processName} is running`);
    }

    return { success: true };
  } catch (error: any) {
    logger.error(`Error starting with PM2: ${error.message || error}`);
    return { success: false, error: error.message || 'Unknown error' };
  }
}

/**
 * Restart server using PM2
 */
export async function restartWithPM2(processName: string = 'xeokey', scriptPath: string = 'src/server.ts'): Promise<{ success: boolean; error?: string }> {
  try {
    const installed = await checkPM2Installed();
    if (!installed) {
      return { success: false, error: 'PM2 is not installed' };
    }

    // Check if process exists
    const status = await getPM2ProcessStatus(processName);

    // First pull updates
    const pullProc = spawn(['git', 'pull', 'origin', 'master'], {
      stdout: 'pipe',
      stderr: 'pipe',
    });

    const pullOutput = await new Response(pullProc.stdout).text();
    const pullError = await new Response(pullProc.stderr).text();
    const pullExitCode = await pullProc.exited;

    if (pullExitCode !== 0) {
      logger.error(`Git pull failed: ${pullError || pullOutput}`);
      return { success: false, error: pullError || 'Git pull failed' };
    }

    logger.info('Git pull successful...');

    // If process doesn't exist, start it instead of restarting
    if (!status.running) {
      logger.info(`Process ${processName} not found in PM2, starting it...`);
      return await startWithPM2(processName, scriptPath);
    }

    logger.info(`Restarting XeoKey via PM2: ${processName}`);

    // Restart with PM2 (this will reload with new code)
    const restartProc = spawn(['pm2', 'restart', processName], {
      stdout: 'pipe',
      stderr: 'pipe',
    });

    const restartOutput = await new Response(restartProc.stdout).text();
    const restartError = await new Response(restartProc.stderr).text();
    const restartExitCode = await restartProc.exited;

    if (restartExitCode !== 0) {
      logger.error(`PM2 restart failed: ${restartError || restartOutput}`);
      return { success: false, error: restartError || 'PM2 restart failed' };
    }

    logger.info(`XeoKey restarted successfully via PM2`);
    return { success: true };
  } catch (error: any) {
    logger.error(`Error restarting with PM2: ${error.message || error}`);
    return { success: false, error: error.message || 'Unknown error' };
  }
}

/**
 * Trigger restart using PM2 (for web interface)
 * This runs asynchronously and doesn't wait for completion
 */
export async function triggerPM2Restart(processName: string = 'xeokey', scriptPath: string = 'src/server.ts'): Promise<{ success: boolean; error?: string }> {
  logger.info('🔄 Triggering PM2 restart after update...');
  return await restartWithPM2(processName, scriptPath);
}

