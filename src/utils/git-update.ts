import { logger } from './logger';
import { spawn } from 'bun';
import { existsSync } from 'fs';

export interface UpdateStatus {
  hasUpdates: boolean;
  currentCommit?: string;
  remoteCommit?: string;
  error?: string;
  isGitRepo?: boolean;
}

let cachedUpdateStatus: UpdateStatus | null = null;
let lastCheckTime: number = 0;
const CACHE_DURATION = 60000; // Cache for 1 minute

/**
 * Check if we're in a git repository
 */
function isGitRepository(): boolean {
  return existsSync('.git') || existsSync('../.git');
}

/**
 * Get current git commit hash
 */
async function getCurrentCommit(): Promise<string | null> {
  try {
    const proc = spawn(['git', 'rev-parse', 'HEAD'], {
      stdout: 'pipe',
      stderr: 'pipe',
    });

    const output = await new Response(proc.stdout).text();
    const error = await new Response(proc.stderr).text();

    if (error.trim()) {
      logger.debug(`Git current commit error: ${error}`);
      return null;
    }

    return output.trim() || null;
  } catch (error: any) {
    logger.debug(`Error getting current commit: ${error.message || error}`);
    return null;
  }
}

/**
 * Fetch latest changes from remote (without merging)
 */
async function fetchRemote(): Promise<boolean> {
  try {
    const proc = spawn(['git', 'fetch', 'origin'], {
      stdout: 'pipe',
      stderr: 'pipe',
    });

    const output = await new Response(proc.stdout).text();
    const error = await new Response(proc.stderr).text();

    // git fetch doesn't output anything on success typically
    if (error && !error.includes('Already up to date') && !error.trim() === '') {
      logger.warn(`Git fetch error: ${error}`);
      return false;
    }

    return true;
  } catch (error: any) {
    logger.error(`Error fetching from remote: ${error.message || error}`);
    return false;
  }
}

/**
 * Get remote commit hash for current branch
 */
async function getRemoteCommit(): Promise<string | null> {
  try {
    // Get current branch name
    const branchProc = spawn(['git', 'branch', '--show-current'], {
      stdout: 'pipe',
      stderr: 'pipe',
    });

    const branchOutput = await new Response(branchProc.stdout).text();
    const branch = branchOutput.trim();

    if (!branch) {
      logger.debug('No git branch found');
      return null;
    }

    // Get remote commit for this branch
    const remoteProc = spawn(['git', 'rev-parse', `origin/${branch}`], {
      stdout: 'pipe',
      stderr: 'pipe',
    });

    const remoteOutput = await new Response(remoteProc.stdout).text();
    const error = await new Response(remoteProc.stderr).text();

    if (error.trim()) {
      logger.debug(`Git remote commit error: ${error}`);
      return null;
    }

    return remoteOutput.trim() || null;
  } catch (error: any) {
    logger.debug(`Error getting remote commit: ${error.message || error}`);
    return null;
  }
}

/**
 * Check if updates are available from GitHub
 */
export async function checkForUpdates(forceRefresh: boolean = false): Promise<UpdateStatus> {
  // Return cached result if still valid
  const now = Date.now();
  if (!forceRefresh && cachedUpdateStatus && (now - lastCheckTime) < CACHE_DURATION) {
    return cachedUpdateStatus;
  }

  const result: UpdateStatus = {
    hasUpdates: false,
    isGitRepo: false,
  };

  try {
    // Check if we're in a git repository
    if (!isGitRepository()) {
      result.isGitRepo = false;
      result.error = 'Not a git repository';
      cachedUpdateStatus = result;
      lastCheckTime = now;
      return result;
    }

    result.isGitRepo = true;

    // Fetch latest changes from remote
    const fetchSuccess = await fetchRemote();
    if (!fetchSuccess) {
      result.error = 'Failed to fetch from remote';
      cachedUpdateStatus = result;
      lastCheckTime = now;
      return result;
    }

    // Get current and remote commit hashes
    const currentCommit = await getCurrentCommit();
    const remoteCommit = await getRemoteCommit();

    if (!currentCommit || !remoteCommit) {
      result.error = 'Could not determine commit status';
      result.currentCommit = currentCommit || undefined;
      result.remoteCommit = remoteCommit || undefined;
      cachedUpdateStatus = result;
      lastCheckTime = now;
      return result;
    }

    result.currentCommit = currentCommit;
    result.remoteCommit = remoteCommit;
    result.hasUpdates = currentCommit !== remoteCommit;

    cachedUpdateStatus = result;
    lastCheckTime = now;

    if (result.hasUpdates) {
      logger.info(`Update available: current=${currentCommit.substring(0, 7)}, remote=${remoteCommit.substring(0, 7)}`);
    }
  } catch (error: any) {
    logger.error(`Error checking for updates: ${error.message || error}`);
    result.error = error.message || 'Unknown error';
  }

  return result;
}

/**
 * Pull latest changes from GitHub and return success status
 */
export async function pullUpdates(): Promise<{ success: boolean; error?: string; commit?: string }> {
  try {
    if (!isGitRepository()) {
      return { success: false, error: 'Not a git repository' };
    }

    logger.info('Pulling updates from GitHub...');

    // Fetch first to ensure we have latest refs
    const fetchSuccess = await fetchRemote();
    if (!fetchSuccess) {
      return { success: false, error: 'Failed to fetch from remote' };
    }

    // Pull changes
    const proc = spawn(['git', 'pull', 'origin'], {
      stdout: 'pipe',
      stderr: 'pipe',
    });

    const output = await new Response(proc.stdout).text();
    const error = await new Response(proc.stderr).text();

    const exitCode = await proc.exited;

    if (exitCode !== 0) {
      logger.error(`Git pull failed: ${error || output}`);
      return { success: false, error: error || 'Git pull failed' };
    }

    // Get the new commit hash
    const newCommit = await getCurrentCommit();

    logger.info(`Successfully pulled updates. New commit: ${newCommit?.substring(0, 7) || 'unknown'}`);

    // Clear cache so next check is fresh
    cachedUpdateStatus = null;
    lastCheckTime = 0;

    return { success: true, commit: newCommit || undefined };
  } catch (error: any) {
    logger.error(`Error pulling updates: ${error.message || error}`);
    return { success: false, error: error.message || 'Unknown error' };
  }
}

/**
 * Trigger server restart
 * This will exit the process, expecting a process manager (PM2, systemd, etc.) to restart it
 * For manual runs, the user should use a restart script or process manager
 */
export function triggerRestart(): void {
  logger.info('🔄 Triggering server restart after update...');
  logger.info('Note: If running manually, restart the server using your start script or process manager.');
  
  // Give a brief moment for the response to be sent
  setTimeout(() => {
    // Exit with code 0 to indicate normal restart
    // Process managers will automatically restart if configured (PM2, systemd with Restart=always, etc.)
    process.exit(0);
  }, 1000);
}

