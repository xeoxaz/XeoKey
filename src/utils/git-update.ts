import { logger } from './logger';
import { spawn } from 'bun';
import { existsSync } from 'fs';

export interface UpdateStatus {
  hasUpdates: boolean;
  currentCommit?: string;
  remoteCommit?: string;
  error?: string;
  isGitRepo?: boolean;
  commitMessages?: string[]; // Commit messages between current and remote
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
 * Get commit messages between two commits
 */
async function getCommitMessages(fromCommit: string, toCommit: string): Promise<string[]> {
  try {
    const proc = spawn(['git', 'log', '--pretty=format:%s', `${fromCommit}..${toCommit}`], {
      stdout: 'pipe',
      stderr: 'pipe',
    });

    const output = await new Response(proc.stdout).text();
    const error = await new Response(proc.stderr).text();

    if (error.trim() && !error.includes('not a git repository')) {
      logger.debug(`Git log error: ${error}`);
      return [];
    }

    // Split by newlines and filter empty strings
    const messages = output.trim().split('\n').filter(msg => msg.trim() !== '');
    return messages;
  } catch (error: any) {
    logger.debug(`Error getting commit messages: ${error.message || error}`);
    return [];
  }
}

/**
 * Get recent commit messages (patch notes) from the repository
 */
export async function getPatchNotes(limit: number = 10): Promise<string[]> {
  try {
    if (!isGitRepository()) {
      return [];
    }

    const proc = spawn(['git', 'log', '--pretty=format:%s', `-${limit}`], {
      stdout: 'pipe',
      stderr: 'pipe',
    });

    const output = await new Response(proc.stdout).text();
    const error = await new Response(proc.stderr).text();

    if (error.trim()) {
      logger.debug(`Git log error for patch notes: ${error}`);
      return [];
    }

    // Split by newlines and filter empty strings
    const messages = output.trim().split('\n').filter(msg => msg.trim() !== '');
    return messages;
  } catch (error: any) {
    logger.debug(`Error getting patch notes: ${error.message || error}`);
    return [];
  }
}

/**
 * Get commit messages between two commits
 */
async function getCommitMessages(fromCommit: string, toCommit: string): Promise<string[]> {
  try {
    const proc = spawn(['git', 'log', '--pretty=format:%s', `${fromCommit}..${toCommit}`], {
      stdout: 'pipe',
      stderr: 'pipe',
    });

    const output = await new Response(proc.stdout).text();
    const error = await new Response(proc.stderr).text();

    if (error.trim() && !error.includes('not a git repository')) {
      logger.debug(`Git log error: ${error}`);
      return [];
    }

    // Split by newlines and filter empty strings
    const messages = output.trim().split('\n').filter(msg => msg.trim() !== '');
    return messages;
  } catch (error: any) {
    logger.debug(`Error getting commit messages: ${error.message || error}`);
    return [];
  }
}

/**
 * Get recent commit messages (patch notes) from the repository
 */
export async function getPatchNotes(limit: number = 10): Promise<string[]> {
  try {
    if (!isGitRepository()) {
      return [];
    }

    const proc = spawn(['git', 'log', '--pretty=format:%s', `-${limit}`], {
      stdout: 'pipe',
      stderr: 'pipe',
    });

    const output = await new Response(proc.stdout).text();
    const error = await new Response(proc.stderr).text();

    if (error.trim()) {
      logger.debug(`Git log error for patch notes: ${error}`);
      return [];
    }

    // Split by newlines and filter empty strings
    const messages = output.trim().split('\n').filter(msg => msg.trim() !== '');
    return messages;
  } catch (error: any) {
    logger.debug(`Error getting patch notes: ${error.message || error}`);
    return [];
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
    commitMessages: [],
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

    // If updates are available, get commit messages
    if (result.hasUpdates) {
      result.commitMessages = await getCommitMessages(currentCommit, remoteCommit);
      logger.info(`Update available: current=${currentCommit.substring(0, 7)}, remote=${remoteCommit.substring(0, 7)}, ${result.commitMessages.length} commits`);
    }

    cachedUpdateStatus = result;
    lastCheckTime = now;
  } catch (error: any) {
    logger.error(`Error checking for updates: ${error.message || error}`);
    result.error = error.message || 'Unknown error';
  }

  return result;
}

/**
 * Prepare for restart - the restart script will handle git pull
 * This just validates we're ready to restart
 */
export async function prepareRestart(): Promise<{ success: boolean; error?: string }> {
  try {
    if (!isGitRepository()) {
      return { success: false, error: 'Not a git repository' };
    }

    logger.info('Preparing for server restart (script will handle git pull)...');
    return { success: true };
  } catch (error: any) {
    logger.error(`Error preparing restart: ${error.message || error}`);
    return { success: false, error: error.message || 'Unknown error' };
  }
}

/**
 * Trigger server restart - uses internal process manager only
 */
export async function triggerRestart(): Promise<void> {
  logger.info('🔄 Triggering server restart after update...');

  try {
    // Check if we're running under internal process manager
    // The manager sets this environment variable
    if (process.env.XEOKEY_MANAGED === 'true') {
      logger.info('Running under process manager, signaling restart...');
      // Write a restart flag file that the manager watches
      const { writeFile } = await import('fs/promises');
      const { join } = await import('path');

      // Determine project root - if we're in src/, go up one level
      let projectRoot = process.cwd();
      if (projectRoot.endsWith('src') || projectRoot.endsWith('src\\') || projectRoot.endsWith('src/')) {
        projectRoot = join(projectRoot, '..');
      }

      const restartFlag = join(projectRoot, '.restart-requested');
      await writeFile(restartFlag, Date.now().toString(), 'utf-8');
      logger.info('Restart flag set, manager will handle restart');
      // Exit gracefully - manager will restart us
      setTimeout(() => {
        process.exit(0);
      }, 1000);
      return;
    }

    // Try internal process manager
    try {
      const { restartWithProcessManager } = await import('./process-manager');
      const result = await restartWithProcessManager();
      if (result.success) {
        logger.info('Process manager restart successful');
        return;
      } else {
        logger.error(`Process manager restart failed: ${result.error}`);
      }
    } catch (error: any) {
      logger.error(`Process manager not available: ${error.message || error}`);
    }

    // If process manager not available, just exit
    // User should start the host manager manually
    logger.warn('Process manager not available. Please restart manually using: bun run host');
    logger.info('Exiting...');
    setTimeout(() => {
      process.exit(0);
    }, 1000);
  } catch (error: any) {
    logger.error(`Error triggering restart: ${error.message || error}`);
    logger.info('Please restart manually using: bun run host');
    setTimeout(() => {
      process.exit(0);
    }, 1000);
  }
}

