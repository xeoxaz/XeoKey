import { getDatabase } from './mongodb';
import { dbLogger } from '../utils/logger';
import { runIntegrityChecks, quickHealthCheck, IntegrityCheckResult } from './integrity';
import { migrateUserIdToString } from './migrations';
import { createBackup } from './backup';

let lastHealthCheck: Date | null = null;
let lastIntegrityCheck: IntegrityCheckResult | null = null;
let healthCheckInterval: any = null;

/**
 * Run automated health checks on startup and periodically
 */
export async function initializeHealthMonitoring(): Promise<void> {
  dbLogger.info('🏥 Initializing health monitoring system...');

  // Run initial health check
  await runStartupHealthCheck();

  // Set up periodic health checks (every 30 minutes)
  if (healthCheckInterval) {
    clearInterval(healthCheckInterval);
  }

  healthCheckInterval = setInterval(async () => {
    try {
      await runPeriodicHealthCheck();
    } catch (error) {
      dbLogger.error(`Periodic health check failed: ${error}`);
    }
  }, 30 * 60 * 1000); // 30 minutes

  dbLogger.info('✅ Health monitoring initialized');
}

/**
 * Comprehensive health check on startup
 */
export async function runStartupHealthCheck(): Promise<void> {
  dbLogger.info('🔍 Running startup health check...');

  try {
    // Quick health check first
    const quickCheck = await quickHealthCheck();
    if (!quickCheck.healthy) {
      dbLogger.warn('⚠️  Quick health check failed - running full integrity check');
    }

    // Run full integrity check
    const integrityResult = await runIntegrityChecks();
    lastIntegrityCheck = integrityResult;
    lastHealthCheck = new Date();

    if (!integrityResult.success) {
      dbLogger.warn(`⚠️  Integrity check found ${integrityResult.summary.criticalIssues} critical issues`);

      // Attempt automatic recovery for critical issues
      await attemptAutomaticRecovery(integrityResult);
    } else {
      dbLogger.info('✅ Startup health check passed');
    }
  } catch (error: any) {
    dbLogger.error(`Startup health check failed: ${error.message}`);
  }
}

/**
 * Periodic health check (lighter weight)
 */
export async function runPeriodicHealthCheck(): Promise<void> {
  dbLogger.info('🔍 Running periodic health check...');

  try {
    const quickCheck = await quickHealthCheck();
    if (!quickCheck.healthy) {
      dbLogger.warn('⚠️  Periodic health check detected issues - running full check');
      const integrityResult = await runIntegrityChecks();
      lastIntegrityCheck = integrityResult;

      if (!integrityResult.success) {
        await attemptAutomaticRecovery(integrityResult);
      }
    }

    lastHealthCheck = new Date();
  } catch (error: any) {
    dbLogger.error(`Periodic health check failed: ${error.message}`);
  }
}

/**
 * Attempt automatic recovery for detected issues
 */
async function attemptAutomaticRecovery(integrityResult: IntegrityCheckResult): Promise<void> {
  dbLogger.info('🔧 Attempting automatic recovery...');

  // Check if userId format issues can be auto-fixed
  const userIdFormatIssues = integrityResult.checks.userIdFormat.issues.filter(
    i => i.severity === 'critical'
  );

  if (userIdFormatIssues.length > 0) {
    dbLogger.info(`Found ${userIdFormatIssues.length} userId format issues - attempting migration...`);

    try {
      // Create backup before recovery
      dbLogger.info('Creating backup before recovery...');
      await createBackup(
        ['passwords', 'totp', 'users', 'sessions'],
        'automatic',
        undefined,
        'Automatic backup before recovery migration'
      );

      // Run migration
      const migrationResult = await migrateUserIdToString();

      if (migrationResult.success) {
        dbLogger.info('✅ Automatic recovery: userId format migration successful');
      } else {
        dbLogger.error(`❌ Automatic recovery: migration failed - ${migrationResult.errors.join(', ')}`);
      }
    } catch (error: any) {
      dbLogger.error(`Automatic recovery failed: ${error.message}`);
    }
  }

  // Log other issues that require manual intervention
  const otherCriticalIssues = [
    ...integrityResult.checks.passwordAccessibility.issues,
    ...integrityResult.checks.dataConsistency.issues,
    ...integrityResult.checks.encryptionIntegrity.issues,
  ].filter(i => i.severity === 'critical');

  if (otherCriticalIssues.length > 0) {
    dbLogger.warn(`⚠️  ${otherCriticalIssues.length} critical issues require manual intervention`);
    for (const issue of otherCriticalIssues.slice(0, 5)) { // Log first 5
      dbLogger.warn(`  - ${issue.collection}: ${issue.message}`);
    }
  }
}

/**
 * Get last health check results
 */
export function getLastHealthCheck(): { timestamp: Date | null; result: IntegrityCheckResult | null } {
  return {
    timestamp: lastHealthCheck,
    result: lastIntegrityCheck,
  };
}

/**
 * Force a health check (for manual triggers)
 */
export async function forceHealthCheck(): Promise<IntegrityCheckResult> {
  dbLogger.info('🔍 Running forced health check...');
  const result = await runIntegrityChecks();
  lastIntegrityCheck = result;
  lastHealthCheck = new Date();
  return result;
}

/**
 * Validate password operation before execution
 * Runs quick checks to ensure data integrity
 */
export async function validatePasswordOperation(
  userId: string,
  operation: 'create' | 'update' | 'delete'
): Promise<{ valid: boolean; error?: string }> {
  try {
    // Quick validation: ensure user exists
    const { getUserById } = await import('../auth/users');
    const user = await getUserById(userId);

    if (!user) {
      return { valid: false, error: 'User does not exist' };
    }

    // Quick validation: ensure database is accessible
    const quickCheck = await quickHealthCheck();
    if (!quickCheck.healthy) {
      return { valid: false, error: 'Database health check failed' };
    }

    return { valid: true };
  } catch (error: any) {
    return { valid: false, error: error.message };
  }
}

/**
 * Validate after password operation
 * Ensures the operation didn't corrupt data
 */
export async function validateAfterPasswordOperation(
  userId: string,
  entryId?: string
): Promise<{ valid: boolean; error?: string }> {
  try {
    // Verify we can still access passwords for this user
    const { getUserPasswords } = await import('../models/password');
    const passwords = await getUserPasswords(userId);

    // If we have an entryId, verify it's accessible
    if (entryId) {
      const { getPasswordEntry } = await import('../models/password');
      const entry = await getPasswordEntry(entryId, userId);

      if (!entry) {
        return { valid: false, error: 'Created/updated entry is not accessible' };
      }
    }

    return { valid: true };
  } catch (error: any) {
    return { valid: false, error: error.message };
  }
}

/**
 * Stop health monitoring
 */
export function stopHealthMonitoring(): void {
  if (healthCheckInterval) {
    clearInterval(healthCheckInterval);
    healthCheckInterval = null;
  }
}

