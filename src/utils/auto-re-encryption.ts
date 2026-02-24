import { logger } from './logger';
import { checkFallbackKeyUsage, reEncryptAllData, generateReEncryptionReport } from './re-encryption';
import { getDatabase } from '../db/mongodb';

export interface AutoReEncryptionConfig {
  enabled: boolean;
  threshold: number; // Percentage of entries using fallback keys to trigger auto-re-encryption
  batchSize: number; // Number of entries to process at once
  delayBetweenBatches: number; // Milliseconds to wait between batches
  requireConfirmation: boolean; // Whether to require user confirmation
}

export interface AutoReEncryptionStatus {
  enabled: boolean;
  isRunning: boolean;
  lastCheck?: Date;
  fallbackUsage: {
    passwordsUsingFallback: number;
    notesUsingFallback: number;
    totpUsingFallback: number;
    totalEntries: number;
    percentage: number;
  };
  lastReEncryption?: {
    date: Date;
    result: any;
    success: boolean;
  };
}

const DEFAULT_CONFIG: AutoReEncryptionConfig = {
  enabled: true,
  threshold: 5, // Trigger if >5% of entries use fallback keys
  batchSize: 10,
  delayBetweenBatches: 1000,
  requireConfirmation: false, // Auto-approve for now
};

let autoReEncryptionStatus: AutoReEncryptionStatus = {
  enabled: DEFAULT_CONFIG.enabled,
  isRunning: false,
  fallbackUsage: {
    passwordsUsingFallback: 0,
    notesUsingFallback: 0,
    totpUsingFallback: 0,
    totalEntries: 0,
    percentage: 0,
  },
};

/**
 * Check if automatic re-encryption should be triggered
 */
export async function checkAutoReEncryption(): Promise<{
  shouldTrigger: boolean;
  status: AutoReEncryptionStatus;
  recommendation: string;
}> {
  if (!DEFAULT_CONFIG.enabled || autoReEncryptionStatus.isRunning) {
    return {
      shouldTrigger: false,
      status: autoReEncryptionStatus,
      recommendation: 'Auto re-encryption is disabled or already running',
    };
  }

  try {
    // Check fallback key usage
    const fallbackUsage = await checkFallbackKeyUsage();
    const percentage = fallbackUsage.totalEntries > 0 
      ? (fallbackUsage.passwordsUsingFallback + fallbackUsage.notesUsingFallback + fallbackUsage.totpUsingFallback) / fallbackUsage.totalEntries * 100
      : 0;

    // Update status
    autoReEncryptionStatus.fallbackUsage = {
      ...fallbackUsage,
      percentage,
    };
    autoReEncryptionStatus.lastCheck = new Date();

    // Determine if re-encryption should be triggered
    const shouldTrigger = percentage >= DEFAULT_CONFIG.threshold;
    
    let recommendation = '';
    if (shouldTrigger) {
      recommendation = `Auto re-encryption recommended: ${percentage.toFixed(1)}% of entries use fallback keys (threshold: ${DEFAULT_CONFIG.threshold}%)`;
    } else {
      recommendation = `Auto re-encryption not needed: ${percentage.toFixed(1)}% of entries use fallback keys (threshold: ${DEFAULT_CONFIG.threshold}%)`;
    }

    return {
      shouldTrigger,
      status: autoReEncryptionStatus,
      recommendation,
    };

  } catch (error: any) {
    logger.error(`Auto re-encryption check failed: ${error.message || error}`);
    return {
      shouldTrigger: false,
      status: autoReEncryptionStatus,
      recommendation: `Check failed: ${error.message || 'Unknown error'}`,
    };
  }
}

/**
 * Perform automatic re-encryption
 */
export async function performAutoReEncryption(): Promise<{
  success: boolean;
  result: any;
  message: string;
}> {
  if (autoReEncryptionStatus.isRunning) {
    return {
      success: false,
      result: null,
      message: 'Auto re-encryption is already running',
    };
  }

  try {
    autoReEncryptionStatus.isRunning = true;
    logger.info('🔄 Starting automatic re-encryption...');

    // Check fallback usage first
    const fallbackUsage = await checkFallbackKeyUsage();
    const percentage = fallbackUsage.totalEntries > 0 
      ? (fallbackUsage.passwordsUsingFallback + fallbackUsage.notesUsingFallback + fallbackUsage.totpUsingFallback) / fallbackUsage.totalEntries * 100
      : 0;

    if (percentage < DEFAULT_CONFIG.threshold) {
      autoReEncryptionStatus.isRunning = false;
      return {
        success: false,
        result: null,
        message: `Re-encryption not needed: ${percentage.toFixed(1)}% fallback usage (threshold: ${DEFAULT_CONFIG.threshold}%)`,
      };
    }

    logger.info(`Auto re-encryption triggered: ${percentage.toFixed(1)}% entries use fallback keys`);

    // Perform re-encryption
    const result = await reEncryptAllData();
    const report = generateReEncryptionReport(result);

    // Update status
    autoReEncryptionStatus.lastReEncryption = {
      date: new Date(),
      result,
      success: result.passwords.failed === 0 && result.notes.failed === 0 && result.totp.failed === 0,
    };

    const totalSuccess = result.passwords.success + result.notes.success + result.totp.success;
    const totalFailed = result.passwords.failed + result.notes.failed + result.totp.failed;
    const totalItems = totalSuccess + totalFailed;

    autoReEncryptionStatus.isRunning = false;

    if (totalFailed === 0) {
      logger.info(`✅ Auto re-encryption completed successfully: ${totalSuccess}/${totalItems} items re-encrypted`);
      return {
        success: true,
        result,
        message: `Successfully re-encrypted ${totalSuccess} items with current encryption key`,
      };
    } else {
      logger.warn(`⚠️ Auto re-encryption completed with ${totalFailed} failures out of ${totalItems} items`);
      return {
        success: false,
        result,
        message: `Re-encryption completed with ${totalFailed} failures. Check logs for details.`,
      };
    }

  } catch (error: any) {
    autoReEncryptionStatus.isRunning = false;
    logger.error(`Auto re-encryption failed: ${error.message || error}`);
    return {
      success: false,
      result: null,
      message: `Auto re-encryption failed: ${error.message || 'Unknown error'}`,
    };
  }
}

/**
 * Get current auto re-encryption status
 */
export function getAutoReEncryptionStatus(): AutoReEncryptionStatus {
  return autoReEncryptionStatus;
}

/**
 * Configure auto re-encryption settings
 */
export function configureAutoReEncryption(config: Partial<AutoReEncryptionConfig>): void {
  Object.assign(DEFAULT_CONFIG, config);
  autoReEncryptionStatus.enabled = DEFAULT_CONFIG.enabled;
  logger.info(`Auto re-encryption configuration updated: enabled=${DEFAULT_CONFIG.enabled}, threshold=${DEFAULT_CONFIG.threshold}%`);
}

/**
 * Schedule automatic re-encryption check
 */
export function scheduleAutoReEncryptionCheck(): void {
  // Check every hour
  setInterval(async () => {
    try {
      const { shouldTrigger, recommendation } = await checkAutoReEncryption();
      
      if (shouldTrigger && !DEFAULT_CONFIG.requireConfirmation) {
        logger.info('🔄 Auto re-encryption threshold reached, starting automatic re-encryption...');
        await performAutoReEncryption();
      } else {
        logger.debug(`Auto re-encryption check: ${recommendation}`);
      }
    } catch (error: any) {
      logger.error(`Scheduled auto re-encryption check failed: ${error.message || error}`);
    }
  }, 60 * 60 * 1000); // 1 hour

  logger.info('Auto re-encryption scheduler started (checks every hour)');
}

/**
 * Generate HTML status report for auto re-encryption
 */
export function generateAutoReEncryptionStatusHTML(): string {
  const { fallbackUsage, isRunning, lastReEncryption } = autoReEncryptionStatus;
  
  return `
    <div style="background: #1d1d1d; border: 1px solid #3d3d3d; padding: 1rem; border-radius: 8px; margin-bottom: 1rem;">
      <h3 style="margin-top: 0; color: #9db4d4; font-size: 1rem;">🔄 Auto Re-Encryption Status</h3>
      
      <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 1rem;">
        <span style="color: ${isRunning ? '#d4a5a5' : '#7fb069'}; font-size: 0.8rem;">
          ${isRunning ? '⏳ Running' : '✅ Idle'}
        </span>
        <span style="color: #888; font-size: 0.8rem;">
          Enabled: ${DEFAULT_CONFIG.enabled ? 'Yes' : 'No'}
        </span>
        <span style="color: #888; font-size: 0.8rem;">
          Threshold: ${DEFAULT_CONFIG.threshold}%
        </span>
      </div>

      <div style="margin-bottom: 1rem;">
        <h4 style="margin: 0 0 0.5rem 0; color: #9db4d4; font-size: 0.9rem;">Fallback Key Usage</h4>
        <div style="display: flex; gap: 1rem; font-size: 0.8rem;">
          <span style="color: ${fallbackUsage.percentage >= DEFAULT_CONFIG.threshold ? '#d47d7d' : '#7fb069'}">
            ${fallbackUsage.percentage.toFixed(1)}%
          </span>
          <span style="color: #888;">
            (${fallbackUsage.passwordsUsingFallback + fallbackUsage.notesUsingFallback + fallbackUsage.totpUsingFallback}/${fallbackUsage.totalEntries})
          </span>
        </div>
      </div>

      ${lastReEncryption ? `
        <div style="margin-bottom: 1rem;">
          <h4 style="margin: 0 0 0.5rem 0; color: #9db4d4; font-size: 0.9rem;">Last Re-Encryption</h4>
          <div style="font-size: 0.8rem; color: #888;">
            <div>Date: ${lastReEncryption.date.toLocaleString()}</div>
            <div>Status: ${lastReEncryption.success ? '✅ Success' : '⚠️ Partial Success'}</div>
          </div>
        </div>
      ` : ''}

      <div style="margin-top: 1rem;">
        <button onclick="triggerAutoReEncryption()" style="background: #4d6d4d; color: #9db4d4; padding: 0.5rem 1rem; border: 1px solid #5d7d5d; border-radius: 4px; cursor: pointer; font-size: 0.8rem;" ${isRunning ? 'disabled' : ''}>
          ${isRunning ? 'Re-Encryption Running...' : 'Trigger Re-Encryption Now'}
        </button>
      </div>

      <script>
        async function triggerAutoReEncryption() {
          const button = event.target;
          button.disabled = true;
          button.textContent = 'Starting...';
          
          try {
            const response = await fetch('/api/auto-re-encryption/trigger', { method: 'POST' });
            const result = await response.json();
            
            if (result.success) {
              button.textContent = 'Completed Successfully';
              button.style.background = '#4d7d4d';
              setTimeout(() => location.reload(), 2000);
            } else {
              button.textContent = 'Failed';
              button.style.background = '#7d4d4d';
              alert('Re-encryption failed: ' + result.message);
            }
          } catch (error) {
            button.textContent = 'Error';
            button.style.background = '#7d4d4d';
            alert('Error: ' + error.message);
          }
        }
      </script>
    </div>
  `;
}
