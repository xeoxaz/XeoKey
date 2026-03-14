import { logger } from './logger';

export interface FallbackStats {
  totalDecryptions: number;
  fallbackDecryptions: number;
  keyUsage: Map<number, number>; // keyIndex -> count
  lastReport: Date;
  startTime: Date;
}

class FallbackLogger {
  private stats: FallbackStats;
  private reportInterval: number = 0; // disabled by default to avoid log spam
  private reportTimer: NodeJS.Timeout | null = null;
  private isStarted: boolean = false;
  private recoveryInProgress: boolean = false;
  private lastRecoveryAttempt: Date | null = null;
  private recoveryCooldownMs: number = 15 * 60 * 1000; // 15 minutes
  private recoveryMinFallbackEvents: number = 25;
  private hasShownFallbackNotice: boolean = false;

  constructor() {
    this.stats = {
      totalDecryptions: 0,
      fallbackDecryptions: 0,
      keyUsage: new Map(),
      lastReport: new Date(),
      startTime: new Date(),
    };
  }

  /**
   * Start the fallback logger
   */
  start(reportIntervalMs?: number): void {
    if (this.isStarted) return;

    this.isStarted = true;
    if (typeof reportIntervalMs === 'number') {
      this.reportInterval = reportIntervalMs;
    }

    // Allow explicit runtime override for detailed interval reporting.
    const envInterval = Number(process.env.XEOKEY_FALLBACK_REPORT_INTERVAL_MS || '');
    if (!Number.isNaN(envInterval) && envInterval >= 0) {
      this.reportInterval = envInterval;
    }

    if (this.reportInterval > 0) {
      this.reportTimer = setInterval(() => {
        this.reportStats();
      }, this.reportInterval);
      logger.info(`Fallback logger started (reports every ${Math.round(this.reportInterval / 1000)}s)`);
    } else {
      logger.info('Fallback logger started (interval reports disabled; auto recovery active)');
    }
  }

  /**
   * Stop the fallback logger
   */
  stop(): void {
    if (this.reportTimer) {
      clearInterval(this.reportTimer);
      this.reportTimer = null;
    }
    this.isStarted = false;

    // Emit final report only when interval reporting is enabled.
    if (this.reportInterval > 0) {
      this.reportStats(true);
    }
    logger.info('Fallback logger stopped');
  }

  /**
   * Log a successful fallback decryption
   */
  logFallbackDecryption(keyIndex: number, totalKeys: number): void {
    this.stats.totalDecryptions++;
    this.stats.fallbackDecryptions++;

    // Track which key was used
    const currentCount = this.stats.keyUsage.get(keyIndex) || 0;
    this.stats.keyUsage.set(keyIndex, currentCount + 1);

    if (!this.hasShownFallbackNotice) {
      this.hasShownFallbackNotice = true;
      logger.warn(`Fallback key decryption detected (key ${keyIndex}/${Math.max(totalKeys, keyIndex)}). Auto recovery service is enabled.`);
    }

    this.maybeTriggerAutoRecovery();
  }

  /**
   * Log a successful primary key decryption
   */
  logPrimaryDecryption(): void {
    this.stats.totalDecryptions++;
    // Don't log primary key decryptions to reduce noise
  }

  /**
   * Get current stats
   */
  getStats(): FallbackStats {
    return { ...this.stats };
  }

  /**
   * Generate a summary report
   */
  private generateSummary(): string {
    const fallbackPercentage = this.stats.totalDecryptions > 0
      ? (this.stats.fallbackDecryptions / this.stats.totalDecryptions * 100).toFixed(1)
      : '0.0';

    const runtime = Date.now() - this.stats.startTime.getTime();
    const runtimeMinutes = Math.floor(runtime / 60000);

    let summary = `Fallback Key Usage Report:\n`;
    summary += `   Runtime: ${runtimeMinutes} minute${runtimeMinutes !== 1 ? 's' : ''}\n`;
    summary += `   Total Decryptions: ${this.stats.totalDecryptions}\n`;
    summary += `   Fallback Decryptions: ${this.stats.fallbackDecryptions} (${fallbackPercentage}%)\n`;

    if (this.stats.keyUsage.size > 0) {
      summary += `   Key Usage:\n`;
      const sortedKeys = Array.from(this.stats.keyUsage.entries()).sort((a, b) => a[0] - b[0]);
      for (const [keyIndex, count] of sortedKeys) {
        const keyName = keyIndex === 0 ? 'Primary' : `Fallback ${keyIndex}`;
        summary += `     ${keyName}: ${count} time${count !== 1 ? 's' : ''}\n`;
      }
    }

    if (this.stats.fallbackDecryptions > 0) {
      summary += `   Auto recovery service is handling migration attempts\n`;
    }

    return summary;
  }

  /**
   * Report current stats
   */
  private reportStats(isFinal: boolean = false): void {
    if (this.reportInterval <= 0 && !isFinal) {
      return;
    }

    if (this.stats.fallbackDecryptions === 0 && !isFinal) {
      return; // Don't report if no fallback usage
    }

    const summary = this.generateSummary();

    if (isFinal) {
      logger.info(`\n${summary}`);
    } else {
      logger.info(summary);
    }

    // Reset stats for next interval (but keep cumulative counts)
    this.stats.lastReport = new Date();
  }

  /**
   * Reset all stats
   */
  reset(): void {
    this.stats = {
      totalDecryptions: 0,
      fallbackDecryptions: 0,
      keyUsage: new Map(),
      lastReport: new Date(),
      startTime: new Date(),
    };
    this.hasShownFallbackNotice = false;
  }

  /**
   * Trigger auto recovery when fallback decryptions are sustained/high.
   */
  private maybeTriggerAutoRecovery(): void {
    if (this.recoveryInProgress) {
      return;
    }

    const now = Date.now();
    if (this.lastRecoveryAttempt && (now - this.lastRecoveryAttempt.getTime()) < this.recoveryCooldownMs) {
      return;
    }

    const fallbackRate = this.stats.totalDecryptions > 0
      ? this.stats.fallbackDecryptions / this.stats.totalDecryptions
      : 0;

    const shouldTrigger =
      this.stats.fallbackDecryptions >= this.recoveryMinFallbackEvents ||
      (this.stats.totalDecryptions >= 20 && fallbackRate >= 0.5);

    if (!shouldTrigger) {
      return;
    }

    this.recoveryInProgress = true;
    this.lastRecoveryAttempt = new Date();

    void this.runAutoRecovery();
  }

  private async runAutoRecovery(): Promise<void> {
    try {
      logger.info('Auto recovery service: starting automatic re-encryption attempt');
      const { performAutoReEncryption } = await import('./auto-re-encryption');
      const result = await performAutoReEncryption();

      if (result.success) {
        logger.info('Auto recovery service: re-encryption completed successfully');
      } else {
        logger.warn(`Auto recovery service: ${result.message}`);
      }
    } catch (error: any) {
      logger.error(`Auto recovery service failed: ${error.message || error}`);
    } finally {
      this.recoveryInProgress = false;
    }
  }
}

// Global instance
const fallbackLogger = new FallbackLogger();

// Export functions for use in other modules
export function startFallbackLogger(reportIntervalMs?: number): void {
  fallbackLogger.start(reportIntervalMs);
}

export function stopFallbackLogger(): void {
  fallbackLogger.stop();
}

export function logFallbackDecryption(keyIndex: number, totalKeys: number): void {
  fallbackLogger.logFallbackDecryption(keyIndex, totalKeys);
}

export function logPrimaryDecryption(): void {
  fallbackLogger.logPrimaryDecryption();
}

export function getFallbackStats(): FallbackStats {
  return fallbackLogger.getStats();
}

export function resetFallbackStats(): void {
  fallbackLogger.reset();
}

// Auto-start the logger when module is imported
if (typeof process !== 'undefined' && process.env.NODE_ENV !== 'test') {
  fallbackLogger.start();
}
