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
  private reportInterval: number = 60000; // 1 minute
  private reportTimer: NodeJS.Timeout | null = null;
  private isStarted: boolean = false;

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
    if (reportIntervalMs) {
      this.reportInterval = reportIntervalMs;
    }
    
    this.reportTimer = setInterval(() => {
      this.reportStats();
    }, this.reportInterval);
    
    logger.info('Fallback logger started (reports every minute)');
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
    
    // Final report
    this.reportStats(true);
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
    
    // Only log if this is the first fallback or if we haven't logged in a while
    const timeSinceLastReport = Date.now() - this.stats.lastReport.getTime();
    if (this.stats.fallbackDecryptions === 1 || timeSinceLastReport > this.reportInterval * 2) {
      this.reportStats();
    }
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
    
    let summary = `🔑 Fallback Key Usage Report:\n`;
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
      summary += `   💡 Consider running auto re-encryption to migrate to current key\n`;
    }
    
    return summary;
  }

  /**
   * Report current stats
   */
  private reportStats(isFinal: boolean = false): void {
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
  // Start with 1-minute intervals
  fallbackLogger.start(60000);
}
