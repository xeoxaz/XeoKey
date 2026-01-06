import { Monitor } from '@frostal/monitor';

// Get log level from environment or default to 'info'
function getLogLevel(): 'debug' | 'info' | 'warn' | 'error' {
  const logLevelEnv = process.env.LOG_LEVEL || process.env.LOGLEVEL || '';
  const validLogLevels: ('debug' | 'info' | 'warn' | 'error')[] = ['debug', 'info', 'warn', 'error'];
  const nodeEnv = process.env.NODE_ENV || 'development';

  if (logLevelEnv && validLogLevels.includes(logLevelEnv.toLowerCase() as any)) {
    return logLevelEnv.toLowerCase() as 'debug' | 'info' | 'warn' | 'error';
  }

  // Default: debug in development, info in production
  return nodeEnv === 'production' ? 'info' : 'info';
}

// Check if debug mode is enabled
export function isDebugMode(): boolean {
  const debugEnv = process.env.DEBUG || process.env.DEBUG_MODE || '';
  const logLevel = getLogLevel();

  return debugEnv.toLowerCase() === 'true' ||
         debugEnv.toLowerCase() === '1' ||
         logLevel === 'debug';
}

const logLevel = getLogLevel();

// Shared logger instance for the application
export const logger = new Monitor('XeoKey', {
  enableFileLogging: true,
  logFilePath: './logs/server.log',
  logLevel
});

// Specialized loggers for different modules
export const dbLogger = new Monitor('Database', {
  enableFileLogging: true,
  logFilePath: './logs/server.log',
  logLevel
});

export const passwordLogger = new Monitor('Password', {
  enableFileLogging: true,
  logFilePath: './logs/server.log',
  logLevel
});

export const analyticsLogger = new Monitor('Analytics', {
  enableFileLogging: true,
  logFilePath: './logs/server.log',
  logLevel
});

