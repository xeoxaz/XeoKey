import { Monitor } from '@frostal/monitor';

// Shared logger instance for the application
export const logger = new Monitor('XeoKey', {
  enableFileLogging: true,
  logFilePath: './logs/server.log',
  logLevel: 'info'
});

// Specialized loggers for different modules
export const dbLogger = new Monitor('Database', {
  enableFileLogging: true,
  logFilePath: './logs/server.log',
  logLevel: 'info'
});

export const passwordLogger = new Monitor('Password', {
  enableFileLogging: true,
  logFilePath: './logs/server.log',
  logLevel: 'info'
});

export const analyticsLogger = new Monitor('Analytics', {
  enableFileLogging: true,
  logFilePath: './logs/server.log',
  logLevel: 'info'
});

