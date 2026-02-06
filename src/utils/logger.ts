import { mkdir, writeFile, appendFile } from 'fs/promises';
import { dirname } from 'path';

type LogLevel = 'debug' | 'info' | 'warn' | 'error';

interface LoggerOptions {
  enableFileLogging?: boolean;
  logFilePath?: string;
  logLevel?: LogLevel;
}

// Get log level from environment or default to 'info'
function getLogLevel(): LogLevel {
  const logLevelEnv = process.env.LOG_LEVEL || process.env.LOGLEVEL || '';
  const validLogLevels: LogLevel[] = ['debug', 'info', 'warn', 'error'];
  const nodeEnv = process.env.NODE_ENV || 'development';

  if (logLevelEnv && validLogLevels.includes(logLevelEnv.toLowerCase() as LogLevel)) {
    return logLevelEnv.toLowerCase() as LogLevel;
  }

  // Default: info in production, info in development
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

// Log level priority
const LOG_LEVELS: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3
};

class SimpleLogger {
  private name: string;
  private options: LoggerOptions;
  private logLevel: LogLevel;

  constructor(name: string, options: LoggerOptions = {}) {
    this.name = name;
    this.options = {
      enableFileLogging: true,
      logFilePath: './logs/server.log',
      logLevel: getLogLevel(),
      ...options
    };
    this.logLevel = this.options.logLevel || getLogLevel();

    // Ensure log directory exists
    if (this.options.enableFileLogging && this.options.logFilePath) {
      this.ensureLogDirectory(this.options.logFilePath).catch(err => {
        console.error(`Failed to create log directory: ${err}`);
      });
    }
  }

  private async ensureLogDirectory(filePath: string): Promise<void> {
    try {
      const dir = dirname(filePath);
      await mkdir(dir, { recursive: true });
    } catch (error) {
      // Directory might already exist, ignore error
    }
  }

  private shouldLog(level: LogLevel): boolean {
    return LOG_LEVELS[level] >= LOG_LEVELS[this.logLevel];
  }

  private formatTime(): string {
    const now = new Date();
    const hours = String(now.getHours()).padStart(2, '0');
    const minutes = String(now.getMinutes()).padStart(2, '0');
    const seconds = String(now.getSeconds()).padStart(2, '0');
    return `${hours}:${minutes}:${seconds}`;
  }

  private formatMessage(level: LogLevel, message: string, ...args: any[]): string {
    const timestamp = this.formatTime();
    const formattedArgs = args.length > 0 ? ' ' + args.map(arg =>
      typeof arg === 'object' ? JSON.stringify(arg) : String(arg)
    ).join(' ') : '';
    
    return `[${timestamp}] ${message}${formattedArgs}`;
  }

  private async writeToFile(message: string): Promise<void> {
    if (!this.options.enableFileLogging || !this.options.logFilePath) {
      return;
    }

    try {
      await appendFile(this.options.logFilePath, message + '\n', 'utf8');
    } catch (error) {
      // Silently fail file logging to avoid breaking the application
      console.error(`Failed to write to log file: ${error}`);
    }
  }

  private log(level: LogLevel, message: string, ...args: any[]): void {
    if (!this.shouldLog(level)) {
      return;
    }

    const timestamp = this.formatTime();
    const formattedArgs = args.length > 0 ? ' ' + args.map(arg =>
      typeof arg === 'object' ? JSON.stringify(arg) : String(arg)
    ).join(' ') : '';

    // More vibrant and friendly colors
    const colors: Record<LogLevel, string> = {
      debug: '\x1b[38;5;147m', // Soft purple
      info: '\x1b[38;5;82m',  // Bright green
      warn: '\x1b[38;5;226m', // Bright yellow
      error: '\x1b[38;5;203m' // Coral red
    };
    const reset = '\x1b[0m';
    const gray = '\x1b[38;5;245m'; // Soft gray

    // Clean format with just timestamp and message
    const consoleMessage = `${gray}[${timestamp}]${reset} ${colors[level]}${message}${formattedArgs}${reset}`;

    console.log(consoleMessage);

    // File logging (plain format, async, don't wait)
    const fileMessage = `[${timestamp}] [${level.toUpperCase()}] [${this.name}] ${message}${formattedArgs}`;
    this.writeToFile(fileMessage).catch(() => {
      // Ignore file write errors
    });
  }

  debug(message: string, ...args: any[]): void {
    this.log('debug', message, ...args);
  }

  info(message: string, ...args: any[]): void {
    this.log('info', message, ...args);
  }

  warn(message: string, ...args: any[]): void {
    this.log('warn', message, ...args);
  }

  error(message: string, ...args: any[]): void {
    this.log('error', message, ...args);
  }
}

const logLevel = getLogLevel();

// Shared logger instance for the application
export const logger = new SimpleLogger('XeoKey', {
  enableFileLogging: true,
  logFilePath: './logs/server.log',
  logLevel
});

// Specialized loggers with more personality
export const dbLogger = new SimpleLogger('Database', {
  enableFileLogging: true,
  logFilePath: './logs/server.log',
  logLevel
});

export const passwordLogger = new SimpleLogger('Password', {
  enableFileLogging: true,
  logFilePath: './logs/server.log',
  logLevel
});

export const analyticsLogger = new SimpleLogger('Analytics', {
  enableFileLogging: true,
  logFilePath: './logs/server.log',
  logLevel
});

// Fun conversational helper functions
export const chat = {
  hey: (msg: string, ...args: any[]) => logger.info(msg, ...args),
  btw: (msg: string, ...args: any[]) => logger.debug(msg, ...args),
  fyi: (msg: string, ...args: any[]) => logger.info(msg, ...args),
  whoa: (msg: string, ...args: any[]) => logger.warn(msg, ...args),
  yikes: (msg: string, ...args: any[]) => logger.error(msg, ...args),
  awesome: (msg: string, ...args: any[]) => logger.info(`🎉 ${msg}`, ...args)
};
