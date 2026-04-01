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

function getConsoleLogLevel(): LogLevel {
  const consoleLevelEnv = process.env.CONSOLE_LOG_LEVEL || '';
  const validLogLevels: LogLevel[] = ['debug', 'info', 'warn', 'error'];

  if (consoleLevelEnv && validLogLevels.includes(consoleLevelEnv.toLowerCase() as LogLevel)) {
    return consoleLevelEnv.toLowerCase() as LogLevel;
  }

  // Keep console concise by default.
  return 'warn';
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
  private consoleLogLevel: LogLevel;
  private static readonly CONSOLE_MAX_LEN = 220;

  constructor(name: string, options: LoggerOptions = {}) {
    this.name = name;
    this.options = {
      enableFileLogging: true,
      logFilePath: './logs/server.log',
      logLevel: getLogLevel(),
      ...options
    };
    this.logLevel = this.options.logLevel || getLogLevel();
    this.consoleLogLevel = getConsoleLogLevel();

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

  private shouldLogToConsole(level: LogLevel): boolean {
    return LOG_LEVELS[level] >= LOG_LEVELS[this.consoleLogLevel];
  }

  private formatTime(): string {
    const now = new Date();
    const hours = String(now.getHours()).padStart(2, '0');
    const minutes = String(now.getMinutes()).padStart(2, '0');
    const seconds = String(now.getSeconds()).padStart(2, '0');
    return `${hours}:${minutes}:${seconds}`;
  }

  private stripEmojis(text: string): string {
    // Remove common emoji/pictograph ranges and variation selectors.
    return text
      .replace(/[\u{1F300}-\u{1FAFF}]/gu, '')
      .replace(/[\u{2600}-\u{27BF}]/gu, '')
      .replace(/[\u{FE0E}\u{FE0F}]/gu, '');
  }

  private compactArg(arg: any): string {
    if (arg === null || arg === undefined) {
      return String(arg);
    }

    if (arg instanceof Error) {
      return arg.message;
    }

    if (typeof arg === 'string') {
      return this.stripEmojis(arg).replace(/\s+/g, ' ').trim();
    }

    if (typeof arg === 'number' || typeof arg === 'boolean') {
      return String(arg);
    }

    if (Array.isArray(arg)) {
      return `[${arg.length} items]`;
    }

    if (typeof arg === 'object') {
      const keys = Object.keys(arg).slice(0, 4);
      return `{${keys.join(',')}}`;
    }

    return String(arg);
  }

  private clip(text: string, maxLen: number = SimpleLogger.CONSOLE_MAX_LEN): string {
    const normalized = this.stripEmojis(text).replace(/\s+/g, ' ').trim();
    if (normalized.length <= maxLen) {
      return normalized;
    }
    return normalized.slice(0, maxLen - 1) + '...';
  }

  private formatMessage(_level: LogLevel, message: string, ...args: any[]): string {
    const timestamp = this.formatTime();
    const compactMessage = this.clip(message);
    const formattedArgs = args.length > 0
      ? ' ' + args.map(arg => this.compactArg(arg)).join(' ')
      : '';

    return `[${timestamp}] ${compactMessage}${this.clip(formattedArgs, 100)}`;
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

    // Slate-gray for all console output with subtle level tag.
    const reset = '\x1b[0m';
    const slateGray = '\x1b[38;5;102m';
    const dimSlate = '\x1b[38;5;245m';

    if (this.shouldLogToConsole(level)) {
      const compact = this.formatMessage(level, message, ...args);
      const levelTag = level.toUpperCase().padEnd(5, ' ');
      const consoleMessage = `${dimSlate}${levelTag}${reset} ${slateGray}${compact}${reset}`;
      console.log(consoleMessage);
    }

    // File logging (plain format, async, don't wait)
    const timestamp = this.formatTime();
    const fileMessage = `[${timestamp}] [${level.toUpperCase()}] [${this.name}] ${this.clip(message, 500)}`;
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
