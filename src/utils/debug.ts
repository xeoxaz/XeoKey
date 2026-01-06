/**
 * Debug logging utilities
 * Provides conditional debug logging based on environment configuration
 */

import { isDebugMode } from './logger';

/**
 * Conditionally logs a debug message only if debug mode is enabled
 * @param logger - The logger instance to use
 * @param message - The message to log
 * @param ...args - Additional arguments to pass to the logger
 */
export function debugLog(
  logger: { debug: (...args: any[]) => void },
  message: string,
  ...args: any[]
): void {
  if (isDebugMode()) {
    logger.debug(message, ...args);
  }
}

/**
 * Conditionally logs a debug message with a function (lazy evaluation)
 * Useful for expensive debug operations that should only run in debug mode
 * @param logger - The logger instance to use
 * @param messageFn - Function that returns the message (only called in debug mode)
 * @param ...args - Additional arguments to pass to the logger
 */
export function debugLogLazy(
  logger: { debug: (...args: any[]) => void },
  messageFn: () => string,
  ...args: any[]
): void {
  if (isDebugMode()) {
    logger.debug(messageFn(), ...args);
  }
}

