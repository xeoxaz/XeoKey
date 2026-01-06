/**
 * Environment variable validation and configuration
 */

import { SESSION_CONFIG } from './constants';

interface EnvConfig {
  port: number;
  nodeEnv: string;
  mongodbUri: string;
  sessionSecret: string;
  encryptionKey: string;
  logLevel: string;
  debugMode: boolean;
}

/**
 * Validates and retrieves environment variables
 * @throws {Error} If required environment variables are missing or invalid
 */
export function validateEnv(): EnvConfig {
  const errors: string[] = [];

  // PORT validation
  const portEnv = process.env.PORT;
  const port = portEnv ? parseInt(portEnv, 10) : 3000;
  if (isNaN(port) || port < 1 || port > 65535) {
    errors.push(`Invalid PORT value: ${portEnv}. Must be between 1 and 65535.`);
  }

  // NODE_ENV validation
  const nodeEnv = process.env.NODE_ENV || 'development';
  if (!['development', 'production', 'test'].includes(nodeEnv)) {
    errors.push(`Invalid NODE_ENV: ${nodeEnv}. Must be 'development', 'production', or 'test'.`);
  }

  // MongoDB URI
  const mongodbUri = process.env.MONGODB_URI || process.env.MONGO_URI || 'mongodb://localhost:27017';

  // SESSION_SECRET validation
  const sessionSecret = process.env.SESSION_SECRET;
  if (!sessionSecret) {
    if (nodeEnv === 'production') {
      errors.push('SESSION_SECRET environment variable must be set in production');
    } else {
      console.warn('WARNING: SESSION_SECRET not set. Using default (INSECURE - only for development)');
    }
  } else if (sessionSecret.length < SESSION_CONFIG.MIN_SECRET_LENGTH) {
    errors.push(`SESSION_SECRET must be at least ${SESSION_CONFIG.MIN_SECRET_LENGTH} characters long`);
  }

  // ENCRYPTION_KEY validation
  const encryptionKey = process.env.ENCRYPTION_KEY;
  if (!encryptionKey) {
    if (nodeEnv === 'production') {
      errors.push('ENCRYPTION_KEY environment variable must be set in production');
    } else {
      console.warn('WARNING: ENCRYPTION_KEY not set. Using default (INSECURE - only for development)');
    }
  }

  // LOG_LEVEL validation (debug, info, warn, error)
  const logLevelEnv = process.env.LOG_LEVEL || process.env.LOGLEVEL || '';
  const validLogLevels = ['debug', 'info', 'warn', 'error'];
  const logLevel = logLevelEnv && validLogLevels.includes(logLevelEnv.toLowerCase())
    ? logLevelEnv.toLowerCase()
    : (nodeEnv === 'production' ? 'info' : 'info');

  // DEBUG mode (verbose logging) - can be enabled via DEBUG=true or LOG_LEVEL=debug
  const debugEnv = process.env.DEBUG || process.env.DEBUG_MODE || '';
  const debugMode = debugEnv.toLowerCase() === 'true' ||
                   debugEnv.toLowerCase() === '1' ||
                   logLevel === 'debug';

  if (errors.length > 0) {
    throw new Error(`Environment validation failed:\n${errors.join('\n')}`);
  }

  return {
    port,
    nodeEnv,
    mongodbUri,
    sessionSecret: sessionSecret || 'change-this-secret-key-in-production',
    encryptionKey: encryptionKey || 'default-encryption-key-change-in-production',
    logLevel,
    debugMode,
  };
}

/**
 * Gets the current environment configuration
 */
export function getEnvConfig(): EnvConfig {
  return validateEnv();
}

