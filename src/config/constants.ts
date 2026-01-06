/**
 * Application-wide constants and configuration values
 */

// Server Configuration
export const SERVER_CONFIG = {
  DEFAULT_PORT: 3000,
  MAX_REQUEST_SIZE: 10 * 1024 * 1024, // 10MB
  REQUEST_TIMEOUT: 30000, // 30 seconds
} as const;

// Session Configuration
export const SESSION_CONFIG = {
  DURATION: 24 * 60 * 60 * 1000, // 24 hours in milliseconds
  COOKIE_NAME: 'xeokey_session',
  MIN_SECRET_LENGTH: 32,
} as const;

// Security Configuration
export const SECURITY_CONFIG = {
  BCRYPT_SALT_ROUNDS: 10,
  RATE_LIMIT_ATTEMPTS: 5,
  RATE_LIMIT_WINDOW: 15 * 60 * 1000, // 15 minutes in milliseconds
  CSRF_TOKEN_LENGTH: 32,
} as const;

// Database Configuration
export const DATABASE_CONFIG = {
  DEFAULT_NAME: 'XeoKey',
  DEFAULT_URI: 'mongodb://localhost:27017',
  CONNECTION_TIMEOUT: 10000, // 10 seconds
} as const;

// Encryption Configuration
export const ENCRYPTION_CONFIG = {
  ALGORITHM: 'aes-256-cbc',
  IV_LENGTH: 16, // bytes
  KEY_LENGTH: 32, // bytes (for AES-256)
} as const;

// Analytics Configuration
export const ANALYTICS_CONFIG = {
  DEFAULT_DAYS: 30,
  REFRESH_INTERVAL: 30000, // 30 seconds
} as const;

// Password Validation
export const PASSWORD_VALIDATION = {
  MIN_LENGTH: 8,
  MAX_LENGTH: 100,
  REQUIRE_LETTER: true,
  REQUIRE_NUMBER: true,
} as const;

// Username Validation
export const USERNAME_VALIDATION = {
  MIN_LENGTH: 3,
  MAX_LENGTH: 20,
  PATTERN: /^[a-zA-Z0-9_-]+$/,
} as const;

