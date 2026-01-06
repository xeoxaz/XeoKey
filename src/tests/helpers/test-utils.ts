/**
 * Test utilities and helpers
 */

import { MongoClient, Db } from 'mongodb';

/**
 * Test database configuration
 */
export const TEST_CONFIG = {
  MONGODB_URI: process.env.TEST_MONGODB_URI || 'mongodb://localhost:27017',
  DATABASE_NAME: 'XeoKey_Test',
  SESSION_SECRET: 'test-session-secret-key-at-least-32-characters-long-for-testing',
  ENCRYPTION_KEY: 'test-encryption-key-for-testing-purposes-only',
} as const;

/**
 * Setup test environment variables
 */
export function setupTestEnv(): void {
  process.env.NODE_ENV = 'test';
  process.env.MONGODB_URI = TEST_CONFIG.MONGODB_URI;
  process.env.SESSION_SECRET = TEST_CONFIG.SESSION_SECRET;
  process.env.ENCRYPTION_KEY = TEST_CONFIG.ENCRYPTION_KEY;
  process.env.LOG_LEVEL = 'error'; // Suppress logs during tests
  process.env.DEBUG = 'false';
}

/**
 * Clean up test environment variables
 */
export function cleanupTestEnv(): void {
  delete process.env.NODE_ENV;
  delete process.env.MONGODB_URI;
  delete process.env.SESSION_SECRET;
  delete process.env.ENCRYPTION_KEY;
  delete process.env.LOG_LEVEL;
  delete process.env.DEBUG;
}

/**
 * Connect to test database
 */
export async function connectTestDatabase(): Promise<{ client: MongoClient; db: Db }> {
  const client = new MongoClient(TEST_CONFIG.MONGODB_URI);
  await client.connect();
  const db = client.db(TEST_CONFIG.DATABASE_NAME);
  return { client, db };
}

/**
 * Drop all collections in test database
 */
export async function dropTestDatabase(db: Db): Promise<void> {
  const collections = await db.listCollections().toArray();
  for (const collection of collections) {
    await db.collection(collection.name).drop().catch(() => {
      // Ignore errors if collection doesn't exist
    });
  }
}

/**
 * Create a test request object
 */
export function createTestRequest(
  method: string = 'GET',
  path: string = '/',
  body?: any,
  headers: Record<string, string> = {}
): Request {
  const url = `http://localhost:3000${path}`;
  const requestInit: RequestInit = {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...headers,
    },
  };

  if (body) {
    requestInit.body = typeof body === 'string' ? body : JSON.stringify(body);
  }

  return new Request(url, requestInit);
}

/**
 * Create a test request with form data
 */
export function createTestFormRequest(
  method: string = 'POST',
  path: string = '/',
  formData: Record<string, string> = {},
  headers: Record<string, string> = {}
): Request {
  const url = `http://localhost:3000${path}`;
  const form = new FormData();

  for (const [key, value] of Object.entries(formData)) {
    form.append(key, value);
  }

  return new Request(url, {
    method,
    headers,
    body: form,
  });
}

/**
 * Create a test request with session cookie
 */
export function createAuthenticatedRequest(
  method: string = 'GET',
  path: string = '/',
  sessionId: string,
  body?: any
): Request {
  return createTestRequest(method, path, body, {
    Cookie: `xeokey_session=${sessionId}`,
  });
}

/**
 * Wait for a specified number of milliseconds
 */
export function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Generate a random string for testing
 */
export function randomString(length: number = 10): string {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

