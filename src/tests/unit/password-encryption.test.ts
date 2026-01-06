import { describe, it, expect, beforeAll, afterAll } from 'bun:test';
import { setupTestEnv, cleanupTestEnv } from '../helpers/test-utils';

// We need to test the encryption functions, but they're not exported
// So we'll test them through the password model functions
describe('Password Encryption', () => {
  beforeAll(() => {
    setupTestEnv();
  });

  afterAll(() => {
    cleanupTestEnv();
  });

  it('should have encryption key set in test environment', () => {
    expect(process.env.ENCRYPTION_KEY).toBeDefined();
    expect(process.env.ENCRYPTION_KEY).toBe('test-encryption-key-for-testing-purposes-only');
  });

  it('should have session secret set in test environment', () => {
    expect(process.env.SESSION_SECRET).toBeDefined();
    expect(process.env.SESSION_SECRET).toContain('test-session-secret');
  });
});

