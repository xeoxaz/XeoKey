import { describe, it, expect, beforeEach } from 'bun:test';
import {
  createCsrfToken,
  getOrCreateCsrfToken,
  verifyCsrfToken,
  deleteCsrfToken,
} from '../../security/csrf';

describe('CSRF Token Management', () => {
  const sessionId = 'test-session-123';

  beforeEach(() => {
    // Clean up tokens before each test
    deleteCsrfToken(sessionId);
  });

  describe('createCsrfToken', () => {
    it('should create a new CSRF token', () => {
      const token = createCsrfToken(sessionId);
      expect(token).toBeDefined();
      expect(token.length).toBe(64); // 32 bytes = 64 hex characters
    });

    it('should create different tokens for different sessions', () => {
      const token1 = createCsrfToken('session1');
      const token2 = createCsrfToken('session2');
      expect(token1).not.toBe(token2);
    });

    it('should create a new token each time for the same session', () => {
      const token1 = createCsrfToken(sessionId);
      const token2 = createCsrfToken(sessionId);
      expect(token1).not.toBe(token2);
    });
  });

  describe('getOrCreateCsrfToken', () => {
    it('should return existing token if valid', () => {
      const token1 = getOrCreateCsrfToken(sessionId);
      const token2 = getOrCreateCsrfToken(sessionId);
      expect(token1).toBe(token2);
    });

    it('should create new token if none exists', () => {
      const token = getOrCreateCsrfToken(sessionId);
      expect(token).toBeDefined();
      expect(token.length).toBe(64);
    });
  });

  describe('verifyCsrfToken', () => {
    it('should verify a valid token', () => {
      const token = createCsrfToken(sessionId);
      expect(verifyCsrfToken(sessionId, token)).toBe(true);
    });

    it('should reject an invalid token', () => {
      createCsrfToken(sessionId);
      expect(verifyCsrfToken(sessionId, 'invalid-token')).toBe(false);
    });

    it('should reject token for non-existent session', () => {
      expect(verifyCsrfToken('non-existent-session', 'any-token')).toBe(false);
    });

    it('should reject token after deletion', () => {
      const token = createCsrfToken(sessionId);
      deleteCsrfToken(sessionId);
      expect(verifyCsrfToken(sessionId, token)).toBe(false);
    });
  });

  describe('deleteCsrfToken', () => {
    it('should delete a token', () => {
      const token = createCsrfToken(sessionId);
      expect(verifyCsrfToken(sessionId, token)).toBe(true);

      deleteCsrfToken(sessionId);
      expect(verifyCsrfToken(sessionId, token)).toBe(false);
    });

    it('should not throw when deleting non-existent token', () => {
      expect(() => deleteCsrfToken('non-existent-session')).not.toThrow();
    });
  });
});

