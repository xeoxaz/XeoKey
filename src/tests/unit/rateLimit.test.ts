import { describe, it, expect, beforeEach } from 'bun:test';
import { checkRateLimit, resetRateLimit } from '../../security/rateLimit';
import { createTestRequest, sleep } from '../helpers/test-utils';

describe('Rate Limiting', () => {
  const endpoint = 'login';
  let request: Request;

  beforeEach(() => {
    // Use unique IP for each test to avoid interference
    const uniqueIP = `127.0.0.${Math.floor(Math.random() * 255)}`;
    request = createTestRequest('POST', '/login', {}, {
      'x-forwarded-for': uniqueIP,
    });
    // Reset rate limit for this endpoint
    resetRateLimit(request, endpoint);
  });

  describe('checkRateLimit', () => {
    it('should allow requests within limit', () => {
      for (let i = 0; i < 5; i++) {
        const result = checkRateLimit(request, endpoint);
        expect(result.allowed).toBe(true);
        expect(result.remaining).toBeGreaterThanOrEqual(0);
      }
    });

    it('should block requests after limit exceeded', () => {
      // Make 5 requests (the limit)
      for (let i = 0; i < 5; i++) {
        checkRateLimit(request, endpoint);
      }

      // 6th request should be blocked
      const result = checkRateLimit(request, endpoint);
      expect(result.allowed).toBe(false);
      expect(result.remaining).toBe(0);
    });

    it('should track remaining attempts', () => {
      resetRateLimit(request, endpoint); // Start fresh
      const result1 = checkRateLimit(request, endpoint);
      expect(result1.remaining).toBe(4);
      expect(result1.allowed).toBe(true);

      const result2 = checkRateLimit(request, endpoint);
      expect(result2.remaining).toBe(3);
      expect(result2.allowed).toBe(true);
    });

    it('should have different limits for different endpoints', () => {
      const loginRequest = createTestRequest('POST', '/login');
      const registerRequest = createTestRequest('POST', '/register');

      // Exceed limit for login
      for (let i = 0; i < 6; i++) {
        checkRateLimit(loginRequest, 'login');
      }

      // Register should still be allowed
      const registerResult = checkRateLimit(registerRequest, 'register');
      expect(registerResult.allowed).toBe(true);
    });

    it('should have different limits for different IPs', () => {
      const request1 = createTestRequest('POST', '/login', {}, {
        'x-forwarded-for': '127.0.0.1',
      });
      const request2 = createTestRequest('POST', '/login', {}, {
        'x-forwarded-for': '192.168.1.1',
      });

      // Exceed limit for IP 1
      for (let i = 0; i < 6; i++) {
        checkRateLimit(request1, endpoint);
      }

      // IP 2 should still be allowed
      const result = checkRateLimit(request2, endpoint);
      expect(result.allowed).toBe(true);
    });
  });

  describe('resetRateLimit', () => {
    it('should reset rate limit for a client', () => {
      // Exceed limit
      for (let i = 0; i < 6; i++) {
        checkRateLimit(request, endpoint);
      }

      // Reset
      resetRateLimit(request, endpoint);

      // Should be allowed again
      const result = checkRateLimit(request, endpoint);
      expect(result.allowed).toBe(true);
      expect(result.remaining).toBe(4);
    });
  });
});

