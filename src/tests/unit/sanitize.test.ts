import { describe, it, expect } from 'bun:test';
import {
  sanitizeString,
  sanitizeWebsite,
  sanitizeUsername,
  validateUsername,
  validatePassword,
} from '../../utils/sanitize';

describe('sanitizeString', () => {
  it('should trim whitespace', () => {
    expect(sanitizeString('  hello  ')).toBe('hello');
  });

  it('should remove angle brackets', () => {
    expect(sanitizeString('<script>alert("xss")</script>')).toBe('scriptalert("xss")/script');
  });

  it('should remove javascript: protocol', () => {
    expect(sanitizeString('javascript:alert(1)')).toBe('alert(1)');
    expect(sanitizeString('JAVASCRIPT:alert(1)')).toBe('alert(1)');
  });

  it('should remove event handlers', () => {
    expect(sanitizeString('onclick=alert(1)')).toBe('alert(1)');
    expect(sanitizeString('onerror=alert(1)')).toBe('alert(1)');
  });

  it('should limit length to 100 characters', () => {
    const longString = 'a'.repeat(150);
    expect(sanitizeString(longString).length).toBe(100);
  });

  it('should return empty string for non-string input', () => {
    expect(sanitizeString(null as any)).toBe('');
    expect(sanitizeString(undefined as any)).toBe('');
    expect(sanitizeString(123 as any)).toBe('');
  });
});

describe('sanitizeWebsite', () => {
  it('should trim whitespace', () => {
    expect(sanitizeWebsite('  example.com  ')).toBe('example.com');
  });

  it('should remove dangerous characters', () => {
    expect(sanitizeWebsite('<script>example.com</script>')).toBe('scriptexample.com/script');
  });

  it('should allow longer names than sanitizeString', () => {
    const longName = 'a'.repeat(250);
    expect(sanitizeWebsite(longName).length).toBe(200);
  });
});

describe('sanitizeUsername', () => {
  it('should only allow alphanumeric and underscore', () => {
    expect(sanitizeUsername('user_name123')).toBe('user_name123');
    expect(sanitizeUsername('user-name')).toBe('username');
    expect(sanitizeUsername('user@name')).toBe('username');
    expect(sanitizeUsername('user name')).toBe('username');
  });

  it('should limit length to 30 characters', () => {
    const longUsername = 'a'.repeat(50);
    expect(sanitizeUsername(longUsername).length).toBe(30);
  });

  it('should trim whitespace', () => {
    expect(sanitizeUsername('  username  ')).toBe('username');
  });
});

describe('validateUsername', () => {
  it('should accept valid usernames', () => {
    expect(validateUsername('user123')).toEqual({ valid: true });
    expect(validateUsername('user_name')).toEqual({ valid: true });
    expect(validateUsername('User123')).toEqual({ valid: true });
  });

  it('should reject usernames shorter than 3 characters', () => {
    const result = validateUsername('ab');
    expect(result.valid).toBe(false);
    expect(result.error).toContain('at least 3 characters');
  });

  it('should reject usernames longer than 30 characters', () => {
    const result = validateUsername('a'.repeat(31));
    expect(result.valid).toBe(false);
    expect(result.error).toContain('less than 30 characters');
  });

  it('should reject usernames with invalid characters', () => {
    const result = validateUsername('user-name');
    expect(result.valid).toBe(false);
    expect(result.error).toContain('letters, numbers, and underscores');
  });

  it('should reject empty usernames', () => {
    const result = validateUsername('');
    expect(result.valid).toBe(false);
  });
});

describe('validatePassword', () => {
  it('should accept valid passwords', () => {
    expect(validatePassword('password123')).toEqual({ valid: true });
    expect(validatePassword('a'.repeat(50))).toEqual({ valid: true });
  });

  it('should reject passwords shorter than 6 characters', () => {
    const result = validatePassword('pass');
    expect(result.valid).toBe(false);
    expect(result.error).toContain('at least 6 characters');
  });

  it('should reject passwords longer than 100 characters', () => {
    const result = validatePassword('a'.repeat(101));
    expect(result.valid).toBe(false);
    expect(result.error).toContain('less than 100 characters');
  });

  it('should reject empty passwords', () => {
    const result = validatePassword('');
    expect(result.valid).toBe(false);
  });
});

