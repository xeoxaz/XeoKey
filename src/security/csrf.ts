// CSRF protection

import { randomBytes } from 'crypto';

// Generate CSRF token
export function generateCsrfToken(): string {
  return randomBytes(32).toString('hex');
}

// Store CSRF tokens (in production, use Redis or database)
const csrfTokens = new Map<string, { token: string; expiresAt: number }>();

// Get or create CSRF token for session (returns existing valid token if available)
export function getOrCreateCsrfToken(sessionId: string): string {
  const stored = csrfTokens.get(sessionId);

  // If token exists and is still valid, return it
  if (stored && stored.expiresAt > Date.now()) {
    return stored.token;
  }

  // Otherwise, create a new token
  return createCsrfToken(sessionId);
}

// Create CSRF token for session
export function createCsrfToken(sessionId: string): string {
  const token = generateCsrfToken();
  const expiresAt = Date.now() + (24 * 60 * 60 * 1000); // 24 hours

  csrfTokens.set(sessionId, { token, expiresAt });

  // Clean up expired tokens
  cleanupExpiredTokens();

  return token;
}

// Verify CSRF token
export function verifyCsrfToken(sessionId: string, token: string): boolean {
  const stored = csrfTokens.get(sessionId);

  if (!stored) {
    return false;
  }

  if (stored.expiresAt < Date.now()) {
    csrfTokens.delete(sessionId);
    return false;
  }

  return stored.token === token;
}

// Delete CSRF token (on logout)
export function deleteCsrfToken(sessionId: string): void {
  csrfTokens.delete(sessionId);
}

// Clean up expired tokens
function cleanupExpiredTokens(): void {
  const now = Date.now();
  for (const [sessionId, data] of csrfTokens.entries()) {
    if (data.expiresAt < now) {
      csrfTokens.delete(sessionId);
    }
  }
}

// Clean up every 5 minutes
setInterval(cleanupExpiredTokens, 5 * 60 * 1000);

