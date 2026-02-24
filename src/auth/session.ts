import { getDatabase } from '../db/mongodb';
import { randomBytes } from 'crypto';
import * as bcrypt from 'bcryptjs';
import { logger } from '../utils/logger';

export interface Session {
  sessionId: string;
  userId: string;
  username: string;
  createdAt: Date;
  expiresAt: Date;
  lastAccessed: Date;
}

// Session configuration
// Fixed vault session duration (does NOT extend on activity)
const SESSION_DURATION = 5 * 60 * 1000; // 5 minutes in milliseconds
const SESSION_COOKIE_NAME = 'xeokey_session';

// Get SESSION_SECRET - fail if not set in production
function getSessionSecret(): string {
  const secret = process.env.SESSION_SECRET;
  if (!secret) {
    if (process.env.NODE_ENV === 'production') {
      throw new Error('SESSION_SECRET environment variable must be set in production');
    }
    // Note: Using console.warn here because logger might not be initialized yet during module load
    console.warn('WARNING: SESSION_SECRET not set. Using default (INSECURE - only for development)');
    return 'change-this-secret-key-in-production';
  }
  if (secret.length < 32) {
    throw new Error('SESSION_SECRET must be at least 32 characters long');
  }
  return secret;
}

const SESSION_SECRET = getSessionSecret();

// In-memory session cache with TTL
interface CachedSession {
  session: Session;
  expiresAt: number; // Timestamp when cache entry expires
}

const sessionCache = new Map<string, CachedSession>();
const CACHE_TTL = 30 * 1000; // Cache for 30 seconds
const MAX_CACHE_SIZE = 1000; // Maximum number of cached sessions

// Clean up expired cache entries periodically
setInterval(() => {
  const now = Date.now();
  for (const [sessionId, cached] of sessionCache.entries()) {
    if (cached.expiresAt < now) {
      sessionCache.delete(sessionId);
    }
  }
  // Also limit cache size
  if (sessionCache.size > MAX_CACHE_SIZE) {
    // Remove oldest entries (simple FIFO)
    const entries = Array.from(sessionCache.entries());
    entries.sort((a, b) => a[1].expiresAt - b[1].expiresAt);
    const toRemove = entries.slice(0, sessionCache.size - MAX_CACHE_SIZE);
    for (const [sessionId] of toRemove) {
      sessionCache.delete(sessionId);
    }
  }
}, 60000); // Run cleanup every minute

// Generate a secure session ID
function generateSessionId(): string {
  return randomBytes(32).toString('hex');
}

// Create a session
export async function createSession(userId: string, username: string): Promise<string> {
  // Input validation
  if (!userId || typeof userId !== 'string' || userId.trim().length === 0) {
    throw new Error('Invalid userId: must be a non-empty string');
  }
  if (!username || typeof username !== 'string' || username.trim().length === 0) {
    throw new Error('Invalid username: must be a non-empty string');
  }

  try {
    const db = getDatabase();
    const sessionsCollection = db.collection<Session>('sessions');

    const sessionId = generateSessionId();
    const now = new Date();
    const expiresAt = new Date(now.getTime() + SESSION_DURATION);

    const session: Session = {
      sessionId,
      userId: userId.trim(),
      username: username.trim(),
      createdAt: now,
      expiresAt,
      lastAccessed: now,
    };

    await sessionsCollection.insertOne(session);

    // Clean up expired sessions (don't fail if cleanup fails)
    try {
      await cleanupExpiredSessions();
    } catch (cleanupError) {
      logger.warn(`Failed to cleanup expired sessions: ${cleanupError}`);
      // Continue - session creation was successful
    }

    return sessionId;
  } catch (error) {
    logger.error(`Failed to create session for user ${userId}: ${error}`);
    throw new Error('Failed to create session');
  }
}

// Get session by session ID (with caching)
export async function getSession(sessionId: string): Promise<Session | null> {
  // Input validation
  if (!sessionId || typeof sessionId !== 'string' || sessionId.trim().length === 0) {
    return null;
  }

  const trimmedSessionId = sessionId.trim();

  // Check cache first
  const cached = sessionCache.get(trimmedSessionId);
  if (cached && cached.expiresAt > Date.now()) {
    // Cache hit - verify session hasn't expired
    if (cached.session.expiresAt > new Date()) {
      return cached.session;
    } else {
      // Session expired, remove from cache
      sessionCache.delete(trimmedSessionId);
    }
  }

  try {
    const db = getDatabase();
    const sessionsCollection = db.collection<Session>('sessions');

    const session = await sessionsCollection.findOne({
      sessionId: trimmedSessionId,
      expiresAt: { $gt: new Date() },
    });

    if (session) {
      // Cache the session
      sessionCache.set(trimmedSessionId, {
        session,
        expiresAt: Date.now() + CACHE_TTL,
      });

      // Update last accessed time (don't fail if update fails)
      try {
        await sessionsCollection.updateOne(
          { sessionId: trimmedSessionId },
          { $set: { lastAccessed: new Date() } }
        );
      } catch (updateError) {
        logger.warn(`Failed to update last accessed time for session ${trimmedSessionId}: ${updateError}`);
        // Continue - session retrieval was successful
      }
    }

    return session;
  } catch (error) {
    logger.error(`Failed to get session ${trimmedSessionId}: ${error}`);
    return null; // Return null on error to prevent authentication bypass
  }
}

// Delete a session (logout)
export async function deleteSession(sessionId: string): Promise<void> {
  // Input validation
  if (!sessionId || typeof sessionId !== 'string' || sessionId.trim().length === 0) {
    logger.warn('Attempted to delete session with invalid sessionId');
    return; // Silently return - invalid session ID means nothing to delete
  }

  const trimmedSessionId = sessionId.trim();

  // Remove from cache
  sessionCache.delete(trimmedSessionId);

  try {
    const db = getDatabase();
    const sessionsCollection = db.collection('sessions');

    await sessionsCollection.deleteOne({ sessionId: trimmedSessionId });
  } catch (error) {
    logger.error(`Failed to delete session ${trimmedSessionId}: ${error}`);
    // Don't throw - logout should succeed even if cleanup fails
    // The session will expire naturally anyway
  }
}

// Clean up expired sessions
export async function cleanupExpiredSessions(): Promise<void> {
  try {
    const db = getDatabase();
    const sessionsCollection = db.collection('sessions');

    const result = await sessionsCollection.deleteMany({
      expiresAt: { $lt: new Date() },
    });

    if (result.deletedCount > 0) {
      logger.debug(`Cleaned up ${result.deletedCount} expired session(s)`);
    }
  } catch (error) {
    logger.error(`Failed to cleanup expired sessions: ${error}`);
    // Don't throw - cleanup is a background operation
    // Failed cleanup doesn't break the application
  }
}

// Get session from request cookies
export function getSessionIdFromRequest(request: Request): string | null {
  const cookieHeader = request.headers.get('cookie');
  if (!cookieHeader) return null;

  const cookies = cookieHeader.split(';').map(c => c.trim());
  const sessionCookie = cookies.find(c => c.startsWith(`${SESSION_COOKIE_NAME}=`));

  if (!sessionCookie) return null;

  return sessionCookie.split('=')[1] || null;
}

// Check if request is over HTTPS
function isSecure(request?: Request): boolean {
  if (!request) return false;
  const protocol = request.headers.get('x-forwarded-proto') ||
                   (request.url.startsWith('https://') ? 'https' : 'http');
  return protocol === 'https';
}

// Create session cookie header
export function createSessionCookie(sessionId: string, request?: Request): string {
  const maxAge = SESSION_DURATION / 1000; // Convert to seconds
  const secure = isSecure(request) ? '; Secure' : '';
  return `${SESSION_COOKIE_NAME}=${sessionId}; HttpOnly${secure}; SameSite=Strict; Max-Age=${maxAge}; Path=/`;
}

// Create logout cookie (expires immediately)
export function createLogoutCookie(request?: Request): string {
  const secure = isSecure(request) ? '; Secure' : '';
  return `${SESSION_COOKIE_NAME}=; HttpOnly${secure}; SameSite=Strict; Max-Age=0; Path=/`;
}

// Clear session cache (for testing)
export function clearSessionCache(): void {
  sessionCache.clear();
}

// Hash password using bcrypt (secure password hashing)
export async function hashPassword(password: string): Promise<string> {
  const saltRounds = 10; // Higher is more secure but slower
  return await bcrypt.hash(password, saltRounds);
}

// Verify password using bcrypt
export async function verifyPassword(password: string, hashedPassword: string): Promise<boolean> {
  return await bcrypt.compare(password, hashedPassword);
}

export { SESSION_COOKIE_NAME };

