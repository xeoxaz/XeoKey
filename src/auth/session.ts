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
const SESSION_DURATION = 24 * 60 * 60 * 1000; // 24 hours in milliseconds
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

// Get session by session ID
export async function getSession(sessionId: string): Promise<Session | null> {
  // Input validation
  if (!sessionId || typeof sessionId !== 'string' || sessionId.trim().length === 0) {
    return null;
  }

  try {
    const db = getDatabase();
    const sessionsCollection = db.collection<Session>('sessions');

    const session = await sessionsCollection.findOne({
      sessionId: sessionId.trim(),
      expiresAt: { $gt: new Date() },
    });

    if (session) {
      // Update last accessed time (don't fail if update fails)
      try {
        await sessionsCollection.updateOne(
          { sessionId: sessionId.trim() },
          { $set: { lastAccessed: new Date() } }
        );
      } catch (updateError) {
        logger.warn(`Failed to update last accessed time for session ${sessionId}: ${updateError}`);
        // Continue - session retrieval was successful
      }
    }

    return session;
  } catch (error) {
    logger.error(`Failed to get session ${sessionId}: ${error}`);
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

  try {
    const db = getDatabase();
    const sessionsCollection = db.collection('sessions');

    await sessionsCollection.deleteOne({ sessionId: sessionId.trim() });
  } catch (error) {
    logger.error(`Failed to delete session ${sessionId}: ${error}`);
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

