import { getDatabase } from '../db/mongodb';
import { randomBytes } from 'crypto';
import * as bcrypt from 'bcryptjs';

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
  const db = getDatabase();
  const sessionsCollection = db.collection<Session>('sessions');

  const sessionId = generateSessionId();
  const now = new Date();
  const expiresAt = new Date(now.getTime() + SESSION_DURATION);

  const session: Session = {
    sessionId,
    userId,
    username,
    createdAt: now,
    expiresAt,
    lastAccessed: now,
  };

  await sessionsCollection.insertOne(session);

  // Clean up expired sessions
  await cleanupExpiredSessions();

  return sessionId;
}

// Get session by session ID
export async function getSession(sessionId: string): Promise<Session | null> {
  const db = getDatabase();
  const sessionsCollection = db.collection<Session>('sessions');

  const session = await sessionsCollection.findOne({
    sessionId,
    expiresAt: { $gt: new Date() },
  });

  if (session) {
    // Update last accessed time
    await sessionsCollection.updateOne(
      { sessionId },
      { $set: { lastAccessed: new Date() } }
    );
  }

  return session;
}

// Delete a session (logout)
export async function deleteSession(sessionId: string): Promise<void> {
  const db = getDatabase();
  const sessionsCollection = db.collection('sessions');

  await sessionsCollection.deleteOne({ sessionId });
}

// Clean up expired sessions
export async function cleanupExpiredSessions(): Promise<void> {
  const db = getDatabase();
  const sessionsCollection = db.collection('sessions');

  await sessionsCollection.deleteMany({
    expiresAt: { $lt: new Date() },
  });
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

