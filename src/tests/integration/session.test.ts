import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'bun:test';
import {
  setupTestEnv,
  cleanupTestEnv,
  connectTestDatabase,
  dropTestDatabase,
  randomString,
  sleep,
} from '../helpers/test-utils';
import { connectMongoDB, closeMongoDB, getDatabase } from '../../db/mongodb';
import { createUser } from '../../auth/users';
import { createSession, getSession, createSessionCookie } from '../../auth/session';

describe('Session Timer and Expiry Integration', () => {
  beforeAll(async () => {
    setupTestEnv();
    try {
      await connectMongoDB();
    } catch (error) {
      console.warn('MongoDB not available for integration tests:', error);
    }
  });

  afterAll(async () => {
    try {
      await closeMongoDB();
    } catch (_) {
      // ignore
    }
    cleanupTestEnv();
  });

  beforeEach(async () => {
    try {
      const { client, db } = await connectTestDatabase();
      await dropTestDatabase(db);
      await client.close();
    } catch (_) {
      // ignore
    }
  });

  it('creates sessions with ~5 minute expiry and cookie max-age 300s', async () => {
    const username = `user_${randomString(6)}`;
    const password = 'testpassword123';
    const user = await createUser(username, password);

    const before = Date.now();
    const sessionId = await createSession(user._id!.toString(), username);
    const after = Date.now();

    const session = await getSession(sessionId);
    expect(session).not.toBeNull();

    const expiresAt = session!.expiresAt.getTime();
    const createdAt = session!.createdAt.getTime();

    // Expiry should be approximately 5 minutes after creation
    const deltaMs = expiresAt - createdAt;
    expect(deltaMs).toBeGreaterThanOrEqual(5 * 60 * 1000 - 2000); // allow small skew
    expect(deltaMs).toBeLessThanOrEqual(5 * 60 * 1000 + 2000);

    // Cookie should advertise Max-Age=300
    const cookie = createSessionCookie(sessionId);
    expect(cookie).toMatch(/Max-Age=300/);

    // Remaining should decrease over time
    const remaining1 = expiresAt - after;
    await sleep(50);
    const remaining2 = expiresAt - Date.now();
    expect(remaining2).toBeLessThan(remaining1);
  });

  it('treats expired sessions as invalid (getSession returns null)', async () => {
    const username = `user_${randomString(6)}`;
    const password = 'testpassword123';
    const user = await createUser(username, password);

    const sessionId = await createSession(user._id!.toString(), username);
    const session = await getSession(sessionId);
    expect(session).not.toBeNull();

    // Force expiry in DB
    const db = getDatabase();
    await db.collection('sessions').updateOne(
      { sessionId },
      { $set: { expiresAt: new Date(Date.now() - 1000) } }
    );

    // Clear session cache to force database read
    const { clearSessionCache } = await import('../../auth/session');
    clearSessionCache();

    const sessionAfter = await getSession(sessionId);
    expect(sessionAfter).toBeNull();
  });
});


