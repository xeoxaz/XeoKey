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

  it('creates sessions with ~7 day expiry and matching cookie max-age', async () => {
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

    // Expiry should be approximately 7 days after creation
    const SEVEN_DAYS_MS = 7 * 24 * 60 * 60 * 1000;
    const deltaMs = expiresAt - createdAt;
    expect(deltaMs).toBeGreaterThanOrEqual(SEVEN_DAYS_MS - 2000); // allow small skew
    expect(deltaMs).toBeLessThanOrEqual(SEVEN_DAYS_MS + 2000);

    // Cookie should advertise the matching Max-Age (in seconds)
    const cookie = createSessionCookie(sessionId);
    expect(cookie).toMatch(new RegExp(`Max-Age=${SEVEN_DAYS_MS / 1000}`));

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


