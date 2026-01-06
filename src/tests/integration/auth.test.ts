import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'bun:test';
import {
  setupTestEnv,
  cleanupTestEnv,
  connectTestDatabase,
  dropTestDatabase,
  randomString,
} from '../helpers/test-utils';
import { connectMongoDB, closeMongoDB } from '../../db/mongodb';
import { createUser, authenticateUser } from '../../auth/users';
import { createSession, getSession, deleteSession } from '../../auth/session';

describe('Authentication Integration Tests', () => {
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
    } catch (error) {
      // Ignore
    }
    cleanupTestEnv();
  });

  beforeEach(async () => {
    // Clean up test data before each test
    try {
      const { client, db } = await connectTestDatabase();
      await dropTestDatabase(db);
      await client.close();
    } catch (error) {
      // MongoDB might not be available
    }
  });

  describe('User Creation', () => {
    it('should create a new user', async () => {
      const username = `testuser_${randomString(8)}`;
      const password = 'testpassword123';

      const user = await createUser(username, password);

      expect(user).toBeDefined();
      expect(user.username).toBe(username);
      expect(user._id).toBeDefined();
      expect(user.password).not.toBe(password); // Should be hashed
    });

    it('should not create duplicate users', async () => {
      const username = `testuser_${randomString(8)}`;
      const password = 'testpassword123';

      await createUser(username, password);

      try {
        await createUser(username, password);
        expect(true).toBe(false); // Should not reach here
      } catch (error: any) {
        expect(error.message).toContain('already exists');
      }
    }, 10000); // Increase timeout for this test
  });

  describe('User Authentication', () => {
    it('should authenticate valid user', async () => {
      const username = `testuser_${randomString(8)}`;
      const password = 'testpassword123';

      await createUser(username, password);
      const user = await authenticateUser(username, password);

      expect(user).not.toBeNull();
      expect(user?.username).toBe(username);
    });

    it('should reject invalid password', async () => {
      const username = `testuser_${randomString(8)}`;
      const password = 'testpassword123';

      await createUser(username, password);
      const user = await authenticateUser(username, 'wrongpassword');

      expect(user).toBeNull();
    });

    it('should reject non-existent user', async () => {
      const user = await authenticateUser('nonexistent', 'password');
      expect(user).toBeNull();
    });
  });

  describe('Session Management', () => {
    it('should create a session', async () => {
      const username = `testuser_${randomString(8)}`;
      const password = 'testpassword123';
      const user = await createUser(username, password);

      const sessionId = await createSession(user._id!, username);

      expect(sessionId).toBeDefined();
      expect(sessionId.length).toBe(64); // 32 bytes = 64 hex characters
    });

    it('should retrieve a session', async () => {
      const username = `testuser_${randomString(8)}`;
      const password = 'testpassword123';
      const user = await createUser(username, password);

      const sessionId = await createSession(user._id!, username);
      const session = await getSession(sessionId);

      expect(session).not.toBeNull();
      expect(session?.userId).toBe(user._id);
      expect(session?.username).toBe(username);
    });

    it('should delete a session', async () => {
      const username = `testuser_${randomString(8)}`;
      const password = 'testpassword123';
      const user = await createUser(username, password);

      const sessionId = await createSession(user._id!, username);
      await deleteSession(sessionId);

      const session = await getSession(sessionId);
      expect(session).toBeNull();
    });
  });
});

