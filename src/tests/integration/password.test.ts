import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'bun:test';
import { setupTestEnv, cleanupTestEnv, randomString } from '../helpers/test-utils';
import { connectMongoDB, closeMongoDB } from '../../db/mongodb';
import { createUser } from '../../auth/users';
import {
  createPasswordEntry,
  getUserPasswords,
  getPasswordEntry,
  getDecryptedPassword,
  updatePasswordEntry,
  deletePasswordEntry,
} from '../../models/password';

describe('Password Management Integration Tests', () => {
  let userId: string;

  beforeAll(async () => {
    setupTestEnv();
    try {
      await connectMongoDB();

      // Create a test user
      const user = await createUser(`testuser_${randomString(8)}`, 'testpassword123');
      userId = user._id!;
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
    // Clean up password entries in the same database used by the app
    try {
      const { getDatabase } = await import('../../db/mongodb');
      const db = getDatabase();
      await db.collection('passwords').deleteMany({ userId });
    } catch (error) {
      // MongoDB might not be available
    }
  });

  describe('Password Entry Creation', () => {
    it('should create a password entry', async () => {
      const entry = await createPasswordEntry(
        userId,
        'example.com',
        'mypassword123',
        'testuser',
        'test@example.com',
        'Test notes'
      );

      expect(entry).toBeDefined();
      expect(entry.website).toBe('example.com');
      expect(entry.username).toBe('testuser');
      expect(entry.email).toBe('test@example.com');
      expect(entry.notes).toBe('Test notes');
      expect(entry.password).not.toBe('mypassword123'); // Should be encrypted
      expect(entry._id).toBeDefined();
    });

    it('should encrypt password', async () => {
      const password = 'mypassword123';
      const entry = await createPasswordEntry(userId, 'example.com', password);

      expect(entry.password).not.toBe(password);
      expect(entry.password).toContain(':'); // Encrypted format: IV:encrypted
    });
  });

  describe('Password Retrieval', () => {
    it('should retrieve user passwords', async () => {
      await createPasswordEntry(userId, 'example.com', 'password1');
      await createPasswordEntry(userId, 'test.com', 'password2');

      const passwords = await getUserPasswords(userId);

      expect(passwords.length).toBe(2);
    });

    it('should decrypt password correctly', async () => {
      const originalPassword = 'mypassword123';
      const entry = await createPasswordEntry(userId, 'example.com', originalPassword);

      const decrypted = await getDecryptedPassword(entry._id!, userId);

      expect(decrypted).toBe(originalPassword);
    });

    it('should retrieve password entry by ID', async () => {
      const entry = await createPasswordEntry(userId, 'example.com', 'password123');

      const retrieved = await getPasswordEntry(entry._id!, userId);

      expect(retrieved).not.toBeNull();
      expect(retrieved?.website).toBe('example.com');
    });
  });

  describe('Password Update', () => {
    it('should update password entry', async () => {
      const entry = await createPasswordEntry(userId, 'example.com', 'oldpassword');

      const updated = await updatePasswordEntry(entry._id!, userId, {
        website: 'newexample.com',
        password: 'newpassword',
      });

      expect(updated).toBe(true);

      const retrieved = await getPasswordEntry(entry._id!, userId);
      expect(retrieved?.website).toBe('newexample.com');

      const decrypted = await getDecryptedPassword(entry._id!, userId);
      expect(decrypted).toBe('newpassword');
    });
  });

  describe('Password Deletion', () => {
    it('should delete password entry', async () => {
      const entry = await createPasswordEntry(userId, 'example.com', 'password123');

      const deleted = await deletePasswordEntry(entry._id!, userId);

      expect(deleted).toBe(true);

      const retrieved = await getPasswordEntry(entry._id!, userId);
      expect(retrieved).toBeNull();
    });
  });
});

