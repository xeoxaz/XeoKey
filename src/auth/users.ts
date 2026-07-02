import { getDatabase } from '../db/mongodb';
import { hashPassword, verifyPassword } from './session';
import { ObjectId } from 'mongodb';
import { logger } from '../utils/logger';

export interface User {
  _id?: ObjectId | string;
  username: string;
  passwordHash: string;
  theme?: 'slate' | 'slate-contrast' | 'legacy-blue';
  createdAt: Date;
  lastLogin?: Date;
}

const ALLOWED_THEMES = new Set(['slate', 'slate-contrast', 'legacy-blue']);

function normalizeTheme(theme?: string): 'slate' | 'slate-contrast' | 'legacy-blue' {
  if (theme && ALLOWED_THEMES.has(theme)) {
    return theme as 'slate' | 'slate-contrast' | 'legacy-blue';
  }
  return 'slate';
}

// Create a new user
export async function createUser(username: string, password: string): Promise<User> {
  // Input validation
  if (!username || typeof username !== 'string' || username.trim().length === 0) {
    throw new Error('Username is required and must be a non-empty string');
  }
  if (!password || typeof password !== 'string' || password.length === 0) {
    throw new Error('Password is required and must be a non-empty string');
  }

  const trimmedUsername = username.trim();

  try {
    const db = getDatabase();
    const usersCollection = db.collection<User>('users');

    // Check if user already exists (case-insensitive)
    const existingUser = await usersCollection.findOne({
      username: { $regex: new RegExp(`^${trimmedUsername.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, 'i') }
    });

    if (existingUser) {
      throw new Error('User already exists');
    }

    const passwordHash = await hashPassword(password);

    const user: User = {
      username: trimmedUsername,
      passwordHash,
      theme: 'slate',
      createdAt: new Date(),
    };

    const result = await usersCollection.insertOne(user);
    user._id = result.insertedId.toString();

    logger.info(`User created: ${trimmedUsername}`);
    return user;
  } catch (error) {
    // Re-throw "User already exists" error as-is
    if (error instanceof Error && error.message === 'User already exists') {
      throw error;
    }
    logger.error(`Failed to create user ${trimmedUsername}: ${error}`);
    throw new Error('Failed to create user');
  }
}

// Authenticate user (login) - case-insensitive username
export async function authenticateUser(username: string, password: string): Promise<User | null> {
  // Input validation
  if (!username || typeof username !== 'string' || username.trim().length === 0) {
    return null; // Invalid username - return null to prevent user enumeration
  }
  if (!password || typeof password !== 'string' || password.length === 0) {
    return null; // Invalid password - return null to prevent user enumeration
  }

  const trimmedUsername = username.trim();

  try {
    const db = getDatabase();
    const usersCollection = db.collection<User>('users');

    // Find user with case-insensitive username matching
    const user = await usersCollection.findOne({
      username: { $regex: new RegExp(`^${trimmedUsername.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, 'i') }
    });

    if (!user) {
      return null; // User not found
    }

    if (!(await verifyPassword(password, user.passwordHash))) {
      return null; // Invalid password
    }

    // Update last login (don't fail if update fails)
    try {
      await usersCollection.updateOne(
        { _id: user._id },
        { $set: { lastLogin: new Date() } }
      );
    } catch (updateError) {
      logger.warn(`Failed to update last login for user ${trimmedUsername}: ${updateError}`);
      // Continue - authentication was successful
    }

    // Convert ObjectId to string for consistency with User interface
    const userWithStringId: User = {
      username: user.username,
      passwordHash: user.passwordHash,
      theme: normalizeTheme(user.theme),
      createdAt: user.createdAt,
      lastLogin: user.lastLogin,
      _id: user._id ? (typeof user._id === 'string' ? user._id : user._id.toString()) : undefined
    };

    return userWithStringId;
  } catch (error) {
    logger.error(`Failed to authenticate user ${trimmedUsername}: ${error}`);
    return null; // Return null on error to prevent authentication bypass
  }
}

// Ensure a local profile row exists for a user whose credentials live in ONYX.
//
// Auth and identity are owned by ONYX; xeokey keeps a lightweight `users` doc
// (keyed by the ONYX id, with no passwordHash) to hold xeokey-only fields such
// as `theme`. Idempotent: a no-op for migrated/existing users. Used after a
// successful ONYX login or registration so theme settings and lookups work.
export async function upsertLocalProfile(userId: string, username: string): Promise<void> {
  if (!userId || !ObjectId.isValid(userId)) {
    return;
  }

  try {
    const db = getDatabase();
    const usersCollection = db.collection<User>('users');
    await usersCollection.updateOne(
      { _id: new ObjectId(userId) } as any,
      { $setOnInsert: { username, theme: 'slate', createdAt: new Date() } },
      { upsert: true }
    );
  } catch (error) {
    // Non-fatal: the session still works without a local profile (theme falls
    // back to the default). Log and continue.
    logger.warn(`Failed to upsert local profile for ${userId}: ${error}`);
  }
}

// Get user by ID
export async function getUserById(userId: string): Promise<User | null> {
  // Input validation
  if (!userId || typeof userId !== 'string' || userId.trim().length === 0) {
    return null;
  }

  // Validate ObjectId format to prevent injection
  if (!ObjectId.isValid(userId)) {
    return null;
  }

  try {
    const db = getDatabase();
    const usersCollection = db.collection('users');
    const user = await usersCollection.findOne({ _id: new ObjectId(userId) });

    if (!user) {
      return null;
    }

    // Convert ObjectId to string for consistency
    return {
      username: user.username,
      passwordHash: user.passwordHash,
      theme: normalizeTheme(user.theme),
      createdAt: user.createdAt,
      lastLogin: user.lastLogin,
      _id: user._id.toString()
    } as User;
  } catch (error) {
    logger.error(`Failed to get user by ID ${userId}: ${error}`);
    return null;
  }
}

// Get user by username (case-insensitive)
export async function getUserByUsername(username: string): Promise<User | null> {
  // Input validation
  if (!username || typeof username !== 'string' || username.trim().length === 0) {
    return null;
  }

  const trimmedUsername = username.trim();

  try {
    const db = getDatabase();
    const usersCollection = db.collection<User>('users');

    const user = await usersCollection.findOne({
      username: { $regex: new RegExp(`^${trimmedUsername.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, 'i') }
    });

    if (!user) {
      return null;
    }

    return {
      ...user,
      theme: normalizeTheme(user.theme),
    };
  } catch (error) {
    logger.error(`Failed to get user by username ${trimmedUsername}: ${error}`);
    return null;
  }
}

export async function updateUserTheme(userId: string, theme: string): Promise<boolean> {
  if (!userId || typeof userId !== 'string' || !ObjectId.isValid(userId)) {
    return false;
  }

  const normalizedTheme = normalizeTheme(theme);

  try {
    const db = getDatabase();
    const usersCollection = db.collection<User>('users');
    const result = await usersCollection.updateOne(
      { _id: new ObjectId(userId) } as any,
      { $set: { theme: normalizedTheme } }
    );

    return result.modifiedCount > 0 || result.matchedCount > 0;
  } catch (error) {
    logger.error(`Failed to update theme for user ${userId}: ${error}`);
    return false;
  }
}

