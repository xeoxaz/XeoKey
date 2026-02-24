import { getDatabase } from '../db/mongodb';
import { hashPassword, verifyPassword } from './session';
import { ObjectId } from 'mongodb';
import { logger } from '../utils/logger';

export interface User {
  _id?: ObjectId | string;
  username: string;
  passwordHash: string;
  createdAt: Date;
  lastLogin?: Date;
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

    return await usersCollection.findOne({
      username: { $regex: new RegExp(`^${trimmedUsername.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, 'i') }
    });
  } catch (error) {
    logger.error(`Failed to get user by username ${trimmedUsername}: ${error}`);
    return null;
  }
}

