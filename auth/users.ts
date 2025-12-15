import { getDatabase } from '../db/mongodb';
import { hashPassword, verifyPassword } from './session';
import { ObjectId } from 'mongodb';

export interface User {
  _id?: string;
  username: string;
  passwordHash: string;
  createdAt: Date;
  lastLogin?: Date;
}

// Create a new user
export async function createUser(username: string, password: string): Promise<User> {
  const db = getDatabase();
  const usersCollection = db.collection<User>('users');

  // Check if user already exists (case-insensitive)
  const existingUser = await usersCollection.findOne({
    username: { $regex: new RegExp(`^${username.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, 'i') }
  });

  if (existingUser) {
    throw new Error('User already exists');
  }

  const passwordHash = await hashPassword(password);

  const user: User = {
    username,
    passwordHash,
    createdAt: new Date(),
  };

  const result = await usersCollection.insertOne(user);
  user._id = result.insertedId.toString();

  return user;
}

// Authenticate user (login) - case-insensitive username
export async function authenticateUser(username: string, password: string): Promise<User | null> {
  const db = getDatabase();
  const usersCollection = db.collection<User>('users');

  // Find user with case-insensitive username matching
  const user = await usersCollection.findOne({
    username: { $regex: new RegExp(`^${username.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, 'i') }
  });

  if (!user) {
    return null;
  }

  if (!(await verifyPassword(password, user.passwordHash))) {
    return null;
  }

  // Update last login
  await usersCollection.updateOne(
    { _id: user._id },
    { $set: { lastLogin: new Date() } }
  );

  return user;
}

// Get user by ID
export async function getUserById(userId: string): Promise<User | null> {
  const db = getDatabase();
  const usersCollection = db.collection<User>('users');

  // Validate ObjectId format to prevent injection
  if (!ObjectId.isValid(userId)) {
    return null;
  }

  try {
    return await usersCollection.findOne({ _id: new ObjectId(userId) });
  } catch (error) {
    return null;
  }
}

// Get user by username (case-insensitive)
export async function getUserByUsername(username: string): Promise<User | null> {
  const db = getDatabase();
  const usersCollection = db.collection<User>('users');

  return await usersCollection.findOne({
    username: { $regex: new RegExp(`^${username.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, 'i') }
  });
}

