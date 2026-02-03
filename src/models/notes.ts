import { getDatabase } from '../db/mongodb';
import { ObjectId, Filter, UpdateFilter } from 'mongodb';
import * as crypto from 'crypto';
import { passwordLogger } from '../utils/logger';

export interface NoteEntry {
  _id?: string;
  userId: string;
  title: string;
  content: string; // Encrypted
  createdAt: Date;
  updatedAt: Date;
  searchCount?: number; // Number of times this note was viewed
}

// Encryption key (same as passwords for consistency)
function getEncryptionKey(): Buffer {
  const key = process.env.ENCRYPTION_KEY || 'default-encryption-key-change-in-production';
  if (process.env.NODE_ENV === 'production' && key === 'default-encryption-key-change-in-production') {
    throw new Error('ENCRYPTION_KEY environment variable must be set in production');
  }
  // Generate 32-byte key for AES-256
  return crypto.createHash('sha256').update(key).digest();
}

// Encrypt note content
function encryptNoteContent(content: string): string {
  const algorithm = 'aes-256-cbc';
  const key = getEncryptionKey();
  const iv = crypto.randomBytes(16);

  const cipher = crypto.createCipheriv(algorithm, key, iv);
  let encrypted = cipher.update(content, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  // Return IV + encrypted data
  return iv.toString('hex') + ':' + encrypted;
}

// Decrypt note content
export function decryptNoteContent(encrypted: string): string {
  const algorithm = 'aes-256-cbc';
  const key = getEncryptionKey();

  const parts = encrypted.split(':');
  if (parts.length !== 2) {
    throw new Error('Invalid encrypted note format');
  }

  const iv = Buffer.from(parts[0], 'hex');
  const encryptedData = parts[1];

  const decipher = crypto.createDecipheriv(algorithm, key, iv);
  let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
}

// Create a new note entry
export async function createNoteEntry(
  userId: string,
  title: string,
  content: string
): Promise<NoteEntry> {
  const db = getDatabase();
  const notesCollection = db.collection<NoteEntry>('notes');

  const encryptedContent = encryptNoteContent(content);

  const entry: NoteEntry = {
    userId,
    title,
    content: encryptedContent,
    createdAt: new Date(),
    updatedAt: new Date(),
    searchCount: 0,
  };

  const result = await notesCollection.insertOne(entry);
  entry._id = result.insertedId.toString();

  return entry;
}

// Get all notes for a user, sorted by most viewed first, then alphabetically by title
export async function getUserNotes(
  userId: string,
  options?: { limit?: number; skip?: number }
): Promise<NoteEntry[]> {
  const db = getDatabase();
  const notesCollection = db.collection<NoteEntry>('notes');

  // Convert userId to string if it's an ObjectId
  const userIdString = typeof userId === 'string' ? userId : (userId as any).toString();

  // Query for BOTH string and ObjectId formats to handle old and new schemas
  const queryConditions: any[] = [{ userId: userIdString }];

  // If userId is a valid ObjectId, also query for ObjectId format (for old schema)
  if (ObjectId.isValid(userIdString)) {
    queryConditions.push({ userId: new ObjectId(userIdString) });
  }

  // Build query with optional pagination
  let query = notesCollection.find({
    $or: queryConditions
  } as any)
    .sort({
      searchCount: -1,  // Most viewed first
      title: 1           // Then alphabetically
    });

  // Apply pagination if provided
  if (options?.skip !== undefined) {
    query = query.skip(options.skip);
  }
  if (options?.limit !== undefined) {
    query = query.limit(options.limit);
  }

  const allResults = await query.toArray();

  // Remove duplicates by _id (in case same note exists in both formats somehow)
  const uniqueResults = new Map<string, NoteEntry>();
  for (const result of allResults) {
    const id = result._id?.toString() || '';
    if (id && !uniqueResults.has(id)) {
      uniqueResults.set(id, result);
    }
  }

  return Array.from(uniqueResults.values());
}

// Get most recent notes for a user (sorted by createdAt descending)
export async function getRecentNotes(userId: string, limit: number = 3): Promise<NoteEntry[]> {
  const db = getDatabase();
  const notesCollection = db.collection<NoteEntry>('notes');

  // Convert userId to string if it's an ObjectId
  const userIdString = typeof userId === 'string' ? userId : (userId as any).toString();

  try {
    // Query for BOTH string and ObjectId formats to handle old and new schemas
    const queryConditions: any[] = [{ userId: userIdString }];

    // If userId is a valid ObjectId, also query for ObjectId format (for old schema)
    if (ObjectId.isValid(userIdString)) {
      queryConditions.push({ userId: new ObjectId(userIdString) });
    }

    // Query for all matching notes using $or to find both formats
    const allResults = await notesCollection.find({
      $or: queryConditions
    } as any)
      .sort({ createdAt: -1 }) // Most recent first
      .limit(limit)
      .toArray();

    // Remove duplicates by _id (in case same note exists in both formats somehow)
    const uniqueResults = new Map<string, NoteEntry>();
    for (const result of allResults) {
      const id = result._id?.toString() || '';
      if (id && !uniqueResults.has(id)) {
        uniqueResults.set(id, result);
      }
    }

    return Array.from(uniqueResults.values());
  } catch (error) {
    passwordLogger.error(`Error in getRecentNotes: ${error}`);
    return [];
  }
}

// Get note entry by ID
export async function getNoteEntry(entryId: string, userId: string): Promise<NoteEntry | null> {
  const db = getDatabase();
  const notesCollection = db.collection<NoteEntry>('notes');

  if (!ObjectId.isValid(entryId)) {
    return null;
  }

  // Convert userId to string if it's an ObjectId
  const userIdString = typeof userId === 'string' ? userId : (userId as any).toString();

  try {
    // Try with string first (most common case)
    let entry = await notesCollection.findOne({
      _id: new ObjectId(entryId),
      userId: userIdString,
    } as any);

    // If not found and userId looks like an ObjectId, try with ObjectId
    if (!entry && ObjectId.isValid(userIdString)) {
      entry = await notesCollection.findOne({
        _id: new ObjectId(entryId),
        userId: new ObjectId(userIdString),
      } as any);
    }

    return entry;
  } catch (error) {
    passwordLogger.error(`Error in getNoteEntry: ${error}`);
    return null;
  }
}

// Get decrypted note content
export async function getDecryptedNoteContent(entryId: string, userId: string): Promise<string | null> {
  try {
    const entry = await getNoteEntry(entryId, userId);
    if (!entry) {
      passwordLogger.debug(`getDecryptedNoteContent: Entry ${entryId} not found for userId ${userId}`);
      return null;
    }

    if (!entry.content || entry.content.trim() === '') {
      passwordLogger.debug(`getDecryptedNoteContent: Entry ${entryId} has no content data`);
      return null;
    }

    try {
      const decrypted = decryptNoteContent(entry.content);
      return decrypted;
    } catch (error: any) {
      passwordLogger.warn(`Decryption failed for note ${entryId}: ${error.message || error}`);
      return null;
    }
  } catch (error: any) {
    passwordLogger.error(`getDecryptedNoteContent error for entry ${entryId}: ${error.message || error}`);
    return null;
  }
}

// Update note entry
export async function updateNoteEntry(
  entryId: string,
  userId: string,
  updates: {
    title?: string;
    content?: string;
  }
): Promise<boolean> {
  const db = getDatabase();
  const notesCollection = db.collection<NoteEntry>('notes');

  if (!ObjectId.isValid(entryId)) {
    passwordLogger.error(`Invalid entryId format: ${entryId}`);
    return false;
  }

  // Convert userId to string if it's an ObjectId
  const userIdString = typeof userId === 'string' ? userId : (userId as any).toString();

  // First, verify the entry exists and belongs to the user
  let filter: any = {
    _id: new ObjectId(entryId),
    userId: userIdString
  };

  let existingEntry = await notesCollection.findOne(filter);

  // If not found and userId is a valid ObjectId, try with ObjectId
  if (!existingEntry && ObjectId.isValid(userIdString)) {
    filter = {
      _id: new ObjectId(entryId),
      userId: new ObjectId(userIdString)
    };
    existingEntry = await notesCollection.findOne(filter);
  }

  if (!existingEntry) {
    passwordLogger.error(`Note not found or does not belong to user: entryId=${entryId}, userId=${userIdString}`);
    return false;
  }

  const updateFields: Partial<NoteEntry> = {
    updatedAt: new Date(),
  };

  if (updates.title !== undefined) updateFields.title = updates.title;
  if (updates.content !== undefined) updateFields.content = encryptNoteContent(updates.content);

  // Verify we have at least one field to update (besides updatedAt)
  const fieldsToUpdate = Object.keys(updateFields).filter(key => key !== 'updatedAt');
  if (fieldsToUpdate.length === 0) {
    passwordLogger.error(`No fields to update! Updates object: ${JSON.stringify(updates)}`);
    return false;
  }

  try {
    // Use _id only for update since we already verified ownership above
    const filter: any = {
      _id: new ObjectId(entryId)
    };

    const updateOperation: UpdateFilter<NoteEntry> = { $set: updateFields };

    const result = await notesCollection.updateOne(
      filter,
      updateOperation
    );

    return result.matchedCount > 0;
  } catch (error) {
    passwordLogger.error(`Error updating note entry: ${error}`);
    return false;
  }
}

// Delete note entry by ID
export async function deleteNoteEntry(entryId: string, userId: string): Promise<boolean> {
  const db = getDatabase();
  const notesCollection = db.collection<NoteEntry>('notes');

  if (!ObjectId.isValid(entryId)) {
    return false;
  }

  const userIdString = typeof userId === 'string' ? userId : (userId as any).toString();

  try {
    // Try with string userId first
    let result = await notesCollection.deleteOne({
      _id: new ObjectId(entryId),
      userId: userIdString,
    } as any);

    // If not found and userId is a valid ObjectId, try with ObjectId
    if (result.deletedCount === 0 && ObjectId.isValid(userIdString)) {
      result = await notesCollection.deleteOne({
        _id: new ObjectId(entryId),
        userId: new ObjectId(userIdString),
      } as any);
    }

    return result.deletedCount > 0;
  } catch (error) {
    passwordLogger.error(`Error deleting note entry: ${error}`);
    return false;
  }
}

// Increment search count for a note entry
export async function incrementNoteSearchCount(entryId: string, userId: string): Promise<boolean> {
  const db = getDatabase();
  const notesCollection = db.collection<NoteEntry>('notes');

  if (!ObjectId.isValid(entryId)) {
    return false;
  }

  // Convert userId to string if it's an ObjectId
  const userIdString = typeof userId === 'string' ? userId : (userId as any).toString();

  try {
    // Try with string first, then ObjectId if that doesn't work
    let filter: any = {
      _id: new ObjectId(entryId),
      userId: userIdString
    };

    let result = await notesCollection.updateOne(
      filter,
      {
        $inc: { searchCount: 1 }
      } as any
    );

    // If not matched and userId is a valid ObjectId, try with ObjectId
    if (result.matchedCount === 0 && ObjectId.isValid(userIdString)) {
      filter = {
        _id: new ObjectId(entryId),
        userId: new ObjectId(userIdString)
      };
      result = await notesCollection.updateOne(
        filter,
        {
          $inc: { searchCount: 1 }
        } as any
      );
    }

    return result.matchedCount > 0;
  } catch (error) {
    passwordLogger.error(`Error incrementing note search count: ${error}`);
    return false;
  }
}
