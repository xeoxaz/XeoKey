import { getDatabase } from '../db/mongodb';
import { ObjectId, Filter, UpdateFilter } from 'mongodb';
import * as crypto from 'crypto';
import { passwordLogger } from '../utils/logger';
import { debugLog } from '../utils/debug';

export interface PasswordEntry {
  _id?: string;
  userId: string;
  website: string;
  username?: string;
  email?: string;
  password: string; // Encrypted
  notes?: string;
  createdAt: Date;
  updatedAt: Date;
  searchCount?: number; // Number of times this password was viewed/searched
  copyCount?: number; // Number of times this password was copied
}

// Encryption key (should be stored securely in production)
export function getEncryptionKey(): Buffer {
  const key = process.env.ENCRYPTION_KEY || 'default-encryption-key-change-in-production';
  if (process.env.NODE_ENV === 'production' && key === 'default-encryption-key-change-in-production') {
    throw new Error('ENCRYPTION_KEY environment variable must be set in production. Please set a secure encryption key in your .env file or environment variables. Generate one with: openssl rand -base64 32');
  }
  // Generate 32-byte key for AES-256
  return crypto.createHash('sha256').update(key).digest();
}

// Get all possible encryption keys for fallback attempts
function getAllEncryptionKeys(): Buffer[] {
  const keys: Buffer[] = [];
  
  // Primary key (from environment)
  if (process.env.ENCRYPTION_KEY) {
    keys.push(crypto.createHash('sha256').update(process.env.ENCRYPTION_KEY).digest());
  }
  
  // Default key (for recovery of data encrypted with default)
  keys.push(crypto.createHash('sha256').update('default-encryption-key-change-in-production').digest());
  
  // Common development keys (for recovery scenarios)
  const commonKeys = [
    'test-encryption-key-for-development-use-only-change-in-production',
    'XeoKey-Dev-Key-2024-Change-In-Production-Use-Strong-Key',
    'xeokey-test-key',
    'development-key-only',
  ];
  
  for (const commonKey of commonKeys) {
    keys.push(crypto.createHash('sha256').update(commonKey).digest());
  }
  
  return keys;
}

// Encrypt password
export function encryptPassword(password: string): string {
  const algorithm = 'aes-256-cbc';
  const key = getEncryptionKey();
  const iv = crypto.randomBytes(16);

  const cipher = crypto.createCipheriv(algorithm, key, iv);
  let encrypted = cipher.update(password, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  // Return IV + encrypted data
  return iv.toString('hex') + ':' + encrypted;
}

// Decrypt password with fallback key support
export function decryptPassword(encrypted: string): string {
  const algorithm = 'aes-256-cbc';

  const parts = encrypted.split(':');
  if (parts.length !== 2) {
    throw new Error('Invalid encrypted password format');
  }

  const iv = Buffer.from(parts[0], 'hex');
  const encryptedData = parts[1];

  // Try primary key first
  try {
    const key = getEncryptionKey();
    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (primaryError) {
    // Primary key failed, try fallback keys
    const fallbackKeys = getAllEncryptionKeys();
    
    // Skip the first key since we already tried it
    for (let i = 1; i < fallbackKeys.length; i++) {
      try {
        const key = fallbackKeys[i];
        const decipher = crypto.createDecipheriv(algorithm, key, iv);
        let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        
        // Log successful fallback for monitoring
        passwordLogger.warn(`Successfully decrypted password with fallback key ${i + 1}/${fallbackKeys.length}. Consider re-encrypting with current key.`);
        
        return decrypted;
      } catch (fallbackError) {
        // Continue trying other keys
        continue;
      }
    }
    
    // All keys failed, throw the original error
    throw primaryError;
  }
}

// Create a new password entry
export async function createPasswordEntry(
  userId: string,
  website: string,
  password: string,
  username?: string,
  email?: string,
  notes?: string
): Promise<PasswordEntry> {
  // Validate operation before execution
  try {
    const { validatePasswordOperation } = await import('../db/health');
    const validation = await validatePasswordOperation(userId, 'create');
    if (!validation.valid) {
      passwordLogger.error(`Password creation validation failed: ${validation.error}`);
      throw new Error(validation.error || 'Validation failed');
    }
  } catch (error) {
    // If health module not available, continue (for backwards compatibility)
    passwordLogger.debug('Health validation skipped');
  }

  const db = getDatabase();
  const passwordsCollection = db.collection<PasswordEntry>('passwords');

  const encryptedPassword = encryptPassword(password);

  const entry: PasswordEntry = {
    userId,
    website,
    username,
    email,
    password: encryptedPassword,
    notes,
    createdAt: new Date(),
    updatedAt: new Date(),
    searchCount: 0,
    copyCount: 0,
  };

  const result = await passwordsCollection.insertOne(entry);
  entry._id = result.insertedId.toString();

  // Validate after creation
  try {
    const { validateAfterPasswordOperation } = await import('../db/health');
    const postValidation = await validateAfterPasswordOperation(userId, entry._id);
    if (!postValidation.valid) {
      passwordLogger.warn(`Post-creation validation warning: ${postValidation.error}`);
      // Don't throw - entry was created, just log warning
    }
  } catch (error) {
    // Non-critical
    passwordLogger.debug('Post-creation validation skipped');
  }

  return entry;
}

// Get all passwords for a user, sorted by most searched/copied first, then alphabetically
// Optional pagination: if limit is provided, only return that many results
export async function getUserPasswords(
  userId: string,
  options?: { limit?: number; skip?: number }
): Promise<PasswordEntry[]> {
  const db = getDatabase();
  const passwordsCollection = db.collection<PasswordEntry>('passwords');

  // Convert userId to string if it's an ObjectId
  const userIdString = typeof userId === 'string' ? userId : (userId as any).toString();

  // Query for BOTH string and ObjectId formats to handle old and new schemas
  // This ensures we always show all passwords regardless of how userId is stored
  const queryConditions: any[] = [{ userId: userIdString }];

  // If userId is a valid ObjectId, also query for ObjectId format (for old schema)
  if (ObjectId.isValid(userIdString)) {
    queryConditions.push({ userId: new ObjectId(userIdString) });
  }

  // Build query with optional pagination
  let query = passwordsCollection.find({
    $or: queryConditions
  } as any)
    .sort({
      searchCount: -1,  // Most searched first
      copyCount: -1,    // Then most copied
      website: 1        // Then alphabetically
    });

  // Apply pagination if provided
  if (options?.skip !== undefined) {
    query = query.skip(options.skip);
  }
  if (options?.limit !== undefined) {
    query = query.limit(options.limit);
  }

  const allResults = await query.toArray();

  // Remove duplicates by _id (in case same password exists in both formats somehow)
  const uniqueResults = new Map<string, PasswordEntry>();
  for (const result of allResults) {
    const id = result._id?.toString() || '';
    if (id && !uniqueResults.has(id)) {
      uniqueResults.set(id, result);
    }
  }

  return Array.from(uniqueResults.values());
}

// Get most recent passwords for a user (sorted by createdAt descending)
export async function getRecentPasswords(userId: string, limit: number = 3): Promise<PasswordEntry[]> {
  const db = getDatabase();
  const passwordsCollection = db.collection<PasswordEntry>('passwords');

  // Convert userId to string if it's an ObjectId
  const userIdString = typeof userId === 'string' ? userId : (userId as any).toString();

  try {
    // Query for BOTH string and ObjectId formats to handle old and new schemas
    // This ensures we always show all passwords regardless of how userId is stored
    const queryConditions: any[] = [{ userId: userIdString }];

    // If userId is a valid ObjectId, also query for ObjectId format (for old schema)
    if (ObjectId.isValid(userIdString)) {
      queryConditions.push({ userId: new ObjectId(userIdString) });
    }

    // Query for all matching passwords using $or to find both formats
    const allResults = await passwordsCollection.find({
      $or: queryConditions
    } as any)
      .sort({ createdAt: -1 }) // Most recent first
      .limit(limit)
      .toArray();

    // Remove duplicates by _id (in case same password exists in both formats somehow)
    const uniqueResults = new Map<string, PasswordEntry>();
    for (const result of allResults) {
      const id = result._id?.toString() || '';
      if (id && !uniqueResults.has(id)) {
        uniqueResults.set(id, result);
      }
    }

    return Array.from(uniqueResults.values());
  } catch (error) {
    passwordLogger.error(`Error in getRecentPasswords: ${error}`);
    return [];
  }
}

// Get password entry by ID
export async function getPasswordEntry(entryId: string, userId: string): Promise<PasswordEntry | null> {
  const db = getDatabase();
  const passwordsCollection = db.collection<PasswordEntry>('passwords');

  if (!ObjectId.isValid(entryId)) {
    return null;
  }

  // Convert userId to string if it's an ObjectId (MongoDB might return it as ObjectId)
  // But also try matching as ObjectId in case the database stores it that way
  const userIdString = typeof userId === 'string' ? userId : (userId as any).toString();

  try {
    // Try with string first (most common case)
    let entry = await passwordsCollection.findOne({
      _id: new ObjectId(entryId),
      userId: userIdString,
    } as any);

    // If not found and userId looks like an ObjectId, try with ObjectId
    if (!entry && ObjectId.isValid(userIdString)) {
      entry = await passwordsCollection.findOne({
        _id: new ObjectId(entryId),
        userId: new ObjectId(userIdString),
      } as any);
    }

    return entry;
  } catch (error) {
    passwordLogger.error(`Error in getPasswordEntry: ${error}`);
    return null;
  }
}

// Get decrypted password
export async function getDecryptedPassword(entryId: string, userId: string): Promise<string | null> {
  try {
    const entry = await getPasswordEntry(entryId, userId);
    if (!entry) {
      passwordLogger.debug(`getDecryptedPassword: Entry ${entryId} not found for userId ${userId}`);
      return null;
    }

    if (!entry.password || entry.password.trim() === '') {
      passwordLogger.debug(`getDecryptedPassword: Entry ${entryId} has no password data`);
      return null;
    }

    try {
      const decrypted = decryptPassword(entry.password);
      return decrypted;
    } catch (error: any) {
      // Log the actual decryption error for debugging
      passwordLogger.warn(`Decryption failed for entry ${entryId}: ${error.message || error}`);
      // Don't log the full encrypted password, but log format issues
      if (error.message?.includes('format') || error.message?.includes('Invalid')) {
        passwordLogger.debug(`Password format issue for entry ${entryId}: ${entry.password.substring(0, 20)}...`);
      }
      return null;
    }
  } catch (error: any) {
    passwordLogger.error(`getDecryptedPassword error for entry ${entryId}: ${error.message || error}`);
    return null;
  }
}

// Update password entry
export async function updatePasswordEntry(
  entryId: string,
  userId: string,
  updates: {
    website?: string;
    username?: string;
    email?: string;
    password?: string;
    notes?: string;
  }
): Promise<boolean> {
  debugLog(passwordLogger, `=== updatePasswordEntry CALLED === entryId=${entryId}, userId=${userId}, userIdType=${typeof userId}`);
  const db = getDatabase();
  const passwordsCollection = db.collection<PasswordEntry>('passwords');

  if (!ObjectId.isValid(entryId)) {
    passwordLogger.error(`Invalid entryId format: ${entryId}`);
    return false;
  }

  // Convert userId to string if it's an ObjectId (MongoDB might return it as ObjectId)
  const userIdString = typeof userId === 'string' ? userId : (userId as any).toString();
  debugLog(passwordLogger, `Using userIdString for query: ${userIdString}, original type: ${typeof userId}`);

  // First, verify the entry exists and belongs to the user
  // Try with string first, then ObjectId if that doesn't work
  let findFilter: any = {
    _id: new ObjectId(entryId),
    userId: userIdString
  };

  debugLog(passwordLogger, `Looking for entry with filter: entryId=${entryId}, userId=${userIdString}`);

  let existingEntry = await passwordsCollection.findOne(findFilter);

  // If not found and userId is a valid ObjectId, try with ObjectId
  if (!existingEntry && ObjectId.isValid(userIdString)) {
    debugLog(passwordLogger, 'Trying with ObjectId format for userId...');
    findFilter = {
      _id: new ObjectId(entryId),
      userId: new ObjectId(userIdString)
    };
    existingEntry = await passwordsCollection.findOne(findFilter);
  }

  if (!existingEntry) {
    passwordLogger.error(`Entry not found or does not belong to user: entryId=${entryId}, userId=${userIdString}, userIdType=${typeof userIdString}`);
    // Try finding by _id only to see if entry exists
    const entryByIdOnly = await passwordsCollection.findOne({ _id: new ObjectId(entryId) } as any);
    if (entryByIdOnly) {
      passwordLogger.error(`Entry exists but userId does not match: entryId=${entryId}, requestedUserId=${userIdString}, requestedUserIdType=${typeof userIdString}, entryUserId=${entryByIdOnly.userId}, entryUserIdType=${typeof entryByIdOnly.userId}`);
    } else {
      passwordLogger.error('Entry does not exist at all');
    }
    return false;
  }

  debugLog(passwordLogger, `Entry found: entryId=${entryId}, userId=${existingEntry.userId}, website=${existingEntry.website}, entryUserIdType=${typeof existingEntry.userId}, requestedUserIdType=${typeof userId}`);

  const updateFields: Partial<PasswordEntry> = {
    updatedAt: new Date(),
  };

  // Always update website if provided (even if it's the same value)
  if (updates.website !== undefined) {
    updateFields.website = updates.website;
  }
  if (updates.username !== undefined) updateFields.username = updates.username;
  if (updates.email !== undefined) updateFields.email = updates.email;
  if (updates.password !== undefined) updateFields.password = encryptPassword(updates.password);
  // Notes can be explicitly set to empty string or null to clear it
  if (updates.notes !== undefined) {
    // Allow empty string to clear notes, or set to null if empty
    updateFields.notes = updates.notes === '' ? undefined : updates.notes;
  }

  // Verify we have at least one field to update (besides updatedAt)
  const fieldsToUpdate = Object.keys(updateFields).filter(key => key !== 'updatedAt');
  if (fieldsToUpdate.length === 0) {
    passwordLogger.error(`No fields to update! Updates object: ${JSON.stringify(updates)}`);
    return false;
  }

  debugLog(passwordLogger, `Update data (password redacted): entryId=${entryId}, userId=${userId}, existingWebsite=${existingEntry.website}, fieldsToUpdate=${fieldsToUpdate.join(',')}`);

  try {
    // Use _id only for update since we already verified ownership above
    // This is more reliable and matches how deletePasswordEntry works
    const filter: any = {
      _id: new ObjectId(entryId)
    };

    const updateOperation: UpdateFilter<PasswordEntry> = { $set: updateFields };

    debugLog(passwordLogger, `MongoDB update query: entryId=${entryId}, userId=${userId}, filter=_id, updateDataKeys=${Object.keys(updateFields).join(',')}, existingWebsite=${existingEntry.website}, newWebsite=${updateFields.website || 'N/A'}`);

    const result = await passwordsCollection.updateOne(
      filter,
      updateOperation
    );

    debugLog(passwordLogger, `MongoDB update result: matchedCount=${result.matchedCount}, modifiedCount=${result.modifiedCount}, upsertedCount=${result.upsertedCount}, acknowledged=${result.acknowledged}`);

    // If the document was matched, check if it was actually modified
    if (result.matchedCount > 0) {
      if (result.modifiedCount === 0) {
        passwordLogger.warn('Document matched but not modified - checking if values are actually different');
        // Check if the values are actually different
        const hasChanges = Object.keys(updateFields).some(key => {
          if (key === 'updatedAt') return true; // Always update timestamp
          if (key === 'password') {
            // Password is encrypted, so we can't directly compare
            // But if password is in updateData, it means it was provided
            return true;
          }
          const existingValue = (existingEntry as any)[key];
          const newValue = (updateFields as any)[key];
          const isDifferent = existingValue !== newValue;
          if (isDifferent) {
            debugLog(passwordLogger, `Field ${key} is different: existing=${existingValue}, new=${newValue}`);
          }
          return isDifferent;
        });

        if (!hasChanges) {
          passwordLogger.warn('No actual changes detected - all values are identical');
          // Still return true since the query worked, but log a warning
        } else {
          passwordLogger.error('Values are different but document was not modified - this indicates a MongoDB issue');
          // Force update by using replaceOne or try update again
          debugLog(passwordLogger, 'Attempting to force update...');
          const forceResult = await passwordsCollection.updateOne(
            filter,
            { $set: updateFields },
            { upsert: false }
          );
          debugLog(passwordLogger, `Force update result: matchedCount=${forceResult.matchedCount}, modifiedCount=${forceResult.modifiedCount}`);
        }
      } else {
        debugLog(passwordLogger, 'Update successful - document was modified');
      }

      // Verify the update by fetching the document again
      const updatedEntry = await passwordsCollection.findOne(filter);
      if (updatedEntry) {
        debugLog(passwordLogger, `Verification - updated entry: website=${updatedEntry.website}, updatedAt=${updatedEntry.updatedAt}`);
        // Check if website was actually updated
        if (updateFields.website && updatedEntry.website !== updateFields.website) {
          passwordLogger.error(`UPDATE VERIFICATION FAILED - website was not updated! expected=${updateFields.website}, actual=${updatedEntry.website}, matchedCount=${result.matchedCount}, modifiedCount=${result.modifiedCount}`);
          // Try one more time with explicit field update
          debugLog(passwordLogger, 'Retrying update with explicit website field...');
          const retryResult = await passwordsCollection.updateOne(
            filter,
            { $set: { website: updateFields.website, updatedAt: new Date() } }
          );
          debugLog(passwordLogger, `Retry result: matchedCount=${retryResult.matchedCount}, modifiedCount=${retryResult.modifiedCount}`);
          if (retryResult.modifiedCount > 0) {
            return true;
          }
          return false;
        }
        debugLog(passwordLogger, 'Update verified successfully');
      } else {
        passwordLogger.error('Could not verify update - document not found after update');
      }

      return true;
    }

    passwordLogger.error(`Update failed - document not matched. EntryId: ${entryId}`);
    return false;
  } catch (error) {
    passwordLogger.error(`Error updating password entry: ${error}`);
    return false;
  }
}

// Delete password entry by ID
export async function deletePasswordEntry(entryId: string, userId: string): Promise<boolean> {
  const db = getDatabase();
  const passwordsCollection = db.collection<PasswordEntry>('passwords');

  if (!ObjectId.isValid(entryId)) {
    return false;
  }

  const userIdString = typeof userId === 'string' ? userId : (userId as any).toString();

  try {
    // Try with string userId first
    let result = await passwordsCollection.deleteOne({
      _id: new ObjectId(entryId),
      userId: userIdString,
    } as any);

    // If not found and userId is a valid ObjectId, try with ObjectId
    if (result.deletedCount === 0 && ObjectId.isValid(userIdString)) {
      result = await passwordsCollection.deleteOne({
        _id: new ObjectId(entryId),
        userId: new ObjectId(userIdString),
      } as any);
    }

    return result.deletedCount > 0;
  } catch (error) {
    passwordLogger.error(`Error deleting password entry: ${error}`);
    return false;
  }
}

// Find password entries by website/username/email (for recovery purposes)
export async function findPasswordEntriesByIdentifier(
  userId: string,
  website: string,
  username?: string,
  email?: string
): Promise<PasswordEntry[]> {
  const db = getDatabase();
  const passwordsCollection = db.collection<PasswordEntry>('passwords');

  const userIdString = typeof userId === 'string' ? userId : (userId as any).toString();

  try {
    // Build base query conditions for userId (try both string and ObjectId)
    const userIdConditions: any[] = [{ userId: userIdString }];
    if (ObjectId.isValid(userIdString)) {
      userIdConditions.push({ userId: new ObjectId(userIdString) });
    }

    // Build query: must match userId AND website
    let query: any = {
      $or: userIdConditions.map(uid => ({ ...uid, website })),
    };

    // If username is provided, include it in the match (match exact or missing/null)
    if (username !== undefined && username !== null && username !== '') {
      // Match exact username or entries without username
      query.$or = query.$or.map((q: any) => ({
        ...q,
        $or: [
          { username: username },
          { username: { $exists: false } },
          { username: null },
          { username: '' },
        ]
      }));
    }

    // If email is provided, include it in the match (match exact or missing/null)
    if (email !== undefined && email !== null && email !== '') {
      // Match exact email or entries without email
      query.$or = query.$or.map((q: any) => {
        const existing = q.$or || [q];
        return existing.map((cond: any) => ({
          ...cond,
          $or: [
            { email: email },
            { email: { $exists: false } },
            { email: null },
            { email: '' },
          ]
        }));
      }).flat();
    }

    // Find all matching entries
    const results = await passwordsCollection.find(query as any).toArray();

    // Filter more precisely for username/email match
    let filteredResults = results.filter(entry => {
      // Must match website
      if (entry.website !== website) return false;

      // If username provided, must match exactly or be missing/null
      if (username !== undefined && username !== null && username !== '') {
        if (entry.username && entry.username !== username) return false;
      }

      // If email provided, must match exactly or be missing/null
      if (email !== undefined && email !== null && email !== '') {
        if (entry.email && entry.email !== email) return false;
      }

      return true;
    });

    return filteredResults;
  } catch (error) {
    passwordLogger.error(`Error finding password entries by identifier: ${error}`);
    return [];
  }
}

// Delete password entry by website/username/email
export async function deletePasswordEntryByIdentifier(
  userId: string,
  website: string,
  username?: string,
  email?: string
): Promise<{ success: boolean; deletedCount: number; error?: string }> {
  try {
    const entries = await findPasswordEntriesByIdentifier(userId, website, username, email);

    if (entries.length === 0) {
      return { success: false, deletedCount: 0, error: 'No matching password entries found' };
    }

    const db = getDatabase();
    const passwordsCollection = db.collection<PasswordEntry>('passwords');
    const userIdString = typeof userId === 'string' ? userId : (userId as any).toString();

    let deletedCount = 0;
    for (const entry of entries) {
      if (!entry._id) continue;

      try {
        // Delete by _id to ensure we're deleting the exact entry
        const result = await passwordsCollection.deleteOne({
          _id: new ObjectId(entry._id),
        } as any);

        if (result.deletedCount > 0) {
          deletedCount++;
          passwordLogger.info(`Deleted password entry: ${entry._id} (${website}${username ? ` / ${username}` : ''}${email ? ` / ${email}` : ''})`);
        }
      } catch (error: any) {
        passwordLogger.error(`Error deleting entry ${entry._id}: ${error.message || error}`);
      }
    }

    return { success: deletedCount > 0, deletedCount };
  } catch (error: any) {
    passwordLogger.error(`Error deleting password entry by identifier: ${error.message || error}`);
    return { success: false, deletedCount: 0, error: error.message || 'Unknown error' };
  }
}

// Increment search count for a password entry
export async function incrementSearchCount(entryId: string, userId: string): Promise<boolean> {
  const db = getDatabase();
  const passwordsCollection = db.collection<PasswordEntry>('passwords');

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

    let result = await passwordsCollection.updateOne(
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
      result = await passwordsCollection.updateOne(
        filter,
        {
          $inc: { searchCount: 1 }
        } as any
      );
    }

    return result.matchedCount > 0;
  } catch (error) {
    passwordLogger.error(`Error incrementing search count: ${error}`);
    return false;
  }
}

// Increment copy count for a password entry
export async function incrementCopyCount(entryId: string, userId: string): Promise<boolean> {
  const db = getDatabase();
  const passwordsCollection = db.collection<PasswordEntry>('passwords');

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

    let result = await passwordsCollection.updateOne(
      filter,
      {
        $inc: { copyCount: 1 }
      } as any
    );

    // If not matched and userId is a valid ObjectId, try with ObjectId
    if (result.matchedCount === 0 && ObjectId.isValid(userIdString)) {
      filter = {
        _id: new ObjectId(entryId),
        userId: new ObjectId(userIdString)
      };
      result = await passwordsCollection.updateOne(
        filter,
        {
          $inc: { copyCount: 1 }
        } as any
      );
    }

    return result.matchedCount > 0;
  } catch (error) {
    passwordLogger.error(`Error incrementing copy count: ${error}`);
    return false;
  }
}

