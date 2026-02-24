import { getDatabase } from './mongodb';
import { ObjectId } from 'mongodb';
import { dbLogger } from '../utils/logger';
import { getPasswordEntry } from '../models/password';
import * as crypto from 'crypto';

export interface PasswordRecoveryEntry {
  entryId: string;
  website: string;
  username?: string;
  email?: string;
  encryptedPassword: string;
  encryptedFormat: string;
  decryptionError?: string;
  canDecrypt: boolean;
  decryptedPassword?: string;
  // Composite identifier for recovery operations
  identifier: {
    website: string;
    username?: string;
    email?: string;
  };
}

export interface RecoveryResult {
  success: boolean;
  recovered: number;
  failed: number;
  entries: PasswordRecoveryEntry[];
  error?: string;
}

/**
 * Get encryption key from environment or master password
 */
function getEncryptionKey(masterKey?: string): Buffer {
  const key = masterKey || process.env.ENCRYPTION_KEY || 'default-encryption-key-change-in-production';
  // Generate 32-byte key for AES-256
  return crypto.createHash('sha256').update(key).digest();
}

/**
 * Attempt to decrypt password with given key
 */
async function attemptDecrypt(encrypted: string, masterKey?: string): Promise<{ success: boolean; password?: string; error?: string }> {
  try {
    // If masterKey is provided, use the old logic for master key recovery
    if (masterKey) {
      const algorithm = 'aes-256-cbc';
      const key = crypto.createHash('sha256').update(masterKey).digest();

      const parts = encrypted.split(':');
      if (parts.length !== 2) {
        return { success: false, error: 'Invalid encrypted password format (expected iv:data)' };
      }

      const iv = Buffer.from(parts[0], 'hex');
      const encryptedData = parts[1];

      // Validate IV is 16 bytes (32 hex characters)
      if (iv.length !== 16) {
        return { success: false, error: `Invalid IV length: ${iv.length} bytes (expected 16)` };
      }

      // Validate encrypted data is hex
      if (!/^[0-9a-f]+$/i.test(encryptedData)) {
        return { success: false, error: 'Invalid encrypted data format (not hex)' };
      }

      const decipher = crypto.createDecipheriv(algorithm, key, iv);
      let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
      decrypted += decipher.final('utf8');

      // Validate decrypted result is not empty
      if (!decrypted || decrypted.trim() === '') {
        return { success: false, error: 'Decryption succeeded but result is empty' };
      }

      return { success: true, password: decrypted };
    } else {
      // Use the new decryptPassword function with fallback support
      const { decryptPassword } = await import('../models/password');
      const decrypted = decryptPassword(encrypted);
      
      // Validate decrypted result is not empty
      if (!decrypted || decrypted.trim() === '') {
        return { success: false, error: 'Decryption succeeded but result is empty' };
      }

      return { success: true, password: decrypted };
    }
  } catch (error: any) {
    const errorMessage = error.message || String(error);
    // Provide more specific error messages
    if (errorMessage.includes('BAD_DECRYPT') || errorMessage.includes('bad decrypt')) {
      return {
        success: false,
        error: 'Decryption failed: The master password/encryption key does not match the key used to encrypt this password. Make sure you\'re using the exact same key that was used when the password was first encrypted.'
      };
    }
    if (errorMessage.includes('Invalid key length')) {
      return { success: false, error: `Invalid key: ${errorMessage}` };
    }
    if (errorMessage.includes('Invalid iv length')) {
      return { success: false, error: `Invalid IV: ${errorMessage}` };
    }
    return { success: false, error: `Decryption error: ${errorMessage}` };
  }
}

/**
 * Re-encrypt password with current encryption key
 */
export function reEncryptPassword(plaintextPassword: string): string {
  const algorithm = 'aes-256-cbc';
  const key = getEncryptionKey();
  const iv = crypto.randomBytes(16);

  const cipher = crypto.createCipheriv(algorithm, key, iv);
  let encrypted = cipher.update(plaintextPassword, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  return iv.toString('hex') + ':' + encrypted;
}

/**
 * Get all passwords that cannot be decrypted for recovery
 */
export async function getUnrecoverablePasswords(userId: string): Promise<PasswordRecoveryEntry[]> {
  const db = getDatabase();
  const passwordsCollection = db.collection('passwords');

  const userIdString = typeof userId === 'string' ? userId : (userId as any).toString();

  // Query for all passwords for this user
  const queryConditions: any[] = [{ userId: userIdString }];
  if (ObjectId.isValid(userIdString)) {
    queryConditions.push({ userId: new ObjectId(userIdString) });
  }

  const passwords = await passwordsCollection.find({
    $or: queryConditions
  } as any).toArray();

  const recoveryEntries: PasswordRecoveryEntry[] = [];

  for (const password of passwords) {
    const entryId = password._id?.toString();
    if (!entryId) continue;

    const encryptedPassword = password.password;
    if (!encryptedPassword || typeof encryptedPassword !== 'string') {
      continue;
    }

    // Try to decrypt with current key
    const decryptResult = await attemptDecrypt(encryptedPassword);

    recoveryEntries.push({
      entryId,
      website: password.website || 'Unknown',
      username: password.username,
      email: password.email,
      encryptedPassword,
      encryptedFormat: encryptedPassword.includes(':') ? 'iv:data' : 'unknown',
      decryptionError: decryptResult.error,
      canDecrypt: decryptResult.success,
      decryptedPassword: decryptResult.password,
      identifier: {
        website: password.website || 'Unknown',
        username: password.username,
        email: password.email,
      },
    });
  }

  return recoveryEntries;
}

/**
 * Attempt to recover password using master key (by entryId)
 */
export async function recoverPasswordWithMasterKey(
  entryId: string,
  userId: string,
  masterKey: string
): Promise<{ success: boolean; decryptedPassword?: string; error?: string }> {
  try {
    const entry = await getPasswordEntry(entryId, userId);
    if (!entry) {
      return { success: false, error: 'Password entry not found' };
    }

    const result = await attemptDecrypt(entry.password, masterKey);
    return result;
  } catch (error: any) {
    return { success: false, error: error.message };
  }
}

/**
 * Attempt to recover password using master key (by website/username/email)
 */
export async function recoverPasswordByIdentifier(
  userId: string,
  website: string,
  masterKey: string,
  username?: string,
  email?: string
): Promise<{ success: boolean; decryptedPassword?: string; entryId?: string; error?: string }> {
  try {
    const { findPasswordEntriesByIdentifier } = await import('../models/password');
    const entries = await findPasswordEntriesByIdentifier(userId, website, username, email);

    if (entries.length === 0) {
      return { success: false, error: 'No matching password entry found' };
    }

    // Try to decrypt the first matching entry
    const entry = entries[0];
    if (!entry.password) {
      return { success: false, error: 'Password entry has no encrypted password data' };
    }

    const result = await attemptDecrypt(entry.password, masterKey);
    if (result.success && result.password) {
      return {
        success: true,
        decryptedPassword: result.password,
        entryId: entry._id,
      };
    }

    return result;
  } catch (error: any) {
    return { success: false, error: error.message };
  }
}

/**
 * Repair password entry by re-encrypting with correct key (by entryId)
 */
export async function repairPasswordEntry(
  entryId: string,
  userId: string,
  plaintextPassword: string
): Promise<{ success: boolean; error?: string }> {
  try {
    const db = getDatabase();
    const passwordsCollection = db.collection('passwords');

    if (!ObjectId.isValid(entryId)) {
      return { success: false, error: 'Invalid entry ID' };
    }

    const userIdString = typeof userId === 'string' ? userId : (userId as any).toString();

    // Verify entry exists and belongs to user
    const entry = await getPasswordEntry(entryId, userIdString);
    if (!entry) {
      return { success: false, error: 'Password entry not found or does not belong to user' };
    }

    // Re-encrypt with current key
    const reEncrypted = reEncryptPassword(plaintextPassword);

    // Update the password
    const result = await passwordsCollection.updateOne(
      { _id: new ObjectId(entryId) },
      {
        $set: {
          password: reEncrypted,
          updatedAt: new Date(),
        }
      }
    );

    if (result.matchedCount === 0) {
      return { success: false, error: 'Failed to update password entry' };
    }

    dbLogger.info(`Password entry ${entryId} repaired successfully`);
    return { success: true };
  } catch (error: any) {
    dbLogger.error(`Error repairing password entry: ${error.message}`);
    return { success: false, error: error.message };
  }
}

/**
 * Repair password entry by identifier (website/username/email)
 */
export async function repairPasswordEntryByIdentifier(
  userId: string,
  website: string,
  plaintextPassword: string,
  username?: string,
  email?: string
): Promise<{ success: boolean; repairedCount: number; error?: string }> {
  try {
    const { findPasswordEntriesByIdentifier } = await import('../models/password');
    const entries = await findPasswordEntriesByIdentifier(userId, website, username, email);

    if (entries.length === 0) {
      return { success: false, repairedCount: 0, error: 'No matching password entries found' };
    }

    const db = getDatabase();
    const passwordsCollection = db.collection('passwords');
    const reEncrypted = reEncryptPassword(plaintextPassword);

    let repairedCount = 0;
    for (const entry of entries) {
      if (!entry._id) continue;

      try {
        const result = await passwordsCollection.updateOne(
          { _id: new ObjectId(entry._id) },
          {
            $set: {
              password: reEncrypted,
              updatedAt: new Date(),
            }
          }
        );

        if (result.matchedCount > 0) {
          repairedCount++;
          dbLogger.info(`Password entry ${entry._id} (${website}${username ? ` / ${username}` : ''}${email ? ` / ${email}` : ''}) repaired successfully`);
        }
      } catch (error: any) {
        dbLogger.error(`Error repairing entry ${entry._id}: ${error.message || error}`);
      }
    }

    return { success: repairedCount > 0, repairedCount };
  } catch (error: any) {
    dbLogger.error(`Error repairing password entry by identifier: ${error.message || error}`);
    return { success: false, repairedCount: 0, error: error.message || 'Unknown error' };
  }
}

/**
 * Batch recover and repair passwords
 */
export async function batchRecoverPasswords(
  userId: string,
  masterKey: string
): Promise<RecoveryResult> {
  const result: RecoveryResult = {
    success: false,
    recovered: 0,
    failed: 0,
    entries: [],
  };

  try {
    const unrecoverable = await getUnrecoverablePasswords(userId);
    result.entries = unrecoverable;

    for (const entry of unrecoverable) {
      if (entry.canDecrypt) {
        // Already can decrypt, skip
        continue;
      }

      // Try to decrypt with master key
      const decryptResult = await attemptDecrypt(entry.encryptedPassword, masterKey);

      if (decryptResult.success && decryptResult.password) {
        // Try to repair
        const repairResult = await repairPasswordEntry(entry.entryId, userId, decryptResult.password);

        if (repairResult.success) {
          result.recovered++;
          entry.canDecrypt = true;
          entry.decryptedPassword = decryptResult.password;
        } else {
          result.failed++;
          entry.decryptionError = repairResult.error || 'Repair failed';
        }
      } else {
        result.failed++;
        // Provide more detailed error message
        const errorMsg = decryptResult.error || 'Decryption failed';
        entry.decryptionError = errorMsg;
        dbLogger.warn(`Failed to decrypt password ${entry.entryId} with master key: ${errorMsg}`);
      }
    }

    result.success = result.failed === 0;
    return result;
  } catch (error: any) {
    result.error = error.message;
    return result;
  }
}

