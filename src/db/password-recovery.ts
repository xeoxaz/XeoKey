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
function attemptDecrypt(encrypted: string, masterKey?: string): { success: boolean; password?: string; error?: string } {
  try {
    const algorithm = 'aes-256-cbc';
    const key = getEncryptionKey(masterKey);

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
    const decryptResult = attemptDecrypt(encryptedPassword);

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
    });
  }

  return recoveryEntries;
}

/**
 * Attempt to recover password using master key
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

    const result = attemptDecrypt(entry.password, masterKey);
    return result;
  } catch (error: any) {
    return { success: false, error: error.message };
  }
}

/**
 * Repair password entry by re-encrypting with correct key
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
      const decryptResult = attemptDecrypt(entry.encryptedPassword, masterKey);

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

