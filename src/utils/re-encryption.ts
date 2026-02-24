import { logger } from './logger';
import { getDatabase } from '../db/mongodb';
import { ObjectId } from 'mongodb';
import crypto from 'crypto';
import { encryptPassword, decryptPassword } from '../models/password';
import { encryptNoteContent, decryptNoteContent } from '../models/notes';

export interface ReEncryptionResult {
  passwords: {
    total: number;
    success: number;
    failed: number;
    errors: string[];
  };
  notes: {
    total: number;
    success: number;
    failed: number;
    errors: string[];
  };
  totp: {
    total: number;
    success: number;
    failed: number;
    errors: string[];
  };
}

/**
 * Re-encrypt all data with the current encryption key
 * This should be run after fallback keys have been used to decrypt data
 */
export async function reEncryptAllData(): Promise<ReEncryptionResult> {
  const result: ReEncryptionResult = {
    passwords: { total: 0, success: 0, failed: 0, errors: [] },
    notes: { total: 0, success: 0, failed: 0, errors: [] },
    totp: { total: 0, success: 0, failed: 0, errors: [] },
  };

  try {
    const db = getDatabase();

    // Re-encrypt passwords
    await reEncryptPasswords(db, result);
    
    // Re-encrypt notes
    await reEncryptNotes(db, result);
    
    // Re-encrypt TOTP secrets
    await reEncryptTotp(db, result);

    logger.info(`Re-encryption completed: ${result.passwords.success + result.notes.success + result.totp.success} items successful, ${result.passwords.failed + result.notes.failed + result.totp.failed} failed`);

  } catch (error: any) {
    logger.error(`Re-encryption failed: ${error.message || error}`);
    throw error;
  }

  return result;
}

/**
 * Re-encrypt all password entries
 */
async function reEncryptPasswords(db: any, result: ReEncryptionResult): Promise<void> {
  const passwordsCollection = db.collection('passwords');
  const passwords = await passwordsCollection.find({}).toArray();

  result.passwords.total = passwords.length;

  for (const password of passwords) {
    try {
      // Decrypt using fallback system
      const decryptedPassword = decryptPassword(password.password);
      const decryptedUsername = password.username ? decryptPassword(password.username) : '';
      const decryptedEmail = password.email ? decryptPassword(password.email) : '';
      const decryptedNotes = password.notes ? decryptPassword(password.notes) : '';

      // Re-encrypt with current key
      const newEncryptedPassword = encryptPassword(decryptedPassword);
      const newEncryptedUsername = decryptedUsername ? encryptPassword(decryptedUsername) : undefined;
      const newEncryptedEmail = decryptedEmail ? encryptPassword(decryptedEmail) : undefined;
      const newEncryptedNotes = decryptedNotes ? encryptPassword(decryptedNotes) : undefined;

      // Update the database
      const updateData: any = {
        password: newEncryptedPassword,
        updatedAt: new Date(),
      };

      if (newEncryptedUsername) updateData.username = newEncryptedUsername;
      if (newEncryptedEmail) updateData.email = newEncryptedEmail;
      if (newEncryptedNotes) updateData.notes = newEncryptedNotes;

      await passwordsCollection.updateOne(
        { _id: password._id },
        { $set: updateData }
      );

      result.passwords.success++;

    } catch (error: any) {
      result.passwords.failed++;
      const errorMsg = `Password ${password._id}: ${error.message || error}`;
      result.passwords.errors.push(errorMsg);
      logger.error(`Re-encryption failed for password ${password._id}: ${error.message || error}`);
    }
  }
}

/**
 * Re-encrypt all note entries
 */
async function reEncryptNotes(db: any, result: ReEncryptionResult): Promise<void> {
  const notesCollection = db.collection('notes');
  const notes = await notesCollection.find({}).toArray();

  result.notes.total = notes.length;

  for (const note of notes) {
    try {
      // Decrypt using fallback system
      const decryptedContent = decryptNoteContent(note.content);

      // Re-encrypt with current key
      const newEncryptedContent = encryptNoteContent(decryptedContent);

      // Update the database
      await notesCollection.updateOne(
        { _id: note._id },
        { 
          $set: {
            content: newEncryptedContent,
            updatedAt: new Date(),
          }
        }
      );

      result.notes.success++;

    } catch (error: any) {
      result.notes.failed++;
      const errorMsg = `Note ${note._id}: ${error.message || error}`;
      result.notes.errors.push(errorMsg);
      logger.error(`Re-encryption failed for note ${note._id}: ${error.message || error}`);
    }
  }
}

/**
 * Re-encrypt all TOTP entries
 */
async function reEncryptTotp(db: any, result: ReEncryptionResult): Promise<void> {
  const totpCollection = db.collection('totp');
  const totpEntries = await totpCollection.find({}).toArray();

  result.totp.total = totpEntries.length;

  for (const totp of totpEntries) {
    try {
      // Import decrypt function from TOTP model
      const { decrypt: decryptTotp, encrypt: encryptTotp } = await import('../models/totp');

      // Decrypt using fallback system
      const decryptedSecret = decryptTotp(totp.secret);

      // Re-encrypt with current key
      const newEncryptedSecret = encryptTotp(decryptedSecret);

      // Update the database
      await totpCollection.updateOne(
        { _id: totp._id },
        { 
          $set: {
            secret: newEncryptedSecret,
            lastUsedAt: new Date(),
          }
        }
      );

      result.totp.success++;

    } catch (error: any) {
      result.totp.failed++;
      const errorMsg = `TOTP ${totp._id}: ${error.message || error}`;
      result.totp.errors.push(errorMsg);
      logger.error(`Re-encryption failed for TOTP ${totp._id}: ${error.message || error}`);
    }
  }
}

/**
 * Check if any data is using fallback keys
 */
export async function checkFallbackKeyUsage(): Promise<{
  passwordsUsingFallback: number;
  notesUsingFallback: number;
  totpUsingFallback: number;
  totalEntries: number;
}> {
  const result = {
    passwordsUsingFallback: 0,
    notesUsingFallback: 0,
    totpUsingFallback: 0,
    totalEntries: 0,
  };

  try {
    const db = getDatabase();

    // Check passwords
    const passwordsCollection = db.collection('passwords');
    const passwords = await passwordsCollection.find({}).limit(50).toArray();
    
    for (const password of passwords) {
      try {
        // Try to decrypt with primary key only
        const { getEncryptionKey } = await import('../models/password');
        const key = getEncryptionKey();
        const algorithm = 'aes-256-cbc';
        
        const parts = password.password.split(':');
        if (parts.length === 2) {
          const iv = Buffer.from(parts[0], 'hex');
          const encryptedData = parts[1];
          const decipher = crypto.createDecipheriv(algorithm, key, iv);
          let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
          decrypted += decipher.final('utf8');
          // Success with primary key
        }
      } catch (error) {
        // Failed with primary key, using fallback
        result.passwordsUsingFallback++;
      }
      result.totalEntries++;
    }

    // Check notes
    const notesCollection = db.collection('notes');
    const notes = await notesCollection.find({}).limit(50).toArray();
    
    for (const note of notes) {
      try {
        const { getEncryptionKey } = await import('../models/notes');
        const key = getEncryptionKey();
        const algorithm = 'aes-256-cbc';
        
        const parts = note.content.split(':');
        if (parts.length === 2) {
          const iv = Buffer.from(parts[0], 'hex');
          const encryptedData = parts[1];
          const decipher = crypto.createDecipheriv(algorithm, key, iv);
          let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
          decrypted += decipher.final('utf8');
          // Success with primary key
        }
      } catch (error) {
        result.notesUsingFallback++;
      }
      result.totalEntries++;
    }

    // Check TOTP
    const totpCollection = db.collection('totp');
    const totpEntries = await totpCollection.find({}).limit(50).toArray();
    
    for (const totp of totpEntries) {
      try {
        const { getEncryptionKey } = await import('../models/totp');
        const key = getEncryptionKey();
        const algorithm = 'aes-256-cbc';
        
        const parts = totp.secret.split(':');
        if (parts.length === 2) {
          const iv = Buffer.from(parts[0], 'hex');
          const encryptedData = parts[1];
          const decipher = crypto.createDecipheriv(algorithm, key, iv);
          let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
          decrypted += decipher.final('utf8');
          // Success with primary key
        }
      } catch (error) {
        result.totpUsingFallback++;
      }
      result.totalEntries++;
    }

  } catch (error: any) {
    logger.error(`Failed to check fallback key usage: ${error.message || error}`);
  }

  return result;
}

/**
 * Generate HTML report for re-encryption results
 */
export function generateReEncryptionReport(result: ReEncryptionResult): string {
  const totalSuccess = result.passwords.success + result.notes.success + result.totp.success;
  const totalFailed = result.passwords.failed + result.notes.failed + result.totp.failed;
  const totalItems = totalSuccess + totalFailed;

  return `
    <div style="background: #1d1d1d; border: 1px solid #3d3d3d; padding: 1.5rem; border-radius: 8px; margin-bottom: 1rem;">
      <h3 style="margin-top: 0; color: #9db4d4; font-size: 1.1rem;">🔄 Re-encryption Results</h3>
      
      <div style="margin-bottom: 1rem;">
        <h4 style="margin: 0 0 0.5rem 0; color: #9db4d4; font-size: 0.9rem;">Overall Status</h4>
        <div style="display: flex; gap: 1rem; font-size: 0.8rem;">
          <span style="color: #7fb069;">✓ ${totalSuccess} successful</span>
          <span style="color: #d47d7d;">✗ ${totalFailed} failed</span>
          <span style="color: #888;">/ ${totalItems} total</span>
        </div>
      </div>

      <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 1rem; margin-bottom: 1rem;">
        <div style="background: #2d2d2d; padding: 0.75rem; border-radius: 4px;">
          <h5 style="margin: 0 0 0.5rem 0; color: #9db4d4; font-size: 0.8rem;">Passwords</h5>
          <div style="font-size: 0.7rem;">
            <div style="color: #7fb069;">✓ ${result.passwords.success}</div>
            <div style="color: #d47d7d;">✗ ${result.passwords.failed}</div>
            <div style="color: #888;">/ ${result.passwords.total}</div>
          </div>
        </div>
        <div style="background: #2d2d2d; padding: 0.75rem; border-radius: 4px;">
          <h5 style="margin: 0 0 0.5rem 0; color: #9db4d4; font-size: 0.8rem;">Notes</h5>
          <div style="font-size: 0.7rem;">
            <div style="color: #7fb069;">✓ ${result.notes.success}</div>
            <div style="color: #d47d7d;">✗ ${result.notes.failed}</div>
            <div style="color: #888;">/ ${result.notes.total}</div>
          </div>
        </div>
        <div style="background: #2d2d2d; padding: 0.75rem; border-radius: 4px;">
          <h5 style="margin: 0 0 0.5rem 0; color: #9db4d4; font-size: 0.8rem;">TOTP</h5>
          <div style="font-size: 0.7rem;">
            <div style="color: #7fb069;">✓ ${result.totp.success}</div>
            <div style="color: #d47d7d;">✗ ${result.totp.failed}</div>
            <div style="color: #888;">/ ${result.totp.total}</div>
          </div>
        </div>
      </div>

      ${totalFailed > 0 ? `
        <div style="margin-bottom: 1rem;">
          <h4 style="margin: 0 0 0.5rem 0; color: #d47d7d; font-size: 0.9rem;">Errors</h4>
          <div style="background: #2d1a1a; border: 1px solid #5d3d3d; padding: 0.5rem; border-radius: 4px; font-family: monospace; font-size: 0.7rem; color: #d4a5a5; max-height: 200px; overflow-y: auto;">
            ${[...result.passwords.errors, ...result.notes.errors, ...result.totp.errors].map(error => `• ${error}`).join('<br>')}
          </div>
        </div>
      ` : ''}

      <div>
        <h4 style="margin: 0 0 0.5rem 0; color: #9db4d4; font-size: 0.9rem;">Recommendations</h4>
        <div style="background: #2d2d2d; border: 1px solid #3d3d3d; padding: 0.75rem; border-radius: 4px;">
          ${totalFailed === 0 ? `
            <p style="margin: 0.25rem 0; color: #7fb069; font-size: 0.8rem;">
              ✅ All data successfully re-encrypted with current key
            </p>
            <p style="margin: 0.25rem 0; color: #9db4d4; font-size: 0.8rem;">
              💡 Your data is now fully migrated to the current encryption key
            </p>
          ` : `
            <p style="margin: 0.25rem 0; color: #d4a5a5; font-size: 0.8rem;">
              ⚠️ ${totalFailed} items failed to re-encrypt
            </p>
            <p style="margin: 0.25rem 0; color: #9db4d4; font-size: 0.8rem;">
              💡 Check the errors above and consider manual intervention
            </p>
          `}
          <p style="margin: 0.25rem 0; color: #9db4d4; font-size: 0.8rem;">
            🔐 Always backup your encryption key and database regularly
          </p>
        </div>
      </div>
    </div>
  `;
}
