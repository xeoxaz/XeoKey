import { logger } from './logger';
import { getDatabase } from '../db/mongodb';
import { decryptPassword, encryptPassword, getEncryptionKey } from '../models/password';
import { decryptNoteContent, encryptNoteContent } from '../models/notes';
import { decrypt, encrypt } from '../models/totp';

export interface ReEncryptionDebug {
  passwords: {
    total: number;
    decryptable: number;
    failed: number;
    errors: string[];
    sampleFailed: Array<{ id: string; error: string; encrypted: string }>;
  };
  notes: {
    total: number;
    decryptable: number;
    failed: number;
    errors: string[];
    sampleFailed: Array<{ id: string; error: string; encrypted: string }>;
  };
  totp: {
    total: number;
    decryptable: number;
    failed: number;
    errors: string[];
    sampleFailed: Array<{ id: string; error: string; encrypted: string }>;
  };
  currentKeyInfo: {
    hash: string;
    length: number;
    environment: string;
  };
}

/**
 * Debug re-encryption process by testing decryption and re-encryption
 */
export async function debugReEncryption(): Promise<ReEncryptionDebug> {
  const result: ReEncryptionDebug = {
    passwords: { total: 0, decryptable: 0, failed: 0, errors: [], sampleFailed: [] },
    notes: { total: 0, decryptable: 0, failed: 0, errors: [], sampleFailed: [] },
    totp: { total: 0, decryptable: 0, failed: 0, errors: [], sampleFailed: [] },
    currentKeyInfo: {
      hash: '',
      length: 0,
      environment: '',
    },
  };

  try {
    const db = getDatabase();

    // Get current key info
    const currentKey = getEncryptionKey();
    result.currentKeyInfo = {
      hash: require('crypto').createHash('sha256').update(currentKey).digest('hex').substring(0, 16),
      length: currentKey.length,
      environment: process.env.NODE_ENV || 'development',
    };

    logger.info(`Current key: hash=${result.currentKeyInfo.hash}, length=${result.currentKeyInfo.length}`);

    // Test passwords
    await debugPasswordReEncryption(db, result);
    
    // Test notes
    await debugNoteReEncryption(db, result);
    
    // Test TOTP
    await debugTotpReEncryption(db, result);

    logger.info(`Re-encryption debug completed:
      Passwords: ${result.passwords.decryptable}/${result.passwords.total} decryptable
      Notes: ${result.notes.decryptable}/${result.notes.total} decryptable  
      TOTP: ${result.totp.decryptable}/${result.totp.total} decryptable
      Total failures: ${result.passwords.failed + result.notes.failed + result.totp.failed}`);

  } catch (error: any) {
    logger.error(`Re-encryption debug failed: ${error.message || error}`);
    throw error;
  }

  return result;
}

async function debugPasswordReEncryption(db: any, result: ReEncryptionDebug): Promise<void> {
  const passwordsCollection = db.collection('passwords');
  const passwords = await passwordsCollection.find({}).limit(20).toArray(); // Limit to first 20 for debugging

  result.passwords.total = passwords.length;

  for (const password of passwords) {
    try {
      // Test decryption
      const decryptedPassword = await decryptPassword(password.password);
      result.passwords.decryptable++;

      // Test re-encryption
      const reEncryptedPassword = encryptPassword(decryptedPassword);
      
      // Test that re-encrypted data can be decrypted
      const testDecryption = await decryptPassword(reEncryptedPassword);
      
      if (testDecryption !== decryptedPassword) {
        result.passwords.failed++;
        result.passwords.errors.push(`Password ${password._id}: Re-encryption test failed - data mismatch`);
        result.passwords.sampleFailed.push({
          id: password._id?.toString() || 'unknown',
          error: 'Re-encryption test failed - data mismatch',
          encrypted: password.password.substring(0, 50) + '...'
        });
      }

    } catch (error: any) {
      result.passwords.failed++;
      const errorMsg = `Password ${password._id}: ${error.message || error}`;
      result.passwords.errors.push(errorMsg);
      result.passwords.sampleFailed.push({
        id: password._id?.toString() || 'unknown',
        error: error.message || 'Unknown error',
        encrypted: password.password.substring(0, 50) + '...'
      });
      logger.error(`Password re-encryption debug failed for ${password._id}: ${error.message || error}`);
    }
  }
}

async function debugNoteReEncryption(db: any, result: ReEncryptionDebug): Promise<void> {
  const notesCollection = db.collection('notes');
  const notes = await notesCollection.find({}).limit(20).toArray(); // Limit to first 20 for debugging

  result.notes.total = notes.length;

  for (const note of notes) {
    try {
      // Test decryption
      const decryptedContent = await decryptNoteContent(note.content);
      result.notes.decryptable++;

      // Test re-encryption
      const reEncryptedContent = encryptNoteContent(decryptedContent);
      
      // Test that re-encrypted data can be decrypted
      const testDecryption = await decryptNoteContent(reEncryptedContent);
      
      if (testDecryption !== decryptedContent) {
        result.notes.failed++;
        result.notes.errors.push(`Note ${note._id}: Re-encryption test failed - data mismatch`);
        result.notes.sampleFailed.push({
          id: note._id?.toString() || 'unknown',
          error: 'Re-encryption test failed - data mismatch',
          encrypted: note.content.substring(0, 50) + '...'
        });
      }

    } catch (error: any) {
      result.notes.failed++;
      const errorMsg = `Note ${note._id}: ${error.message || error}`;
      result.notes.errors.push(errorMsg);
      result.notes.sampleFailed.push({
        id: note._id?.toString() || 'unknown',
        error: error.message || 'Unknown error',
        encrypted: note.content.substring(0, 50) + '...'
      });
      logger.error(`Note re-encryption debug failed for ${note._id}: ${error.message || error}`);
    }
  }
}

async function debugTotpReEncryption(db: any, result: ReEncryptionDebug): Promise<void> {
  const totpCollection = db.collection('totp');
  const totpEntries = await totpCollection.find({}).limit(20).toArray(); // Limit to first 20 for debugging

  result.totp.total = totpEntries.length;

  for (const totp of totpEntries) {
    try {
      // Test decryption
      const decryptedSecret = await decrypt(totp.secret);
      result.totp.decryptable++;

      // Test re-encryption
      const reEncryptedSecret = encrypt(decryptedSecret);
      
      // Test that re-encrypted data can be decrypted
      const testDecryption = await decrypt(reEncryptedSecret);
      
      if (testDecryption !== decryptedSecret) {
        result.totp.failed++;
        result.totp.errors.push(`TOTP ${totp._id}: Re-encryption test failed - data mismatch`);
        result.totp.sampleFailed.push({
          id: totp._id?.toString() || 'unknown',
          error: 'Re-encryption test failed - data mismatch',
          encrypted: totp.secret.substring(0, 50) + '...'
        });
      }

    } catch (error: any) {
      result.totp.failed++;
      const errorMsg = `TOTP ${totp._id}: ${error.message || error}`;
      result.totp.errors.push(errorMsg);
      result.totp.sampleFailed.push({
        id: totp._id?.toString() || 'unknown',
        error: error.message || 'Unknown error',
        encrypted: totp.secret.substring(0, 50) + '...'
      });
      logger.error(`TOTP re-encryption debug failed for ${totp._id}: ${error.message || error}`);
    }
  }
}

/**
 * Generate HTML report for re-encryption debug
 */
export function generateReEncryptionDebugReport(debug: ReEncryptionDebug): string {
  const totalSuccess = debug.passwords.decryptable + debug.notes.decryptable + debug.totp.decryptable;
  const totalFailed = debug.passwords.failed + debug.notes.failed + debug.totp.failed;
  const totalItems = totalSuccess + totalFailed;

  return `
    <div style="background: #1d1d1d; border: 1px solid #3d3d3d; padding: 1.5rem; border-radius: 8px; margin-bottom: 1rem;">
      <h3 style="margin-top: 0; color: #9db4d4; font-size: 1.1rem;">🔍 Re-Encryption Debug Report</h3>
      
      <div style="margin-bottom: 1rem;">
        <h4 style="margin: 0 0 0.5rem 0; color: #9db4d4; font-size: 0.9rem;">Current Key Information</h4>
        <div style="background: #2d2d2d; padding: 0.75rem; border-radius: 4px; font-family: monospace; font-size: 0.8rem;">
          <div>Hash: ${debug.currentKeyInfo.hash}</div>
          <div>Length: ${debug.currentKeyInfo.length} bytes</div>
          <div>Environment: ${debug.currentKeyInfo.environment}</div>
        </div>
      </div>

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
            <div style="color: #7fb069;">✓ ${debug.passwords.decryptable}</div>
            <div style="color: #d47d7d;">✗ ${debug.passwords.failed}</div>
            <div style="color: #888;">/ ${debug.passwords.total}</div>
          </div>
        </div>
        <div style="background: #2d2d2d; padding: 0.75rem; border-radius: 4px;">
          <h5 style="margin: 0 0 0.5rem 0; color: #9db4d4; font-size: 0.8rem;">Notes</h5>
          <div style="font-size: 0.7rem;">
            <div style="color: #7fb069;">✓ ${debug.notes.decryptable}</div>
            <div style="color: #d47d7d;">✗ ${debug.notes.failed}</div>
            <div style="color: #888;">/ ${debug.notes.total}</div>
          </div>
        </div>
        <div style="background: #2d2d2d; padding: 0.75rem; border-radius: 4px;">
          <h5 style="margin: 0 0 0.5rem 0; color: #9db4d4; font-size: 0.8rem;">TOTP</h5>
          <div style="font-size: 0.7rem;">
            <div style="color: #7fb069;">✓ ${debug.totp.decryptable}</div>
            <div style="color: #d47d7d;">✗ ${debug.totp.failed}</div>
            <div style="color: #888;">/ ${debug.totp.total}</div>
          </div>
        </div>
      </div>

      ${totalFailed > 0 ? `
        <div style="margin-bottom: 1rem;">
          <h4 style="margin: 0 0 0.5rem 0; color: #d47d7d; font-size: 0.9rem;">Sample Failures</h4>
          <div style="background: #2d1a1a; border: 1px solid #5d3d3d; padding: 0.5rem; border-radius: 4px; font-family: monospace; font-size: 0.7rem; color: #d4a5a5; max-height: 200px; overflow-y: auto;">
            ${[...debug.passwords.sampleFailed, ...debug.notes.sampleFailed, ...debug.totp.sampleFailed].slice(0, 10).map(failure => `• ${failure.id}: ${failure.error}`).join('<br>')}
          </div>
        </div>
      ` : ''}

      <div>
        <h4 style="margin: 0 0 0.5rem 0; color: #9db4d4; font-size: 0.9rem;">Recommendations</h4>
        <div style="background: #2d2d2d; border: 1px solid #3d3d3d; padding: 0.75rem; border-radius: 4px;">
          ${totalFailed === 0 ? `
            <p style="margin: 0.25rem 0; color: #7fb069; font-size: 0.8rem;">
              ✅ All tested items can be decrypted and re-encrypted successfully
            </p>
            <p style="margin: 0.25rem 0; color: #9db4d4; font-size: 0.8rem;">
              💡 Re-encryption should work properly
            </p>
          ` : `
            <p style="margin: 0.25rem 0; color: #d4a5a5; font-size: 0.8rem;">
              ⚠️ ${totalFailed} items failed re-encryption test
            </p>
            <p style="margin: 0.25rem 0; color: #9db4d4; font-size: 0.8rem;">
              💡 Check the sample failures above for specific error details
            </p>
            <p style="margin: 0.25rem 0; color: #9db4d4; font-size: 0.8rem;">
              🔧 This may indicate a key mismatch or encryption format issue
            </p>
          `}
        </div>
      </div>
    </div>
  `;
}
