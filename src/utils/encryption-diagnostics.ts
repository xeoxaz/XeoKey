import { logger } from './logger';
import { getDatabase } from '../db/mongodb';
import { ObjectId } from 'mongodb';
import crypto from 'crypto';

export interface EncryptionDiagnostic {
  currentKey: string;
  keyHash: string;
  passwordEntries: {
    total: number;
    decryptable: number;
    failed: number;
    sampleErrors: string[];
  };
  noteEntries: {
    total: number;
    decryptable: number;
    failed: number;
    sampleErrors: string[];
  };
  recommendations: string[];
}

/**
 * Comprehensive encryption diagnostics to identify key mismatches
 */
export async function runEncryptionDiagnostics(): Promise<EncryptionDiagnostic> {
  const diagnostic: EncryptionDiagnostic = {
    currentKey: process.env.ENCRYPTION_KEY || 'default-encryption-key-change-in-production',
    keyHash: '',
    passwordEntries: { total: 0, decryptable: 0, failed: 0, sampleErrors: [] },
    noteEntries: { total: 0, decryptable: 0, failed: 0, sampleErrors: [] },
    recommendations: [],
  };

  // Generate key hash for comparison (don't log the actual key)
  diagnostic.keyHash = crypto.createHash('sha256').update(diagnostic.currentKey).digest('hex').substring(0, 16);

  try {
    const db = getDatabase();

    // Test password entries
    const passwordsCollection = db.collection('passwords');
    const passwordEntries = await passwordsCollection.find({}).limit(10).toArray();

    diagnostic.passwordEntries.total = passwordEntries.length;

    for (const entry of passwordEntries) {
      try {
        if (entry.password && typeof entry.password === 'string') {
          // Test decryption
          testPasswordDecryption(entry.password);
          diagnostic.passwordEntries.decryptable++;
        }
      } catch (error: any) {
        diagnostic.passwordEntries.failed++;
        const errorMsg = error.message || String(error);
        
        if (diagnostic.passwordEntries.sampleErrors.length < 3) {
          diagnostic.passwordEntries.sampleErrors.push(errorMsg);
        }
      }
    }

    // Test note entries
    const notesCollection = db.collection('notes');
    const noteEntries = await notesCollection.find({}).limit(10).toArray();

    diagnostic.noteEntries.total = noteEntries.length;

    for (const entry of noteEntries) {
      try {
        if (entry.content && typeof entry.content === 'string') {
          // Test decryption
          testNoteDecryption(entry.content);
          diagnostic.noteEntries.decryptable++;
        }
      } catch (error: any) {
        diagnostic.noteEntries.failed++;
        const errorMsg = error.message || String(error);
        
        if (diagnostic.noteEntries.sampleErrors.length < 3) {
          diagnostic.noteEntries.sampleErrors.push(errorMsg);
        }
      }
    }

    // Generate recommendations
    diagnostic.recommendations = generateRecommendations(diagnostic);

    logger.info(`Encryption diagnostic completed: ${diagnostic.passwordEntries.decryptable}/${diagnostic.passwordEntries.total} passwords decryptable`);

  } catch (error: any) {
    logger.error(`Encryption diagnostic failed: ${error.message || error}`);
    diagnostic.recommendations.push('Database connection failed. Check MongoDB connectivity.');
  }

  return diagnostic;
}

/**
 * Test password decryption without exposing data
 */
function testPasswordDecryption(encrypted: string): void {
  const algorithm = 'aes-256-cbc';
  const key = getEncryptionKey();

  const parts = encrypted.split(':');
  if (parts.length !== 2) {
    throw new Error('Invalid encrypted password format');
  }

  const iv = Buffer.from(parts[0], 'hex');
  const encryptedData = parts[1];

  const decipher = crypto.createDecipheriv(algorithm, key, iv);
  let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
}

/**
 * Test note decryption without exposing data
 */
function testNoteDecryption(encrypted: string): void {
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
}

/**
 * Get encryption key (same as in models)
 */
function getEncryptionKey(): Buffer {
  const key = process.env.ENCRYPTION_KEY || 'default-encryption-key-change-in-production';
  if (process.env.NODE_ENV === 'production' && key === 'default-encryption-key-change-in-production') {
    throw new Error('ENCRYPTION_KEY environment variable must be set in production');
  }
  return crypto.createHash('sha256').update(key).digest();
}

/**
 * Generate recommendations based on diagnostic results
 */
function generateRecommendations(diagnostic: EncryptionDiagnostic): string[] {
  const recommendations: string[] = [];

  // Check for default key
  if (diagnostic.currentKey === 'default-encryption-key-change-in-production') {
    recommendations.push('CRITICAL: Using default encryption key. Set ENCRYPTION_KEY environment variable.');
  }

  // Check for high failure rates
  const totalFailures = diagnostic.passwordEntries.failed + diagnostic.noteEntries.failed;
  const totalEntries = diagnostic.passwordEntries.total + diagnostic.noteEntries.total;

  if (totalEntries > 0) {
    const failureRate = totalFailures / totalEntries;
    
    if (failureRate > 0.5) {
      recommendations.push('HIGH: More than 50% of entries cannot be decrypted. Encryption key has likely changed.');
      recommendations.push('ACTION: Restore the original ENCRYPTION_KEY used when passwords were created.');
    } else if (failureRate > 0.1) {
      recommendations.push('MEDIUM: Some entries cannot be decrypted. Key may have been changed recently.');
    }
  }

  // Check for specific error patterns
  const allErrors = [...diagnostic.passwordEntries.sampleErrors, ...diagnostic.noteEntries.sampleErrors];
  
  if (allErrors.some(error => error.includes('BAD_DECRYPT'))) {
    recommendations.push('ISSUE: BAD_DECRYPT errors indicate encryption key mismatch.');
    recommendations.push('SOLUTION: Use the original ENCRYPTION_KEY or recover data using password recovery.');
  }

  if (allErrors.some(error => error.includes('Invalid encrypted'))) {
    recommendations.push('ISSUE: Data format corruption detected.');
    recommendations.push('SOLUTION: Some entries may be permanently corrupted and need manual recreation.');
  }

  // General recommendations
  if (diagnostic.passwordEntries.failed > 0 || diagnostic.noteEntries.failed > 0) {
    recommendations.push('RECOVERY: Use the password recovery feature with the original master password.');
    recommendations.push('PREVENTION: Backup your ENCRYPTION_KEY and environment variables.');
  }

  if (recommendations.length === 0) {
    recommendations.push('GOOD: All tested entries can be decrypted successfully.');
    recommendations.push('MAINTENANCE: Regularly backup your encryption configuration.');
  }

  return recommendations;
}

/**
 * Generate HTML report for diagnostics
 */
export function generateDiagnosticReport(diagnostic: EncryptionDiagnostic): string {
  const totalEntries = diagnostic.passwordEntries.total + diagnostic.noteEntries.total;
  const totalDecryptable = diagnostic.passwordEntries.decryptable + diagnostic.noteEntries.decryptable;
  const totalFailed = diagnostic.passwordEntries.failed + diagnostic.noteEntries.failed;
  const successRate = totalEntries > 0 ? (totalDecryptable / totalEntries * 100).toFixed(1) : '0';

  return `
    <div style="background: #1d1d1d; border: 1px solid #3d3d3d; padding: 1.5rem; border-radius: 8px; margin-bottom: 1rem;">
      <h3 style="margin-top: 0; color: #9db4d4; font-size: 1.1rem;">🔍 Encryption Diagnostics</h3>
      
      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1rem;">
        <div style="background: #2d2d2d; padding: 0.75rem; border-radius: 4px;">
          <p style="margin: 0; color: #888; font-size: 0.8rem;">Current Key Hash</p>
          <p style="margin: 0.25rem 0 0 0; color: #7fb069; font-family: monospace; font-size: 0.9rem;">${diagnostic.keyHash}</p>
        </div>
        <div style="background: #2d2d2d; padding: 0.75rem; border-radius: 4px;">
          <p style="margin: 0; color: #888; font-size: 0.8rem;">Success Rate</p>
          <p style="margin: 0.25rem 0 0 0; color: ${successRate >= '90' ? '#7fb069' : successRate >= '50' ? '#d4a5a5' : '#d47d7d'}; font-family: monospace; font-size: 0.9rem;">${successRate}%</p>
        </div>
      </div>

      <div style="margin-bottom: 1rem;">
        <h4 style="margin: 0 0 0.5rem 0; color: #9db4d4; font-size: 0.9rem;">Password Entries</h4>
        <div style="display: flex; gap: 1rem; font-size: 0.8rem;">
          <span style="color: #7fb069;">✓ ${diagnostic.passwordEntries.decryptable} decryptable</span>
          <span style="color: #d47d7d;">✗ ${diagnostic.passwordEntries.failed} failed</span>
          <span style="color: #888;">/ ${diagnostic.passwordEntries.total} total</span>
        </div>
      </div>

      <div style="margin-bottom: 1rem;">
        <h4 style="margin: 0 0 0.5rem 0; color: #9db4d4; font-size: 0.9rem;">Note Entries</h4>
        <div style="display: flex; gap: 1rem; font-size: 0.8rem;">
          <span style="color: #7fb069;">✓ ${diagnostic.noteEntries.decryptable} decryptable</span>
          <span style="color: #d47d7d;">✗ ${diagnostic.noteEntries.failed} failed</span>
          <span style="color: #888;">/ ${diagnostic.noteEntries.total} total</span>
        </div>
      </div>

      ${diagnostic.passwordEntries.sampleErrors.length > 0 || diagnostic.noteEntries.sampleErrors.length > 0 ? `
        <div style="margin-bottom: 1rem;">
          <h4 style="margin: 0 0 0.5rem 0; color: #d47d7d; font-size: 0.9rem;">Sample Errors</h4>
          <div style="background: #2d1a1a; border: 1px solid #5d3d3d; padding: 0.5rem; border-radius: 4px; font-family: monospace; font-size: 0.7rem; color: #d4a5a5;">
            ${[...diagnostic.passwordEntries.sampleErrors, ...diagnostic.noteEntries.sampleErrors].map(error => `• ${error}`).join('<br>')}
          </div>
        </div>
      ` : ''}

      <div>
        <h4 style="margin: 0 0 0.5rem 0; color: #9db4d4; font-size: 0.9rem;">Recommendations</h4>
        <div style="background: #2d2d2d; border: 1px solid #3d3d3d; padding: 0.75rem; border-radius: 4px;">
          ${diagnostic.recommendations.map(rec => `
            <p style="margin: 0.25rem 0; color: ${rec.includes('CRITICAL') ? '#d47d7d' : rec.includes('HIGH') ? '#d4a5a5' : rec.includes('GOOD') ? '#7fb069' : '#9db4d4'}; font-size: 0.8rem;">
              ${rec.includes('CRITICAL') ? '🚨' : rec.includes('HIGH') ? '⚠️' : rec.includes('GOOD') ? '✅' : '💡'} ${rec}
            </p>
          `).join('')}
        </div>
      </div>
    </div>
  `;
}

/**
 * Check if current key is the default key
 */
export function isUsingDefaultKey(): boolean {
  const key = process.env.ENCRYPTION_KEY || 'default-encryption-key-change-in-production';
  return key === 'default-encryption-key-change-in-production';
}

/**
 * Get key information without exposing the actual key
 */
export function getKeyInfo(): { 
  isDefault: boolean; 
  keyHash: string; 
  keyLength: number; 
  algorithm: string; 
  environment: string; 
  timestamp: string;
} {
  const key = process.env.ENCRYPTION_KEY || 'default-encryption-key-change-in-production';
  const isDefault = key === 'default-encryption-key-change-in-production';
  const keyHash = crypto.createHash('sha256').update(key).digest('hex').substring(0, 16);
  const keyLength = key.length;
  const algorithm = 'AES-256-CBC';
  const environment = process.env.NODE_ENV || 'development';
  const timestamp = new Date().toISOString();

  return { 
    isDefault, 
    keyHash, 
    keyLength, 
    algorithm, 
    environment, 
    timestamp 
  };
}
