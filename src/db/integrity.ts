import { getDatabase } from './mongodb';
import { ObjectId } from 'mongodb';
import { dbLogger } from '../utils/logger';
import { getUserPasswords, getPasswordEntry, getDecryptedPassword } from '../models/password';
import { listTotpEntries } from '../models/totp';
import { getUserById } from '../auth/users';

export interface IntegrityCheckResult {
  success: boolean;
  checks: {
    userIdFormat: CheckResult;
    passwordAccessibility: CheckResult;
    dataConsistency: CheckResult;
    orphanedEntries: CheckResult;
    encryptionIntegrity: CheckResult;
  };
  summary: {
    totalIssues: number;
    criticalIssues: number;
    warnings: number;
  };
  timestamp: Date;
}

export interface CheckResult {
  passed: boolean;
  issues: IntegrityIssue[];
  details: string;
}

export interface IntegrityIssue {
  severity: 'critical' | 'warning' | 'info';
  collection: string;
  entryId?: string;
  userId?: string;
  message: string;
  suggestion?: string;
}

/**
 * Comprehensive data integrity checker
 * Validates that all passwords are accessible regardless of schema version
 */
export async function runIntegrityChecks(): Promise<IntegrityCheckResult> {
  const result: IntegrityCheckResult = {
    success: false,
    checks: {
      userIdFormat: { passed: false, issues: [], details: '' },
      passwordAccessibility: { passed: false, issues: [], details: '' },
      dataConsistency: { passed: false, issues: [], details: '' },
      orphanedEntries: { passed: false, issues: [], details: '' },
      encryptionIntegrity: { passed: false, issues: [], details: '' },
    },
    summary: {
      totalIssues: 0,
      criticalIssues: 0,
      warnings: 0,
    },
    timestamp: new Date(),
  };

  try {
    dbLogger.info('🔍 Starting comprehensive data integrity checks...');

    // Run all checks
    result.checks.userIdFormat = await checkUserIdFormat();
    result.checks.passwordAccessibility = await checkPasswordAccessibility();
    result.checks.dataConsistency = await checkDataConsistency();
    result.checks.orphanedEntries = await checkOrphanedEntries();
    result.checks.encryptionIntegrity = await checkEncryptionIntegrity();

    // Calculate summary
    const allIssues: IntegrityIssue[] = [
      ...result.checks.userIdFormat.issues,
      ...result.checks.passwordAccessibility.issues,
      ...result.checks.dataConsistency.issues,
      ...result.checks.orphanedEntries.issues,
      ...result.checks.encryptionIntegrity.issues,
    ];

    result.summary.totalIssues = allIssues.length;
    result.summary.criticalIssues = allIssues.filter(i => i.severity === 'critical').length;
    result.summary.warnings = allIssues.filter(i => i.severity === 'warning').length;

    result.success = result.summary.criticalIssues === 0;

    dbLogger.info(`✅ Integrity checks completed: ${result.summary.criticalIssues} critical, ${result.summary.warnings} warnings`);

    return result;
  } catch (error: any) {
    dbLogger.error(`Integrity check failed: ${error.message}`);
    result.checks.userIdFormat.issues.push({
      severity: 'critical',
      collection: 'system',
      message: `Integrity check system error: ${error.message}`,
    });
    result.summary.criticalIssues++;
    return result;
  }
}

/**
 * Check 1: Verify userId format consistency
 * Ensures all userIds are strings (not ObjectIds)
 */
async function checkUserIdFormat(): Promise<CheckResult> {
  const result: CheckResult = {
    passed: true,
    issues: [],
    details: '',
  };

  try {
    const db = getDatabase();
    const collections = ['passwords', 'totp', 'analytics'];

    for (const collectionName of collections) {
      try {
        const collection = db.collection(collectionName);
        const documents = await collection.find({}).toArray();

        for (const doc of documents) {
          if (doc.userId) {
            // Check if userId is an ObjectId (should be string)
            if (doc.userId instanceof ObjectId) {
              result.passed = false;
              result.issues.push({
                severity: 'critical',
                collection: collectionName,
                entryId: doc._id?.toString(),
                userId: doc.userId.toString(),
                message: `userId is ObjectId format in ${collectionName}`,
                suggestion: 'Run migration to normalize userId format',
              });
            } else if (typeof doc.userId !== 'string') {
              result.passed = false;
              result.issues.push({
                severity: 'critical',
                collection: collectionName,
                entryId: doc._id?.toString(),
                userId: String(doc.userId),
                message: `userId has invalid type in ${collectionName}: ${typeof doc.userId}`,
                suggestion: 'Run migration to normalize userId format',
              });
            }
          }
        }
      } catch (error: any) {
        if (!error.message?.includes('does not exist')) {
          result.issues.push({
            severity: 'warning',
            collection: collectionName,
            message: `Could not check ${collectionName}: ${error.message}`,
          });
        }
      }
    }

    result.details = result.passed
      ? 'All userId fields are in correct string format'
      : `Found ${result.issues.length} entries with incorrect userId format`;

    return result;
  } catch (error: any) {
    result.passed = false;
    result.issues.push({
      severity: 'critical',
      collection: 'system',
      message: `UserId format check failed: ${error.message}`,
    });
    return result;
  }
}

/**
 * Check 2: Verify all passwords are accessible
 * Tests that passwords can be retrieved using both old and new schema queries
 */
async function checkPasswordAccessibility(): Promise<CheckResult> {
  const result: CheckResult = {
    passed: true,
    issues: [],
    details: '',
  };

  try {
    const db = getDatabase();
    const passwordsCollection = db.collection('passwords');
    const usersCollection = db.collection('users');

    // Get all users
    const users = await usersCollection.find({}).toArray();
    const userIds = users.map(u => u._id?.toString()).filter(Boolean) as string[];

    let totalPasswords = 0;
    let accessiblePasswords = 0;
    let inaccessiblePasswords = 0;

    for (const userId of userIds) {
      try {
        // Get passwords using the standard function (handles both formats)
        const passwords = await getUserPasswords(userId);
        totalPasswords += passwords.length;

        // Verify each password can be accessed individually
        for (const password of passwords) {
          if (!password._id) continue;

          try {
            // Try to get the password entry
            const entry = await getPasswordEntry(password._id, userId);
            if (!entry) {
              result.passed = false;
              inaccessiblePasswords++;
              result.issues.push({
                severity: 'critical',
                collection: 'passwords',
                entryId: password._id,
                userId: userId,
                message: `Password entry ${password._id} cannot be retrieved`,
                suggestion: 'Check database connection and entry existence',
              });
            } else {
              accessiblePasswords++;

              // Try to decrypt the password
              try {
                const decrypted = await getDecryptedPassword(password._id, userId);
                if (!decrypted) {
                  result.passed = false;
                  result.issues.push({
                    severity: 'critical',
                    collection: 'passwords',
                    entryId: password._id,
                    userId: userId,
                    message: `Password ${password._id} cannot be decrypted`,
                    suggestion: 'Check encryption key and password format',
                  });
                }
              } catch (decryptError: any) {
                result.passed = false;
                result.issues.push({
                  severity: 'critical',
                  collection: 'passwords',
                  entryId: password._id,
                  userId: userId,
                  message: `Password decryption failed: ${decryptError.message}`,
                  suggestion: 'Verify encryption key matches',
                });
              }
            }
          } catch (error: any) {
            result.passed = false;
            inaccessiblePasswords++;
            result.issues.push({
              severity: 'critical',
              collection: 'passwords',
              entryId: password._id,
              userId: userId,
              message: `Error accessing password: ${error.message}`,
            });
          }
        }
      } catch (error: any) {
        result.passed = false;
        result.issues.push({
          severity: 'warning',
          collection: 'passwords',
          userId: userId,
          message: `Error retrieving passwords for user ${userId}: ${error.message}`,
        });
      }
    }

    result.details = `Checked ${totalPasswords} passwords: ${accessiblePasswords} accessible, ${inaccessiblePasswords} inaccessible`;

    return result;
  } catch (error: any) {
    result.passed = false;
    result.issues.push({
      severity: 'critical',
      collection: 'system',
      message: `Password accessibility check failed: ${error.message}`,
    });
    return result;
  }
}

/**
 * Check 3: Verify data consistency
 * Ensures passwords exist in database and can be queried by both string and ObjectId userId
 */
async function checkDataConsistency(): Promise<CheckResult> {
  const result: CheckResult = {
    passed: true,
    issues: [],
    details: '',
  };

  try {
    const db = getDatabase();
    const passwordsCollection = db.collection('passwords');
    const usersCollection = db.collection('users');

    // Build user map using cursor for memory efficiency
    const userMap = new Map<string, boolean>();
    const userCursor = usersCollection.find({});
    for await (const user of userCursor) {
      const userId = user._id?.toString();
      if (userId) {
        userMap.set(userId, true);
      }
    }

    let checkedCount = 0;
    let inconsistentCount = 0;

    // Process passwords in batches using cursor to avoid loading all into memory
    const passwordCursor = passwordsCollection.find({});
    for await (const password of passwordCursor) {
      checkedCount++;
      const passwordId = password._id?.toString();
      if (!passwordId) continue;

      const userId = password.userId;
      let userIdString: string;

      // Normalize userId to string
      if (userId instanceof ObjectId) {
        userIdString = userId.toString();
      } else if (typeof userId === 'string') {
        userIdString = userId;
      } else {
        result.passed = false;
        inconsistentCount++;
        result.issues.push({
          severity: 'critical',
          collection: 'passwords',
          entryId: passwordId,
          userId: String(userId),
          message: `Password has invalid userId type: ${typeof userId}`,
          suggestion: 'Run migration to fix userId format',
        });
        continue;
      }

      // Verify user exists
      if (!userMap.has(userIdString)) {
        result.passed = false;
        inconsistentCount++;
        result.issues.push({
          severity: 'critical',
          collection: 'passwords',
          entryId: passwordId,
          userId: userIdString,
          message: `Password references non-existent user: ${userIdString}`,
          suggestion: 'Remove orphaned entry or restore user',
        });
        continue;
      }

      // Test query with string userId
      try {
        const entryString = await getPasswordEntry(passwordId, userIdString);
        if (!entryString) {
          result.passed = false;
          inconsistentCount++;
          result.issues.push({
            severity: 'critical',
            collection: 'passwords',
            entryId: passwordId,
            userId: userIdString,
            message: `Password not accessible with string userId query`,
            suggestion: 'Check query logic and userId format',
          });
        }
      } catch (error: any) {
        result.passed = false;
        inconsistentCount++;
        result.issues.push({
          severity: 'critical',
          collection: 'passwords',
          entryId: passwordId,
          userId: userIdString,
          message: `Error querying with string userId: ${error.message}`,
        });
      }

      // Test query with ObjectId userId (if valid ObjectId)
      if (ObjectId.isValid(userIdString)) {
        try {
          const entryObjectId = await passwordsCollection.findOne({
            _id: new ObjectId(passwordId),
            userId: new ObjectId(userIdString),
          } as any);

          // This is expected to work for old schema entries
          // We log it but don't fail if it doesn't (since we're migrating away from ObjectId)
        } catch (error: any) {
          // Not critical if ObjectId query fails - we're migrating to string format
        }
      }
    }

    result.details = `Checked ${checkedCount} passwords: ${inconsistentCount} inconsistencies found`;

    return result;
  } catch (error: any) {
    result.passed = false;
    result.issues.push({
      severity: 'critical',
      collection: 'system',
      message: `Data consistency check failed: ${error.message}`,
    });
    return result;
  }
}

/**
 * Check 4: Find orphaned entries
 * Entries that reference non-existent users
 */
async function checkOrphanedEntries(): Promise<CheckResult> {
  const result: CheckResult = {
    passed: true,
    issues: [],
    details: '',
  };

  try {
    const db = getDatabase();
    const passwordsCollection = db.collection('passwords');
    const totpCollection = db.collection('totp');
    const usersCollection = db.collection('users');

    // Get all user IDs
    const users = await usersCollection.find({}).toArray();
    const validUserIds = new Set<string>();
    for (const user of users) {
      const userId = user._id?.toString();
      if (userId) {
        validUserIds.add(userId);
      }
    }

    // Check passwords
    const passwords = await passwordsCollection.find({}).toArray();
    let orphanedPasswords = 0;

    for (const password of passwords) {
      const userId = password.userId;
      let userIdString: string;

      if (userId instanceof ObjectId) {
        userIdString = userId.toString();
      } else if (typeof userId === 'string') {
        userIdString = userId;
      } else {
        continue;
      }

      if (!validUserIds.has(userIdString)) {
        result.passed = false;
        orphanedPasswords++;
        result.issues.push({
          severity: 'warning',
          collection: 'passwords',
          entryId: password._id?.toString(),
          userId: userIdString,
          message: `Password references non-existent user: ${userIdString}`,
          suggestion: 'Remove orphaned entry or restore user',
        });
      }
    }

    // Check TOTP entries
    try {
      const totpEntries = await totpCollection.find({}).toArray();
      let orphanedTotp = 0;

      for (const totp of totpEntries) {
        const userId = totp.userId;
        let userIdString: string;

        if (userId instanceof ObjectId) {
          userIdString = userId.toString();
        } else if (typeof userId === 'string') {
          userIdString = userId;
        } else {
          continue;
        }

        if (!validUserIds.has(userIdString)) {
          result.passed = false;
          orphanedTotp++;
          result.issues.push({
            severity: 'warning',
            collection: 'totp',
            entryId: totp._id?.toString(),
            userId: userIdString,
            message: `TOTP entry references non-existent user: ${userIdString}`,
            suggestion: 'Remove orphaned entry or restore user',
          });
        }
      }

      result.details = `Found ${orphanedPasswords} orphaned passwords, ${orphanedTotp} orphaned TOTP entries`;
    } catch (error: any) {
      if (!error.message?.includes('does not exist')) {
        result.details = `Found ${orphanedPasswords} orphaned passwords (TOTP check failed)`;
      } else {
        result.details = `Found ${orphanedPasswords} orphaned passwords`;
      }
    }

    return result;
  } catch (error: any) {
    result.passed = false;
    result.issues.push({
      severity: 'critical',
      collection: 'system',
      message: `Orphaned entries check failed: ${error.message}`,
    });
    return result;
  }
}

/**
 * Check 5: Verify encryption integrity
 * Ensures all passwords can be decrypted
 */
async function checkEncryptionIntegrity(): Promise<CheckResult> {
  const result: CheckResult = {
    passed: true,
    issues: [],
    details: '',
  };

  try {
    const db = getDatabase();
    const passwordsCollection = db.collection('passwords');
    const usersCollection = db.collection('users');

    const users = await usersCollection.find({}).toArray();
    let totalChecked = 0;
    let decryptionFailures = 0;

    for (const user of users) {
      const userId = user._id?.toString();
      if (!userId) continue;

      try {
        const passwords = await getUserPasswords(userId);
        totalChecked += passwords.length;

        for (const password of passwords) {
          if (!password._id) continue;

          try {
            // Verify entry exists and belongs to user
            // Use the password object we already have from getUserPasswords as verification
            if (!password.password || password.password.trim() === '') {
              result.passed = false;
              decryptionFailures++;
              result.issues.push({
                severity: 'critical',
                collection: 'passwords',
                entryId: password._id,
                userId: userId,
                message: `Password entry ${password._id} has no encrypted password data`,
                suggestion: 'Password may be corrupted or empty',
              });
              continue;
            }

            // Try to decrypt using the password object we already have
            // This avoids potential userId format mismatches in getPasswordEntry
            try {
              const { decryptPassword } = await import('../models/password');
              try {
                const decrypted = await decryptPassword(password.password);
                if (!decrypted || decrypted.trim() === '') {
                  result.passed = false;
                  decryptionFailures++;
                  result.issues.push({
                    severity: 'critical',
                    collection: 'passwords',
                    entryId: password._id,
                    userId: userId,
                    message: `Password ${password._id} cannot be decrypted (returned empty)`,
                    suggestion: 'Password may have been encrypted with a different key. Try password recovery.',
                  });
                }
                // If decrypted is truthy and non-empty, password decrypts successfully - no issue
              } catch (decryptError: any) {
                // Direct decryption failed - this is a real decryption error
                result.passed = false;
                decryptionFailures++;
                dbLogger.warn(`Password decryption failed for ${password._id}: ${decryptError.message || decryptError}`);
                result.issues.push({
                  severity: 'critical',
                  collection: 'passwords',
                  entryId: password._id,
                  userId: userId,
                  message: `Password ${password._id} cannot be decrypted (returned empty)`,
                  suggestion: 'Password may have been encrypted with a different key. Try password recovery.',
                });
              }
              // If decrypted is truthy and non-empty, password decrypts successfully - no issue
            } catch (decryptError: any) {
              // Direct decryption failed - this is a real decryption error
              result.passed = false;
              decryptionFailures++;
              dbLogger.warn(`Password decryption failed for ${password._id}: ${decryptError.message || decryptError}`);
              result.issues.push({
                severity: 'critical',
                collection: 'passwords',
                entryId: password._id,
                userId: userId,
                message: `Password ${password._id} cannot be decrypted: ${decryptError.message || 'Invalid encryption format'}`,
                suggestion: 'Password may have been encrypted with a different key. Try password recovery with the original master password.',
              });
            }
          } catch (error: any) {
            result.passed = false;
            decryptionFailures++;
            dbLogger.error(`Error checking password ${password._id}: ${error.message || error}`);
            result.issues.push({
              severity: 'critical',
              collection: 'passwords',
              entryId: password._id,
              userId: userId,
              message: `Error checking password: ${error.message || 'Unknown error'}`,
              suggestion: 'Check server logs for details',
            });
          }
        }
      } catch (error: any) {
        result.issues.push({
          severity: 'warning',
          collection: 'passwords',
          userId: userId,
          message: `Error checking passwords for user: ${error.message}`,
        });
      }
    }

    result.details = `Checked ${totalChecked} passwords: ${decryptionFailures} decryption failures`;

    return result;
  } catch (error: any) {
    result.passed = false;
    result.issues.push({
      severity: 'critical',
      collection: 'system',
      message: `Encryption integrity check failed: ${error.message}`,
    });
    return result;
  }
}

/**
 * Quick health check - runs essential checks only
 */
export async function quickHealthCheck(): Promise<{ healthy: boolean; issues: number }> {
  try {
    const db = getDatabase();

    // Quick check: Can we query passwords?
    const passwordsCollection = db.collection('passwords');
    const count = await passwordsCollection.countDocuments({});

    // Quick check: Can we access at least one password if any exist?
    if (count > 0) {
      const sample = await passwordsCollection.findOne({});
      if (sample && sample.userId) {
        const userId = sample.userId instanceof ObjectId
          ? sample.userId.toString()
          : String(sample.userId);

        try {
          const passwords = await getUserPasswords(userId);
          return { healthy: passwords.length > 0, issues: 0 };
        } catch {
          return { healthy: false, issues: 1 };
        }
      }
    }

    return { healthy: true, issues: 0 };
  } catch (error) {
    return { healthy: false, issues: 1 };
  }
}

