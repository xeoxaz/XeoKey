import { getDatabase } from './mongodb';
import { ObjectId } from 'mongodb';
import { dbLogger } from '../utils/logger';

export interface MigrationResult {
  success: boolean;
  migratedCount: number;
  errorCount: number;
  errors: string[];
  skippedCount: number;
}

/**
 * Migration 3: Normalize userId format in all collections
 *
 * This migration converts all userId fields from ObjectId to string format
 * to ensure consistency across old and new schemas.
 *
 * Collections migrated:
 * - passwords
 * - totp
 * - analytics (if exists)
 *
 * Safety features:
 * - Only migrates if userId is an ObjectId type
 * - Validates userId exists in users collection before migration
 * - Uses bulk operations for efficiency
 * - Idempotent (safe to run multiple times)
 * - Logs all operations
 * - Never corrupts data - validates before updating
 */
export async function migrateUserIdToString(): Promise<MigrationResult> {
  const result: MigrationResult = {
    success: false,
    migratedCount: 0,
    errorCount: 0,
    errors: [],
    skippedCount: 0,
  };

  if (!getDatabase) {
    result.errors.push('Database not connected');
    return result;
  }

  const db = getDatabase();
  const usersCollection = db.collection('users');

  try {
    dbLogger.info('🔄 Starting userId normalization migration (Migration 3)...');

    // Get all valid user IDs as strings for validation
    const allUsers = await usersCollection.find({}).toArray();
    const validUserIds = new Set<string>();
    for (const user of allUsers) {
      if (user._id) {
        const userIdString = typeof user._id === 'string'
          ? user._id
          : user._id.toString();
        validUserIds.add(userIdString);
      }
    }

    dbLogger.info(`Found ${validUserIds.size} valid users for validation`);

    // Migrate each collection
    const collections = [
      { name: 'passwords', displayName: 'passwords' },
      { name: 'totp', displayName: 'TOTP entries' },
      { name: 'analytics', displayName: 'analytics', optional: true }
    ];

    for (const collectionInfo of collections) {
      try {
        const collection = db.collection(collectionInfo.name);
        const count = await collection.countDocuments({});

        if (count === 0) {
          dbLogger.info(`No ${collectionInfo.displayName} found to migrate`);
          continue;
        }

        dbLogger.info(`Checking ${count} ${collectionInfo.displayName} entries...`);

        const collectionResult = await migrateCollectionUserId(
          collection,
          validUserIds,
          collectionInfo.displayName
        );

        result.migratedCount += collectionResult.migratedCount;
        result.errorCount += collectionResult.errorCount;
        result.skippedCount += collectionResult.skippedCount;
        result.errors.push(...collectionResult.errors);

      } catch (error: any) {
        if (collectionInfo.optional && error.message?.includes('does not exist')) {
          dbLogger.info(`Collection ${collectionInfo.name} does not exist, skipping...`);
          continue;
        }
        const errorMsg = `Error migrating ${collectionInfo.displayName}: ${error.message}`;
        dbLogger.error(errorMsg);
        result.errors.push(errorMsg);
        result.errorCount++;
      }
    }

    result.success = result.errorCount === 0;

    if (result.success) {
      dbLogger.info(`✅ Migration completed successfully!`);
      dbLogger.info(`   Migrated: ${result.migratedCount} entries`);
      dbLogger.info(`   Skipped: ${result.skippedCount} entries (already correct format)`);
    } else {
      dbLogger.warn(`⚠️  Migration completed with errors`);
      dbLogger.warn(`   Migrated: ${result.migratedCount} entries`);
      dbLogger.warn(`   Errors: ${result.errorCount} entries`);
      dbLogger.warn(`   Skipped: ${result.skippedCount} entries`);
    }

    return result;
  } catch (error: any) {
    const errorMsg = `Migration failed: ${error.message}`;
    dbLogger.error(errorMsg);
    result.errors.push(errorMsg);
    result.success = false;
    return result;
  }
}

/**
 * Migrate userId format for a specific collection
 */
async function migrateCollectionUserId(
  collection: any,
  validUserIds: Set<string>,
  displayName: string
): Promise<MigrationResult> {
  const result: MigrationResult = {
    success: false,
    migratedCount: 0,
    errorCount: 0,
    errors: [],
    skippedCount: 0,
  };

  const allEntries = await collection.find({}).toArray();

  if (allEntries.length === 0) {
    result.success = true;
    return result;
  }

  // Prepare bulk operations
  const bulkOps: any[] = [];
  let checkedCount = 0;

  for (const entry of allEntries) {
    checkedCount++;

    // Check if userId is an ObjectId (not a string)
    const userId = entry.userId;

    // Skip if userId is already a string
    if (typeof userId === 'string') {
      // Validate it's a valid user ID
      if (!validUserIds.has(userId)) {
        dbLogger.warn(`${displayName} ${entry._id} has invalid userId string: ${userId}`);
        result.skippedCount++;
      }
      continue;
    }

    // Check if userId is an ObjectId
    if (userId instanceof ObjectId || ObjectId.isValid(userId?.toString?.() || '')) {
      const userIdString = userId instanceof ObjectId
        ? userId.toString()
        : userId?.toString?.() || '';

      // Validate the userId exists in users collection
      if (!validUserIds.has(userIdString)) {
        const errorMsg = `${displayName} ${entry._id} references non-existent userId: ${userIdString}`;
        dbLogger.warn(errorMsg);
        result.errors.push(errorMsg);
        result.errorCount++;
        result.skippedCount++;
        continue;
      }

      // Add update operation to convert ObjectId to string
      bulkOps.push({
        updateOne: {
          filter: { _id: entry._id },
          update: {
            $set: { userId: userIdString }
          }
        }
      });

      if (checkedCount % 100 === 0) {
        dbLogger.info(`Processed ${checkedCount}/${allEntries.length} ${displayName}...`);
      }
    } else {
      const errorMsg = `${displayName} ${entry._id} has invalid userId type: ${typeof userId}`;
      dbLogger.warn(errorMsg);
      result.errors.push(errorMsg);
      result.errorCount++;
      result.skippedCount++;
    }
  }

  dbLogger.info(`Prepared ${bulkOps.length} update operations for ${displayName}`);

  // Execute bulk operations in batches to avoid overwhelming the database
  if (bulkOps.length > 0) {
    const BATCH_SIZE = 100;
    for (let i = 0; i < bulkOps.length; i += BATCH_SIZE) {
      const batch = bulkOps.slice(i, i + BATCH_SIZE);
      try {
        const bulkResult = await collection.bulkWrite(batch, { ordered: false });
        result.migratedCount += bulkResult.modifiedCount || 0;
        dbLogger.info(`Migrated ${displayName} batch ${Math.floor(i / BATCH_SIZE) + 1}/${Math.ceil(bulkOps.length / BATCH_SIZE)}: ${bulkResult.modifiedCount} documents`);
      } catch (batchError: any) {
        const errorMsg = `Error in ${displayName} batch ${Math.floor(i / BATCH_SIZE) + 1}: ${batchError.message}`;
        dbLogger.error(errorMsg);
        result.errors.push(errorMsg);
        result.errorCount += batch.length;
      }
    }
  } else {
    dbLogger.info(`No ${displayName} need migration (all userIds are already strings)`);
  }

  result.success = result.errorCount === 0;
  return result;
}

/**
 * Check if userId migration is needed
 * Returns true if any documents have ObjectId userId format
 * Checks passwords, totp, and analytics collections
 */
export async function needsUserIdMigration(): Promise<boolean> {
  try {
    const db = getDatabase();
    const collections = [
      { name: 'passwords', optional: false },
      { name: 'totp', optional: false },
      { name: 'analytics', optional: true }
    ];

    for (const collectionInfo of collections) {
      try {
        const collection = db.collection(collectionInfo.name);
        const count = await collection.countDocuments({});

        if (count === 0) {
          continue;
        }

        // Sample documents to check if any have ObjectId userId
        const sampleSize = Math.min(100, count);
        const sample = await collection.find({}).limit(sampleSize).toArray();

        for (const doc of sample) {
          const userId = doc.userId;
          // If we find any ObjectId userId, migration is needed
          if (userId instanceof ObjectId ||
              (userId && typeof userId !== 'string' && ObjectId.isValid(userId?.toString?.() || ''))) {
            return true;
          }
        }

        // If sample is clean and there are more documents, check additional samples
        if (count > sampleSize) {
          const additionalSamples = Math.min(3, Math.floor(count / sampleSize));
          for (let i = 0; i < additionalSamples; i++) {
            const skip = Math.floor(Math.random() * (count - sampleSize));
            const additionalSample = await collection.find({}).skip(skip).limit(sampleSize).toArray();

            for (const doc of additionalSample) {
              const userId = doc.userId;
              if (userId instanceof ObjectId ||
                  (userId && typeof userId !== 'string' && ObjectId.isValid(userId?.toString?.() || ''))) {
                return true;
              }
            }
          }
        }
      } catch (error: any) {
        if (collectionInfo.optional && error.message?.includes('does not exist')) {
          continue;
        }
        // If we can't check a required collection, assume migration might be needed
        dbLogger.warn(`Error checking ${collectionInfo.name} for migration: ${error.message}`);
        return true;
      }
    }

    return false;
  } catch (error) {
    dbLogger.error(`Error checking if migration is needed: ${error}`);
    // If we can't check, assume migration might be needed (safe default)
    return true;
  }
}

