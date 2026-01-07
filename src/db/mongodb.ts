import { MongoClient, Db } from 'mongodb';
import { dbLogger } from '../utils/logger';
import { migrateUserIdToString, needsUserIdMigration } from './migrations';
import { createPreMigrationBackup } from './backup';

let client: MongoClient | null = null;
let db: Db | null = null;

// Current database schema version
// Increment this when making schema changes that require migration
const CURRENT_SCHEMA_VERSION = 3; // Version 3: Normalized userId format (ObjectId -> string)

interface DatabaseMetadata {
  _id: 'metadata';
  schemaVersion: number;
  appVersion: string;
  lastUpdated: Date;
  indexesInitialized: boolean;
}

// Get MongoDB connection string from environment or use default
function getMongoUri(): string {
  const uri = process.env.MONGODB_URI || process.env.MONGO_URI || 'mongodb://localhost:27017';
  return uri;
}

// Connect to MongoDB
export async function connectMongoDB(): Promise<Db> {
  if (db) {
    return db;
  }

  try {
    const uri = getMongoUri();
    const dbName = 'XeoKey';

    // Don't log full URI (might contain credentials)
    const uriDisplay = uri.includes('@')
      ? uri.split('@')[1] || 'MongoDB server'
      : uri;
    dbLogger.info(`Connecting to MongoDB at ${uriDisplay}...`);
    client = new MongoClient(uri);

    await client.connect();
    dbLogger.info('MongoDB client connected');

    db = client.db(dbName);
    dbLogger.info(`Using database: ${dbName}`);

    // Test the connection
    await db.admin().ping();
    dbLogger.info('MongoDB connection verified');

    // Check database version and detect old databases
    await detectAndHandleDatabaseVersion();

    // Run migrations if needed
    await runMigrations();

    // Initialize indexes for optimal query performance
    await initializeIndexes();

    // Initialize health monitoring
    const { initializeHealthMonitoring } = await import('./health');
    await initializeHealthMonitoring();

    return db;
  } catch (error) {
    dbLogger.error(`Failed to connect to MongoDB: ${error}`);
    throw error;
  }
}

// Get the database instance
export function getDatabase(): Db {
  if (!db) {
    throw new Error('Database not connected. Call connectMongoDB() first.');
  }
  return db;
}

// Close MongoDB connection
export async function closeMongoDB(): Promise<void> {
  if (client) {
    await client.close();
    client = null;
    db = null;
    dbLogger.info('MongoDB connection closed');
  }
}

// Check if database is connected
export function isConnected(): boolean {
  return db !== null && client !== null;
}

// Initialize database indexes for optimal query performance
export async function initializeIndexes(): Promise<void> {
  if (!db) {
    throw new Error('Database not connected. Call connectMongoDB() first.');
  }

  try {
    dbLogger.info('Initializing database indexes...');

    // Passwords collection indexes
    const passwordsCollection = db.collection('passwords');
    await passwordsCollection.createIndexes([
      // Compound index for user's passwords sorted by popularity
      { key: { userId: 1, searchCount: -1, copyCount: -1, website: 1 }, name: 'userId_popularity_website' },
      // Index for recent passwords
      { key: { userId: 1, createdAt: -1 }, name: 'userId_createdAt_desc' },
      // Index for user's passwords by website (for duplicate detection)
      { key: { userId: 1, website: 1 }, name: 'userId_website' }
    ]);
    dbLogger.info('Created indexes for passwords collection');

    // Users collection indexes
    const usersCollection = db.collection('users');
    await usersCollection.createIndexes([
      // Unique case-insensitive username index
      {
        key: { username: 1 },
        unique: true,
        name: 'username_unique',
        collation: { locale: 'en', strength: 2 } // Case-insensitive
      }
    ]);
    dbLogger.info('Created indexes for users collection');

    // Sessions collection indexes
    const sessionsCollection = db.collection('sessions');
    await sessionsCollection.createIndexes([
      // Unique session ID index
      { key: { sessionId: 1 }, unique: true, name: 'sessionId_unique' },
      // TTL index for automatic cleanup of expired sessions
      { key: { expiresAt: 1 }, expireAfterSeconds: 0, name: 'expiresAt_ttl' }
    ]);
    dbLogger.info('Created indexes for sessions collection');

    // TOTP collection indexes
    const totpCollection = db.collection('totp');
    await totpCollection.createIndexes([
      // Index for user's TOTP entries
      { key: { userId: 1, label: 1 }, name: 'userId_label' },
      // Index for user's TOTP entries sorted by label
      { key: { userId: 1 }, name: 'userId' }
    ]);
    dbLogger.info('Created indexes for totp collection');

    // Analytics collection indexes (if it exists)
    const analyticsCollection = db.collection('analytics');
    try {
      await analyticsCollection.createIndexes([
        // Index for user's analytics queries
        { key: { userId: 1, timestamp: -1 }, name: 'userId_timestamp_desc' },
        // Index for event type queries
        { key: { eventType: 1, timestamp: -1 }, name: 'eventType_timestamp_desc' }
      ]);
      dbLogger.info('Created indexes for analytics collection');
    } catch (error) {
      // Analytics collection might not exist yet, that's okay
      dbLogger.debug('Analytics collection indexes skipped (collection may not exist)');
    }

    dbLogger.info('Database indexes initialized successfully');

    // Update metadata to reflect that indexes are initialized
    try {
      const metadataCollection = db.collection<DatabaseMetadata>('_metadata');
      await metadataCollection.updateOne(
        { _id: 'metadata' },
        {
          $set: {
            indexesInitialized: true,
            lastUpdated: new Date()
          }
        },
        { upsert: true } // Create if doesn't exist
      );
    } catch (metadataError) {
      dbLogger.warn(`Failed to update metadata after index creation: ${metadataError}`);
      // Non-critical, continue
    }
  } catch (error) {
    dbLogger.error(`Failed to initialize indexes: ${error}`);
    // Don't throw - indexes are performance optimizations, not critical for operation
    // Log warning but allow server to continue
    dbLogger.warn('Server will continue without optimal indexes. Performance may be degraded.');
  }
}

// Detect database version and handle old databases
export async function detectAndHandleDatabaseVersion(): Promise<void> {
  if (!db) {
    throw new Error('Database not connected. Call connectMongoDB() first.');
  }

  try {
    const metadataCollection = db.collection<DatabaseMetadata>('_metadata');

    // Check if metadata exists
    const existingMetadata = await metadataCollection.findOne({ _id: 'metadata' });

    // Check if database has data (indicates existing database)
    const hasUsers = await db.collection('users').countDocuments({}) > 0;
    const hasPasswords = await db.collection('passwords').countDocuments({}) > 0;
    const hasData = hasUsers || hasPasswords;

    // Check if indexes exist (newer databases should have them)
    const passwordsIndexes = await db.collection('passwords').indexes();
    const hasIndexes = passwordsIndexes.length > 1; // More than just _id index

    if (existingMetadata) {
      // Database has version metadata
      const dbVersion = existingMetadata.schemaVersion || 1;
      const dbAppVersion = existingMetadata.appVersion || 'unknown';

      if (dbVersion < CURRENT_SCHEMA_VERSION) {
        dbLogger.warn(`⚠️  Database version mismatch detected!`);
        dbLogger.warn(`   Database schema version: ${dbVersion}`);
        dbLogger.warn(`   Current schema version: ${CURRENT_SCHEMA_VERSION}`);
        dbLogger.warn(`   Database was created with app version: ${dbAppVersion}`);
        dbLogger.warn(`   This database may need migration to work with the current version.`);
        dbLogger.warn(`   The system will attempt to upgrade indexes automatically.`);
      } else if (dbVersion > CURRENT_SCHEMA_VERSION) {
        dbLogger.error(`❌ Database version is newer than application version!`);
        dbLogger.error(`   Database schema version: ${dbVersion}`);
        dbLogger.error(`   Current schema version: ${CURRENT_SCHEMA_VERSION}`);
        dbLogger.error(`   This application version may not be compatible with the database.`);
        dbLogger.error(`   Please upgrade the application to match the database version.`);
        throw new Error('Database version mismatch: Database is newer than application');
      } else {
        dbLogger.info(`✓ Database version matches current schema (v${CURRENT_SCHEMA_VERSION})`);
      }
    } else if (hasData && !hasIndexes) {
      // Old database detected: has data but no indexes
      dbLogger.warn(`⚠️  Old database detected!`);
      dbLogger.warn(`   Database contains data but appears to be from an older version.`);
      dbLogger.warn(`   Missing indexes will be created automatically.`);
      dbLogger.warn(`   This may take a moment if you have many passwords.`);

      // Create metadata entry for old database
      await metadataCollection.insertOne({
        _id: 'metadata',
        schemaVersion: 1, // Assume it was version 1
        appVersion: '1.0.0', // Unknown, but likely 1.0.0
        lastUpdated: new Date(),
        indexesInitialized: false
      });
    } else if (hasData && hasIndexes) {
      // Database has data and indexes but no metadata (upgrade scenario)
      dbLogger.info(`Database detected with existing data and indexes.`);
      dbLogger.info(`Creating metadata entry...`);

      await metadataCollection.insertOne({
        _id: 'metadata',
        schemaVersion: CURRENT_SCHEMA_VERSION,
        appVersion: '1.0.0',
        lastUpdated: new Date(),
        indexesInitialized: true
      });
    } else {
      // New database - no data yet
      dbLogger.info(`New database detected. Initializing metadata...`);

      await metadataCollection.insertOne({
        _id: 'metadata',
        schemaVersion: CURRENT_SCHEMA_VERSION,
        appVersion: '1.0.0',
        lastUpdated: new Date(),
        indexesInitialized: false
      });
    }

    // Metadata will be updated after indexes are initialized
    // (handled in initializeIndexes function)

  } catch (error) {
    dbLogger.error(`Failed to detect database version: ${error}`);
    // Don't throw - version detection is informational, not critical
    dbLogger.warn('Continuing without version metadata. Database may need manual migration.');
  }
}

// Run database migrations based on current schema version
export async function runMigrations(): Promise<void> {
  if (!db) {
    throw new Error('Database not connected. Call connectMongoDB() first.');
  }

  try {
    const metadataCollection = db.collection<DatabaseMetadata>('_metadata');
    const metadata = await metadataCollection.findOne({ _id: 'metadata' });
    const currentVersion = metadata?.schemaVersion || 1;

    if (currentVersion >= CURRENT_SCHEMA_VERSION) {
      dbLogger.info(`Database is up to date (v${currentVersion})`);
      return;
    }

    dbLogger.info(`🔄 Database migration needed: v${currentVersion} -> v${CURRENT_SCHEMA_VERSION}`);

    // Migration 2 -> 3: Normalize userId format
    if (currentVersion < 3) {
      dbLogger.info('Running migration 2 -> 3: Normalizing userId format...');

      // Check if migration is actually needed
      const needsMigration = await needsUserIdMigration();

      if (needsMigration) {
        // Create automatic backup before migration
        dbLogger.info('Creating automatic backup before migration...');
        const backupResult = await createPreMigrationBackup(3);
        if (backupResult?.success) {
          dbLogger.info(`✅ Pre-migration backup created: ${backupResult.backupId}`);
        } else {
          dbLogger.warn(`⚠️  Pre-migration backup failed: ${backupResult?.error || 'Unknown error'}`);
          dbLogger.warn('Migration will continue, but no backup is available for rollback');
        }

        const migrationResult = await migrateUserIdToString();

        if (migrationResult.success) {
          dbLogger.info(`✅ Migration 2 -> 3 completed successfully`);
          dbLogger.info(`   Migrated ${migrationResult.migratedCount} password entries`);

          // Update schema version to 3
          await metadataCollection.updateOne(
            { _id: 'metadata' },
            {
              $set: {
                schemaVersion: 3,
                lastUpdated: new Date()
              }
            }
          );

          dbLogger.info('Database schema version updated to 3');
        } else {
          dbLogger.error(`❌ Migration 2 -> 3 failed or had errors`);
          dbLogger.error(`   Migrated: ${migrationResult.migratedCount}`);
          dbLogger.error(`   Errors: ${migrationResult.errorCount}`);
          dbLogger.error(`   Error details: ${migrationResult.errors.join('; ')}`);

          // Don't update version if migration failed
          // This allows the migration to retry on next startup
          throw new Error('Migration failed - database version not updated. Please check logs and fix issues.');
        }
      } else {
        dbLogger.info('Migration 2 -> 3 not needed (all userIds already normalized)');

        // Update schema version anyway since we've verified it's not needed
        await metadataCollection.updateOne(
          { _id: 'metadata' },
          {
            $set: {
              schemaVersion: 3,
              lastUpdated: new Date()
            }
          }
        );

        dbLogger.info('Database schema version updated to 3');
      }
    }

    dbLogger.info(`✅ All migrations completed. Database is now at version ${CURRENT_SCHEMA_VERSION}`);
  } catch (error) {
    dbLogger.error(`Failed to run migrations: ${error}`);
    // Don't throw - allow server to start even if migrations fail
    // But log the error so it's visible
    dbLogger.warn('Server will continue, but database may need manual migration');
  }
}

// Get current database schema version
export async function getDatabaseSchemaVersion(): Promise<number | null> {
  if (!db) {
    return null;
  }

  try {
    const metadataCollection = db.collection<DatabaseMetadata>('_metadata');
    const metadata = await metadataCollection.findOne({ _id: 'metadata' });
    return metadata?.schemaVersion || null;
  } catch (error) {
    dbLogger.error(`Failed to get database schema version: ${error}`);
    return null;
  }
}

// Get database metadata for status/health checks
export async function getDatabaseMetadata(): Promise<DatabaseMetadata | null> {
  if (!db) {
    return null;
  }

  try {
    const metadataCollection = db.collection<DatabaseMetadata>('_metadata');
    return await metadataCollection.findOne({ _id: 'metadata' });
  } catch (error) {
    dbLogger.error(`Failed to get database metadata: ${error}`);
    return null;
  }
}

// Check if database needs migration
export async function databaseNeedsMigration(): Promise<boolean> {
  const version = await getDatabaseSchemaVersion();
  if (version === null) {
    return false; // Can't determine, assume no migration needed
  }
  return version < CURRENT_SCHEMA_VERSION;
}

