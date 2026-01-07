import { getDatabase } from './mongodb';
import { ObjectId } from 'mongodb';
import { dbLogger } from '../utils/logger';
import * as fs from 'fs';
import * as path from 'path';

export interface BackupMetadata {
  _id: ObjectId;
  backupId: string;
  timestamp: Date;
  schemaVersion: number;
  collections: string[];
  totalDocuments: number;
  backupType: 'manual' | 'automatic' | 'pre-migration';
  migrationVersion?: number; // If this was a pre-migration backup
  description?: string;
  size: number; // Size in bytes
}

export interface BackupResult {
  success: boolean;
  backupId: string;
  timestamp: Date;
  collections: string[];
  totalDocuments: number;
  size: number;
  error?: string;
}

export interface RestoreResult {
  success: boolean;
  restoredCollections: string[];
  restoredDocuments: number;
  error?: string;
}

// Get backup directory path
function getBackupDirectory(): string {
  const backupDir = process.env.BACKUP_DIR || path.join(process.cwd(), 'backups');

  // Ensure backup directory exists
  if (!fs.existsSync(backupDir)) {
    fs.mkdirSync(backupDir, { recursive: true });
    dbLogger.info(`Created backup directory: ${backupDir}`);
  }

  return backupDir;
}

// Get backup file path
function getBackupFilePath(backupId: string): string {
  return path.join(getBackupDirectory(), `${backupId}.json`);
}

// Get metadata file path
function getMetadataFilePath(): string {
  return path.join(getBackupDirectory(), 'metadata.json');
}

// Load backup metadata
async function loadBackupMetadata(): Promise<BackupMetadata[]> {
  const metadataPath = getMetadataFilePath();

  if (!fs.existsSync(metadataPath)) {
    return [];
  }

  try {
    const data = fs.readFileSync(metadataPath, 'utf-8');
    return JSON.parse(data);
  } catch (error) {
    dbLogger.error(`Failed to load backup metadata: ${error}`);
    return [];
  }
}

// Save backup metadata
async function saveBackupMetadata(metadata: BackupMetadata[]): Promise<void> {
  const metadataPath = getMetadataFilePath();

  try {
    fs.writeFileSync(metadataPath, JSON.stringify(metadata, null, 2), 'utf-8');
  } catch (error) {
    dbLogger.error(`Failed to save backup metadata: ${error}`);
    throw error;
  }
}

/**
 * Create a backup of specified collections
 */
export async function createBackup(
  collections: string[],
  backupType: 'manual' | 'automatic' | 'pre-migration' = 'manual',
  migrationVersion?: number,
  description?: string
): Promise<BackupResult> {
  const db = getDatabase();
  const backupId = `backup_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
  const timestamp = new Date();

  const result: BackupResult = {
    success: false,
    backupId,
    timestamp,
    collections: [],
    totalDocuments: 0,
    size: 0,
  };

  try {
    dbLogger.info(`🔄 Creating backup: ${backupId} (type: ${backupType})`);

    const backupData: any = {
      backupId,
      timestamp: timestamp.toISOString(),
      schemaVersion: 3, // Current schema version
      collections: {},
      metadata: {
        backupType,
        migrationVersion,
        description,
      }
    };

    let totalDocs = 0;

    // Backup each collection
    for (const collectionName of collections) {
      try {
        const collection = db.collection(collectionName);
        const documents = await collection.find({}).toArray();

        // Convert ObjectIds to strings for JSON serialization
        const serializedDocs = documents.map(doc => {
          const serialized: any = { ...doc };
          if (serialized._id && serialized._id instanceof ObjectId) {
            serialized._id = serialized._id.toString();
          }
          // Also convert any ObjectId fields in the document
          for (const key in serialized) {
            if (serialized[key] instanceof ObjectId) {
              serialized[key] = serialized[key].toString();
            }
          }
          return serialized;
        });

        backupData.collections[collectionName] = serializedDocs;
        totalDocs += documents.length;

        dbLogger.info(`  Backed up ${documents.length} documents from ${collectionName}`);
      } catch (error: any) {
        dbLogger.warn(`  Failed to backup ${collectionName}: ${error.message}`);
        // Continue with other collections
      }
    }

    // Save backup to file
    const backupPath = getBackupFilePath(backupId);
    const backupJson = JSON.stringify(backupData, null, 2);
    fs.writeFileSync(backupPath, backupJson, 'utf-8');

    const fileSize = fs.statSync(backupPath).size;

    // Create metadata entry
    const metadata: BackupMetadata = {
      _id: new ObjectId(),
      backupId,
      timestamp,
      schemaVersion: backupData.schemaVersion,
      collections: Object.keys(backupData.collections),
      totalDocuments: totalDocs,
      backupType,
      migrationVersion,
      description,
      size: fileSize,
    };

    // Save metadata
    const allMetadata = await loadBackupMetadata();
    allMetadata.push(metadata);
    await saveBackupMetadata(allMetadata);

    result.success = true;
    result.collections = metadata.collections;
    result.totalDocuments = totalDocs;
    result.size = fileSize;

    dbLogger.info(`✅ Backup created successfully: ${backupId}`);
    dbLogger.info(`   Collections: ${metadata.collections.join(', ')}`);
    dbLogger.info(`   Documents: ${totalDocs}`);
    dbLogger.info(`   Size: ${(fileSize / 1024).toFixed(2)} KB`);

    return result;
  } catch (error: any) {
    const errorMsg = `Backup failed: ${error.message}`;
    dbLogger.error(errorMsg);
    result.error = errorMsg;
    return result;
  }
}

/**
 * Create automatic backup before migration
 */
export async function createPreMigrationBackup(migrationVersion: number): Promise<BackupResult | null> {
  dbLogger.info(`📦 Creating pre-migration backup for version ${migrationVersion}...`);

  // Backup critical collections
  const collections = ['passwords', 'totp', 'users', 'sessions'];

  return await createBackup(
    collections,
    'pre-migration',
    migrationVersion,
    `Automatic backup before migration to version ${migrationVersion}`
  );
}

/**
 * List all available backups
 */
export async function listBackups(): Promise<BackupMetadata[]> {
  const metadata = await loadBackupMetadata();

  // Sort by timestamp (newest first)
  return metadata.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
}

/**
 * Get backup metadata by ID
 */
export async function getBackupMetadata(backupId: string): Promise<BackupMetadata | null> {
  const metadata = await loadBackupMetadata();
  return metadata.find(b => b.backupId === backupId) || null;
}

/**
 * Restore a backup
 * WARNING: This will overwrite existing data in the collections!
 */
export async function restoreBackup(backupId: string): Promise<RestoreResult> {
  const db = getDatabase();
  const result: RestoreResult = {
    success: false,
    restoredCollections: [],
    restoredDocuments: 0,
  };

  try {
    dbLogger.info(`🔄 Restoring backup: ${backupId}`);

    // Load backup file
    const backupPath = getBackupFilePath(backupId);
    if (!fs.existsSync(backupPath)) {
      throw new Error(`Backup file not found: ${backupId}`);
    }

    const backupJson = fs.readFileSync(backupPath, 'utf-8');
    const backupData = JSON.parse(backupJson);

    // Verify backup structure
    if (!backupData.collections || typeof backupData.collections !== 'object') {
      throw new Error('Invalid backup file format');
    }

    let totalRestored = 0;

    // Restore each collection
    for (const [collectionName, documents] of Object.entries(backupData.collections)) {
      try {
        const collection = db.collection(collectionName);
        const docsArray = documents as any[];

        if (docsArray.length === 0) {
          dbLogger.info(`  Skipping empty collection: ${collectionName}`);
          continue;
        }

        // Convert string IDs back to ObjectIds
        const restoredDocs = docsArray.map(doc => {
          const restored: any = { ...doc };
          if (restored._id && typeof restored._id === 'string' && ObjectId.isValid(restored._id)) {
            restored._id = new ObjectId(restored._id);
          }
          // Convert other ObjectId fields if needed
          for (const key in restored) {
            if (typeof restored[key] === 'string' && ObjectId.isValid(restored[key])) {
              // Only convert if it looks like an ObjectId (24 hex chars)
              if (restored[key].length === 24) {
                try {
                  restored[key] = new ObjectId(restored[key]);
                } catch {
                  // Not an ObjectId, keep as string
                }
              }
            }
          }
          return restored;
        });

        // Clear existing collection and insert backup data
        await collection.deleteMany({});
        if (restoredDocs.length > 0) {
          await collection.insertMany(restoredDocs);
        }

        result.restoredCollections.push(collectionName);
        totalRestored += restoredDocs.length;

        dbLogger.info(`  Restored ${restoredDocs.length} documents to ${collectionName}`);
      } catch (error: any) {
        dbLogger.error(`  Failed to restore ${collectionName}: ${error.message}`);
        result.error = `Failed to restore ${collectionName}: ${error.message}`;
        // Continue with other collections
      }
    }

    result.success = result.restoredCollections.length > 0;
    result.restoredDocuments = totalRestored;

    if (result.success) {
      dbLogger.info(`✅ Backup restored successfully: ${backupId}`);
      dbLogger.info(`   Collections: ${result.restoredCollections.join(', ')}`);
      dbLogger.info(`   Documents: ${totalRestored}`);
    } else {
      dbLogger.error(`❌ Backup restore failed: ${backupId}`);
    }

    return result;
  } catch (error: any) {
    const errorMsg = `Restore failed: ${error.message}`;
    dbLogger.error(errorMsg);
    result.error = errorMsg;
    return result;
  }
}

/**
 * Delete a backup
 */
export async function deleteBackup(backupId: string): Promise<boolean> {
  try {
    // Remove backup file
    const backupPath = getBackupFilePath(backupId);
    if (fs.existsSync(backupPath)) {
      fs.unlinkSync(backupPath);
    }

    // Remove from metadata
    const metadata = await loadBackupMetadata();
    const filtered = metadata.filter(b => b.backupId !== backupId);
    await saveBackupMetadata(filtered);

    dbLogger.info(`Deleted backup: ${backupId}`);
    return true;
  } catch (error: any) {
    dbLogger.error(`Failed to delete backup ${backupId}: ${error.message}`);
    return false;
  }
}

/**
 * Get backup statistics
 */
export async function getBackupStats(): Promise<{
  totalBackups: number;
  totalSize: number;
  oldestBackup: Date | null;
  newestBackup: Date | null;
}> {
  const metadata = await loadBackupMetadata();

  if (metadata.length === 0) {
    return {
      totalBackups: 0,
      totalSize: 0,
      oldestBackup: null,
      newestBackup: null,
    };
  }

  const totalSize = metadata.reduce((sum, b) => sum + b.size, 0);
  const timestamps = metadata.map(b => b.timestamp.getTime());

  return {
    totalBackups: metadata.length,
    totalSize,
    oldestBackup: new Date(Math.min(...timestamps)),
    newestBackup: new Date(Math.max(...timestamps)),
  };
}

