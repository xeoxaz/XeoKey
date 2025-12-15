import { MongoClient, Db } from 'mongodb';
import { dbLogger } from '../utils/logger';

let client: MongoClient | null = null;
let db: Db | null = null;

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

