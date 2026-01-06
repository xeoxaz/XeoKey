import { getDatabase } from '../db/mongodb';
import { ObjectId } from 'mongodb';
import * as crypto from 'crypto';
import bcrypt from 'bcryptjs';
import { base32ToBuffer, generateTotpCode, verifyTotpCode, TotpAlgorithm, generateHotpCode, verifyHotpCode } from '../utils/totp';

export interface TotpEntry {
  _id?: string;
  userId: string;
  label: string; // e.g., "GitHub"
  account?: string; // e.g., email/username
  secret: string; // Encrypted (base32 before encrypt)
  algorithm: TotpAlgorithm; // SHA1 default
  digits: number; // 6 default
  period: number; // 30 default for TOTP
  type: 'TOTP' | 'HOTP';
  counter?: number; // for HOTP
  createdAt: Date;
  lastUsedAt?: Date;
  backupCodeHashes?: string[]; // hashed with bcrypt
}

// Reuse AES-256-CBC encryption from password model
function getEncryptionKey(): Buffer {
  const key = process.env.ENCRYPTION_KEY || 'default-encryption-key-change-in-production';
  if (process.env.NODE_ENV === 'production' && key === 'default-encryption-key-change-in-production') {
    throw new Error('ENCRYPTION_KEY environment variable must be set in production');
  }
  return crypto.createHash('sha256').update(key).digest();
}

function encrypt(value: string): string {
  const algorithm = 'aes-256-cbc';
  const key = getEncryptionKey();
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(algorithm, key, iv);
  let encrypted = cipher.update(value, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
}

function decrypt(encrypted: string): string {
  const algorithm = 'aes-256-cbc';
  const key = getEncryptionKey();
  const parts = encrypted.split(':');
  if (parts.length !== 2) {
    throw new Error('Invalid encrypted value format');
  }
  const iv = Buffer.from(parts[0], 'hex');
  const data = parts[1];
  const decipher = crypto.createDecipheriv(algorithm, key, iv);
  let decrypted = decipher.update(data, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

export function generateBackupCodes(count: number = 10): { codes: string[]; hashes: string[] } {
  const codes: string[] = [];
  const hashes: string[] = [];
  for (let i = 0; i < count; i++) {
    // 10-character alphanumeric (no ambiguous)
    const raw = crypto.randomBytes(8).toString('base64').replace(/[+/=]/g, '').slice(0, 10);
    const salt = bcrypt.genSaltSync(10);
    const hash = bcrypt.hashSync(raw, salt);
    codes.push(raw);
    hashes.push(hash);
  }
  return { codes, hashes };
}

export async function createTotpEntry(
  userId: string,
  label: string,
  secretBase32: string,
  options?: { account?: string; algorithm?: TotpAlgorithm; digits?: number; period?: number; withBackupCodes?: boolean; type?: 'TOTP'|'HOTP'; counter?: number }
): Promise<{ entry: TotpEntry; plaintextBackupCodes?: string[] }> {
  const db = getDatabase();
  const col = db.collection<TotpEntry>('totp');

  const algorithm = options?.algorithm ?? 'SHA1';
  const digits = options?.digits ?? 6;
  const period = options?.type === 'HOTP' ? 30 : (options?.period ?? 30);
  const type = options?.type ?? 'TOTP';

  // Validate base32 by decoding to buffer
  base32ToBuffer(secretBase32);

  const encSecret = encrypt(secretBase32);
  const entry: TotpEntry = {
    userId,
    label,
    account: options?.account,
    secret: encSecret,
    algorithm,
    digits,
    period,
    type,
    counter: type === 'HOTP' ? (options?.counter ?? 0) : undefined,
    createdAt: new Date(),
  };

  let plaintextBackupCodes: string[] | undefined;
  if (options?.withBackupCodes) {
    const { codes, hashes } = generateBackupCodes();
    plaintextBackupCodes = codes;
    entry.backupCodeHashes = hashes;
  }

  const result = await col.insertOne(entry);
  entry._id = result.insertedId.toString();
  return { entry, plaintextBackupCodes };
}

export async function listTotpEntries(userId: string): Promise<TotpEntry[]> {
  const db = getDatabase();
  const col = db.collection<TotpEntry>('totp');
  return await col.find({ userId } as any).sort({ label: 1 }).toArray();
}

export async function getTotpEntry(entryId: string, userId: string): Promise<TotpEntry | null> {
  const db = getDatabase();
  const col = db.collection<TotpEntry>('totp');
  if (!ObjectId.isValid(entryId)) return null;
  return await col.findOne({ _id: new ObjectId(entryId), userId } as any);
}

export async function deleteTotpEntry(entryId: string, userId: string): Promise<boolean> {
  const db = getDatabase();
  const col = db.collection<TotpEntry>('totp');
  if (!ObjectId.isValid(entryId)) return false;
  const res = await col.deleteOne({ _id: new ObjectId(entryId), userId } as any);
  return res.deletedCount > 0;
}

export async function getCurrentTotpCode(entry: TotpEntry): Promise<string> {
  const secretBase32 = decrypt(entry.secret);
  if (entry.type === 'HOTP') {
    return generateHotpCode(secretBase32, entry.counter ?? 0, entry.digits, entry.algorithm);
  }
  return generateTotpCode(secretBase32, Date.now(), entry.period, entry.digits, entry.algorithm);
}

export async function verifyTotpOrBackup(entry: TotpEntry, code: string): Promise<{ ok: boolean; usedBackup?: boolean }> {
  const secretBase32 = decrypt(entry.secret);
  let ok = false;
  if (entry.type === 'HOTP') {
    // For HOTP use lookahead window of 5
    const res = verifyHotpCode(secretBase32, code, entry.counter ?? 0, 5, entry.digits, entry.algorithm);
    if (res.ok && typeof res.matchedCounter === 'number') {
      // Advance counter to the next value after the matched one
      const db = getDatabase();
      const col = db.collection<TotpEntry>('totp');
      entry.counter = (res.matchedCounter ?? (entry.counter ?? 0)) + 1;
      await col.updateOne({ _id: new ObjectId(entry._id!), userId: entry.userId } as any, { $set: { counter: entry.counter, lastUsedAt: new Date() } });
      ok = true;
    }
  } else {
    ok = verifyTotpCode(secretBase32, code, 1, entry.period, entry.digits, entry.algorithm);
  }
  if (ok) return { ok: true };
  if (entry.backupCodeHashes && entry.backupCodeHashes.length > 0) {
    const idx = entry.backupCodeHashes.findIndex(h => bcrypt.compareSync(code, h));
    if (idx !== -1) {
      // Consume backup code (one-time use)
      const db = getDatabase();
      const col = db.collection<TotpEntry>('totp');
      const newHashes = entry.backupCodeHashes.slice();
      newHashes.splice(idx, 1);
      await col.updateOne({ _id: new ObjectId(entry._id!), userId: entry.userId } as any, { $set: { backupCodeHashes: newHashes, lastUsedAt: new Date() } });
      return { ok: true, usedBackup: true };
    }
  }
  return { ok: false };
}


