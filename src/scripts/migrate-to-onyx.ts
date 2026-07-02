/**
 * xeokey -> ONYX user migration (Parts B + C of MIGRATION.md).
 *
 * Copies the *login* (username + bcrypt password hash) and *identity* (`_id`)
 * of every xeokey user into ONYX's `users` collection, preserving `_id` exactly
 * so xeokey's vault data (passwords / totp / notes / analytics) stays linked.
 *
 * It is read-only by default (Part C: pre-flight validation). Pass `--apply` to
 * perform the migration (Part B). Idempotent: re-running never clobbers a row
 * ONYX has already upgraded to Argon2id — existing target rows are left intact.
 *
 *   bun run src/scripts/migrate-to-onyx.ts            # dry-run / validate
 *   bun run src/scripts/migrate-to-onyx.ts --apply    # perform migration
 *
 * Configuration (env vars, with sensible localhost defaults):
 *   XEOKEY_MONGODB_URI  source connection string   (default: MONGODB_URI or mongodb://localhost:27017)
 *   XEOKEY_DB_NAME      source database name        (default: XeoKey)
 *   ONYX_MONGODB_URI    target connection string    (default: same as source URI)
 *   ONYX_DB_NAME        target database name        (default: onyx)
 */

import { MongoClient, ObjectId, Collection, Document } from 'mongodb';

// ---- configuration -------------------------------------------------------

const DEFAULT_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017';

const SOURCE_URI = process.env.XEOKEY_MONGODB_URI || DEFAULT_URI;
const SOURCE_DB = process.env.XEOKEY_DB_NAME || 'XeoKey';
const TARGET_URI = process.env.ONYX_MONGODB_URI || SOURCE_URI;
const TARGET_DB = process.env.ONYX_DB_NAME || 'onyx';

// ONYX's request-level username rule (LoginRequest validates 3-32 chars). A user
// outside this range can be migrated but will not be able to log in by username
// until renamed, so we flag them.
const USERNAME_MIN = 3;
const USERNAME_MAX = 32;

// Case-insensitive collation matching xeokey's and ONYX's unique username index.
const CI_COLLATION = { locale: 'en', strength: 2 } as const;

const APPLY = process.argv.includes('--apply');

// ---- source/target shapes ------------------------------------------------

interface SourceUser extends Document {
  _id: ObjectId;
  username: string;
  passwordHash: string;
  theme?: string;
  createdAt?: Date;
  lastLogin?: Date;
}

interface Report {
  total: number;
  migrated: number;
  skipped: number; // already present in ONYX
  flagged: number; // migrated but with a warning (e.g. username length)
  errors: number;
}

// ---- helpers -------------------------------------------------------------

function log(msg = '') {
  console.log(msg);
}

function toDate(value: unknown, fallback: Date): Date {
  if (value instanceof Date) return value;
  if (typeof value === 'string' || typeof value === 'number') {
    const d = new Date(value);
    if (!Number.isNaN(d.getTime())) return d;
  }
  return fallback;
}

/** Build the ONYX `users` document. `email` is intentionally omitted so ONYX's
 *  partial unique email index skips this user (they log in by username). */
function toOnyxUser(src: SourceUser) {
  const createdAt = toDate(src.createdAt, new Date());
  const updatedAt = toDate(src.lastLogin ?? src.createdAt, createdAt);
  return {
    // _id is supplied via the upsert filter, not here, so Mongo cannot reject a
    // _id mutation on an existing document.
    username: src.username,
    password_hash: src.passwordHash,
    role: 'user',
    created_at: createdAt,
    updated_at: updatedAt,
  };
}

function usernameLengthOk(username: string): boolean {
  const len = username?.length ?? 0;
  return len >= USERNAME_MIN && len <= USERNAME_MAX;
}

/** Find an ONYX user with the same username (case-insensitive) but a different
 *  id — a collision that would violate ONYX's unique username index. */
async function findCollision(
  target: Collection,
  username: string,
  id: ObjectId,
): Promise<ObjectId | null> {
  const existing = await target.findOne(
    { username },
    { collation: CI_COLLATION, projection: { _id: 1 } },
  );
  if (existing && !existing._id.equals(id)) {
    return existing._id as ObjectId;
  }
  return null;
}

// ---- main ----------------------------------------------------------------

async function main() {
  log('='.repeat(70));
  log(`xeokey -> ONYX user migration  (${APPLY ? 'APPLY' : 'DRY-RUN / validate'})`);
  log('='.repeat(70));
  log(`Source: ${SOURCE_DB} @ ${redact(SOURCE_URI)}`);
  log(`Target: ${TARGET_DB} @ ${redact(TARGET_URI)}`);
  log();

  const sourceClient = new MongoClient(SOURCE_URI);
  const targetClient = SOURCE_URI === TARGET_URI ? sourceClient : new MongoClient(TARGET_URI);

  const report: Report = { total: 0, migrated: 0, skipped: 0, flagged: 0, errors: 0 };
  const flaggedUsernames: string[] = [];
  const collisions: string[] = [];

  try {
    await sourceClient.connect();
    if (targetClient !== sourceClient) await targetClient.connect();

    const sourceUsers = sourceClient.db(SOURCE_DB).collection<SourceUser>('users');
    const targetUsers = targetClient.db(TARGET_DB).collection('users');

    const cursor = sourceUsers.find({});
    for await (const src of cursor) {
      report.total++;

      // --- validation (Part C) ---
      if (!src.username || !src.passwordHash) {
        log(`  ✗ ${String(src._id)}: missing username or passwordHash — SKIPPED`);
        report.errors++;
        continue;
      }

      let flagged = false;
      if (!usernameLengthOk(src.username)) {
        flagged = true;
        flaggedUsernames.push(src.username);
        log(
          `  ⚠ "${src.username}" (len ${src.username.length}): outside ONYX's ` +
            `${USERNAME_MIN}-${USERNAME_MAX} char rule — username login will fail until renamed`,
        );
      }

      const collidesWith = await findCollision(targetUsers, src.username, src._id);
      if (collidesWith) {
        collisions.push(src.username);
        log(
          `  ✗ "${src.username}": collides with existing ONYX user ${String(collidesWith)} ` +
            `(case-insensitive) — SKIPPED`,
        );
        report.errors++;
        continue;
      }

      // --- migration (Part B) ---
      const onyxUser = toOnyxUser(src);

      if (!APPLY) {
        log(`  • would migrate "${src.username}" (${String(src._id)})${flagged ? ' [flagged]' : ''}`);
        if (flagged) report.flagged++;
        continue;
      }

      try {
        const result = await targetUsers.updateOne(
          { _id: src._id },
          { $setOnInsert: onyxUser },
          { upsert: true },
        );

        if (result.upsertedCount > 0) {
          report.migrated++;
          if (flagged) report.flagged++;
          log(`  ✓ migrated "${src.username}" (${String(src._id)})`);
        } else {
          report.skipped++;
          log(`  = "${src.username}" (${String(src._id)}) already in ONYX — skipped`);
        }
      } catch (err) {
        report.errors++;
        log(`  ✗ "${src.username}" (${String(src._id)}): ${err instanceof Error ? err.message : err}`);
      }
    }

    // --- summary ---
    log();
    log('-'.repeat(70));
    log('Summary');
    log('-'.repeat(70));
    log(`  Source users:        ${report.total}`);
    if (APPLY) {
      log(`  Migrated:            ${report.migrated}`);
      log(`  Already present:     ${report.skipped}`);
    } else {
      log(`  Would migrate:       ${report.total - report.errors}`);
    }
    log(`  Flagged (username):  ${report.flagged}${flaggedUsernames.length ? ` -> ${flaggedUsernames.join(', ')}` : ''}`);
    log(`  Collisions:          ${collisions.length}${collisions.length ? ` -> ${collisions.join(', ')}` : ''}`);
    log(`  Errors/skipped:      ${report.errors}`);
    log();

    if (!APPLY) {
      log('Dry-run only. Re-run with --apply to perform the migration.');
    } else {
      const targetCount = await targetUsers.countDocuments({});
      log(`ONYX users collection now holds ${targetCount} document(s).`);
    }

    // Non-zero exit if anything could not be migrated, so CI/operators notice.
    if (report.errors > 0) process.exitCode = 1;
  } finally {
    await sourceClient.close();
    if (targetClient !== sourceClient) await targetClient.close();
  }
}

function redact(uri: string): string {
  return uri.includes('@') ? uri.split('@')[1] || uri : uri;
}

main().catch((err) => {
  console.error('Migration failed:', err);
  process.exit(1);
});
