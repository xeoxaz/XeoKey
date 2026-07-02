# xeokey → ONYX user migration

Move **login (username + password)** and **identity (`_id`)** from xeokey's
`XeoKey.users` collection into ONYX's `onyx.users` collection, preserving user
ids so xeokey's existing vault data stays linked, then point xeokey's auth at
the ONYX user API.

## Why this is non-trivial

| Concern | xeokey (`XeoKey.users`) | ONYX (`onyx.users`) |
| --- | --- | --- |
| Identity | `_id` (ObjectId) | `_id` (ObjectId) |
| Login key | `username` (case-insensitive) | `email` (unique) |
| Password hash | **bcrypt** (`bcryptjs`, 10 rounds) | **Argon2id** (PHC) |
| Email | none | required + unique index |
| Role | none | `user` / `admin` |
| Timestamps | `createdAt`, `lastLogin` | `created_at`, `updated_at` |
| Theme | `theme` | — |

Three hard constraints drive the design:

1. **IDs must be preserved 1:1.** xeokey's vault collections — `passwords`,
   `totp`, `notes`, `analytics` — are all keyed by `userId` = the string form of
   `users._id`. ONYX's `POST /auth/register` mints a *fresh* `ObjectId`, so it
   **cannot** be used for migration. We insert directly into `onyx.users` with
   the same `_id`.
2. **Login key mismatch.** xeokey users authenticate by username and have no
   email. ONYX is taught to log in by username (Part A).
3. **Password hash mismatch.** ONYX's `verify_password` only parses Argon2 PHC
   strings. ONYX is taught to detect and verify bcrypt hashes, then transparently
   rehash to Argon2id on the next successful login (Part A). Hashes migrate
   verbatim — **no password resets**.

## Decisions (locked)

- **Login key:** add username login to ONYX.
- **Passwords:** ONYX verifies bcrypt + rehashes to Argon2id on login.
- **Mechanism:** direct Mongo→Mongo migration script (preserves `_id` exactly).

---

## Part A — ONYX changes (deploy *before* migrating)

These are backward compatible: existing email login keeps working.

1. **Username login**
   - `db/users.rs`: add `find_by_username` (case-insensitive, matching xeokey
     semantics) and a **unique index on username** (case-insensitive collation
     or a normalized `username_lower`).
   - `db/cached_users.rs`: add a `find_by_username` passthrough.
   - `models/user.rs`: accept `{ username, password }` as a login payload in
     addition to `{ email, password }`.
   - `routes/auth.rs`: branch on the supplied identifier; keep the single
     ambiguous `401` to avoid user enumeration.
   - Make `email` optional/nullable and switch the unique-email index to a
     **partial unique index** so many migrated rows can have no email.

2. **bcrypt verify + transparent rehash**
   - Add the `bcrypt` crate.
   - `auth/password.rs` `verify_password`: detect scheme by prefix
     (`$2a$/$2b$/$2y$` → bcrypt, `$argon2` → argon2).
   - `routes/auth.rs` login: after a successful bcrypt verify, recompute an
     Argon2id hash and persist via `users.update(...)` (best-effort).

---

## Parts B & C — Migration script

Implemented in [`src/scripts/migrate-to-onyx.ts`](src/scripts/migrate-to-onyx.ts).
Read-only by default (Part C validation); `--apply` performs the migration
(Part B). Idempotent — re-running never clobbers a row ONYX has already upgraded
to Argon2id (uses `$setOnInsert` upsert keyed on `_id`).

```sh
cd src
# Part C — pre-flight validation (dry-run, no writes):
ONYX_MONGODB_URI='mongodb://<user>:<pass>@<host>:27017/?authSource=admin' \
  bun run migrate:onyx
# Part B — perform the migration:
ONYX_MONGODB_URI='mongodb://<user>:<pass>@<host>:27017/?authSource=admin' \
  bun run migrate:onyx:apply
```

Config (env, with localhost defaults): `XEOKEY_MONGODB_URI` / `XEOKEY_DB_NAME`
(default `XeoKey`), `ONYX_MONGODB_URI` / `ONYX_DB_NAME` (default `onyx`). The
target needs **ONYX's own DB credentials** — xeokey's user is not authorized on
the `onyx` database.

The script reports `total / migrated / skipped (already present) / flagged /
collisions / errors`, exits non-zero if anything could not be migrated, and:

- **flags** usernames outside ONYX's 3–32 char rule (they migrate, but cannot log
  in by username until renamed — Part C concern);
- **skips** usernames that collide (case-insensitive) with an existing different
  ONYX user, which would violate the unique username index.

For each doc in `XeoKey.users`, it upserts into `onyx.users` **by `_id`**:

```
_id:           <same ObjectId>           // preserve verbatim (upsert filter)
username:      username                  // 3–32 chars enforced at ONYX login; flagged here
password_hash: passwordHash              // bcrypt string, carried verbatim
email:         <omitted>                 // field left out → partial unique index skips it
role:          "user"
created_at:    createdAt
updated_at:    lastLogin ?? createdAt
```

- Upsert keyed on `_id` via `$setOnInsert` → safe to re-run; a row already
  upgraded to Argon2id is never clobbered.
- `email` is **omitted entirely** (not set to `null`) so ONYX's partial unique
  email index excludes migrated users.
- `theme` and all vault collections are **not** touched — they remain in
  `XeoKey` keyed by the now-shared id.

---

## Part D — Wire xeokey to ONYX (the "link")

**Implemented.** New module [`src/auth/onyx-client.ts`](src/auth/onyx-client.ts)
talks to ONYX; the `/login` and `/register` routes in `src/server.ts` now
delegate to it. ONYX base URL is `ONYX_CONFIG.BASE_URL` (env `ONYX_API_URL`,
default `http://127.0.0.1:8080`).

- **Login:** `onyxLogin(username, password)` → `POST /auth/login` (by username) →
  on success `GET /users/me` for the canonical `{ id, username, role }`. The id
  equals xeokey's `_id` for migrated users. The route then calls
  `upsertLocalProfile(id, username)` and `createSession(id, username)`, so the
  5-minute vault session and all `userId`-keyed vault data keep resolving.
  Invalid credentials → `null` (form error); ONYX unreachable → thrown → 500.
- **Register:** `onyxRegister(username, password)` → `POST /auth/register`
  (username only, no email). `409` → "Username already exists", `422` → the
  validation message. On success a local profile is created with the ONYX id.
- **Local profile:** `upsertLocalProfile` (in `src/auth/users.ts`) keeps a
  lightweight `XeoKey.users` doc (id + username + `theme`, **no** `passwordHash`)
  so xeokey-only fields work for users whose credentials live in ONYX. Idempotent
  — a no-op for migrated users.
- `authenticateUser` / `createUser` remain for the test suite but are no longer
  called by the routes. `theme` and vault data stay xeokey-owned; ONYX is the
  source of truth for credentials + identity.

> **ONYX deploy note (found in testing).** Part A changed the `email` index from
> a plain unique index to a *partial* unique one and added a unique `username`
> index. On a database created by an older ONYX, the auto-named `email_1` index
> conflicts; `init_indexes` now detects the conflict (codes 85/86), drops the
> stale index, and recreates it. The old plain index **must** be replaced —
> otherwise a second email-less migrated user collides on `null`. Restart ONYX
> with the new build *before* running Part B.

---

## Part E — Rollout & rollback

1. ✅ Deploy ONYX with Part A (backward compatible). *Done — :9000 serves username
   login + bcrypt verify; index migration applied on startup.*
2. ✅ Run Part C validation — 10 users, 0 flagged, 0 collisions.
3. ✅ `mongodump` both `XeoKey.users` (10 docs) and `onyx.users` (pre: 1 doc).
4. ✅ Run Part B + verify: 10/10 migrated, idempotent on re-run, `_id` preserved,
   bcrypt hashes verbatim, email absent. bcrypt→Argon2id rehash-on-login proven
   end-to-end. `onyx.users` now 11.
5. ✅ **Cutover — xeokey auth flipped to ONYX.**
   - `ONYX_API_URL=http://127.0.0.1:9000` set in `src/.env` (default :8080 would
     break logins since ONYX listens on :9000).
   - Service restarted (systemd, :3000). Verified end-to-end: register via xeokey
     creates the ONYX user + a same-`_id` local profile; login returns a vault
     session; bad creds return the normal form error (no 500).
6. **Rollback:** Part B only *added* to `onyx.users` (left `XeoKey.users` intact),
   and a backup is in the migration scratch dir. To revert the cutover: remove
   `ONYX_API_URL`, revert the `src/server.ts` Part-D edits, and restart — local
   `authenticateUser`/`createUser` are unchanged and resume immediately.

---

## Open follow-ups (out of "login + id" scope)

- Two password stores coexist temporarily (xeokey `passwordHash` + ONYX). Decide
  when to stop writing / clear xeokey's copy.
- Profile fields beyond login (`theme`, `lastLogin` semantics) stay in xeokey.
- Optional long-term email backfill for ONYX email login / password recovery.
