/**
 * Thin HTTP client for the ONYX user service.
 *
 * ONYX is the source of truth for credentials and identity; xeokey delegates
 * login and registration to it and uses the returned id (which equals xeokey's
 * `users._id` for migrated users) to key its own vault session and data.
 *
 * See ONYX/API.md and MIGRATION.md (Part D).
 */

import { ONYX_CONFIG } from '../config/constants';
import { logger } from '../utils/logger';

/** A user as returned by ONYX (`UserResponse`). `email` may be null. */
export interface OnyxUser {
  id: string;
  username: string;
  role: 'user' | 'admin';
  email: string | null;
}

/** Outcome of a registration attempt. */
export type OnyxRegisterResult =
  | { ok: true; user: OnyxUser }
  | { ok: false; conflict: true }
  | { ok: false; validationError: string };

/** Raised when ONYX is unreachable or returns an unexpected error. The login /
 *  register routes map this to a 5xx rather than an auth failure. */
export class OnyxServiceError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'OnyxServiceError';
  }
}

async function onyxFetch(path: string, init: RequestInit): Promise<Response> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), ONYX_CONFIG.REQUEST_TIMEOUT);
  try {
    return await fetch(`${ONYX_CONFIG.BASE_URL}${path}`, {
      ...init,
      signal: controller.signal,
      headers: { 'Content-Type': 'application/json', ...init.headers },
    });
  } catch (error) {
    throw new OnyxServiceError(
      `ONYX request to ${path} failed: ${error instanceof Error ? error.message : String(error)}`,
    );
  } finally {
    clearTimeout(timeout);
  }
}

/**
 * Authenticate against ONYX by username.
 *
 * Returns the canonical ONYX user on success, `null` for invalid credentials
 * (ONYX `401`), and throws [`OnyxServiceError`] if ONYX is unreachable or errors.
 */
export async function onyxLogin(username: string, password: string): Promise<OnyxUser | null> {
  const loginRes = await onyxFetch('/auth/login', {
    method: 'POST',
    body: JSON.stringify({ username, password }),
  });

  if (loginRes.status === 401) {
    return null; // invalid credentials
  }
  if (!loginRes.ok) {
    throw new OnyxServiceError(`ONYX login returned ${loginRes.status}`);
  }

  const { token } = (await loginRes.json()) as { token?: string };
  if (!token) {
    throw new OnyxServiceError('ONYX login response missing token');
  }

  // Resolve the canonical id/username/role from the issued token.
  const meRes = await onyxFetch('/users/me', {
    method: 'GET',
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!meRes.ok) {
    throw new OnyxServiceError(`ONYX /users/me returned ${meRes.status}`);
  }

  return (await meRes.json()) as OnyxUser;
}

/**
 * Register a new user in ONYX (username + password, no email).
 *
 * Returns the created user on success, a conflict marker on `409`, or a
 * validation message on `422`. Throws [`OnyxServiceError`] for service errors.
 */
export async function onyxRegister(username: string, password: string): Promise<OnyxRegisterResult> {
  const res = await onyxFetch('/auth/register', {
    method: 'POST',
    body: JSON.stringify({ username, password }),
  });

  if (res.status === 201) {
    return { ok: true, user: (await res.json()) as OnyxUser };
  }
  if (res.status === 409) {
    return { ok: false, conflict: true };
  }
  if (res.status === 422) {
    const body = (await res.json().catch(() => ({}))) as { error?: string };
    return { ok: false, validationError: body.error || 'Invalid username or password.' };
  }

  const detail = await res.text().catch(() => '');
  logger.error(`ONYX register returned ${res.status}: ${detail}`);
  throw new OnyxServiceError(`ONYX register returned ${res.status}`);
}
