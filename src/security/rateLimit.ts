// Rate limiting for authentication endpoints

interface RateLimitEntry {
  count: number;
  resetAt: number;
}

const rateLimitStore = new Map<string, RateLimitEntry>();

// Rate limit configuration
const RATE_LIMIT_WINDOW = 15 * 60 * 1000; // 15 minutes
const MAX_ATTEMPTS = 5; // Max attempts per window
const LOCKOUT_DURATION = 30 * 60 * 1000; // 30 minutes lockout after max attempts

// Get client identifier (IP address)
function getClientId(request: Request): string {
  const forwarded = request.headers.get('x-forwarded-for');
  const ip = forwarded ? forwarded.split(',')[0].trim() :
             request.headers.get('x-real-ip') ||
             'unknown';
  return ip;
}

// Check rate limit
export function checkRateLimit(request: Request, endpoint: string): { allowed: boolean; remaining: number; resetAt: number } {
  const clientId = `${getClientId(request)}:${endpoint}`;
  const now = Date.now();

  let entry = rateLimitStore.get(clientId);

  // Clean up expired entries
  if (entry && entry.resetAt < now) {
    rateLimitStore.delete(clientId);
    entry = undefined;
  }

  if (!entry) {
    entry = {
      count: 0,
      resetAt: now + RATE_LIMIT_WINDOW,
    };
    rateLimitStore.set(clientId, entry);
  }

  // Check if locked out
  if (entry.count >= MAX_ATTEMPTS) {
    const lockoutRemaining = entry.resetAt - now;
    if (lockoutRemaining > 0) {
      return {
        allowed: false,
        remaining: 0,
        resetAt: entry.resetAt,
      };
    } else {
      // Reset after lockout period
      entry.count = 0;
      entry.resetAt = now + RATE_LIMIT_WINDOW;
    }
  }

  entry.count++;
  rateLimitStore.set(clientId, entry);

  const remaining = Math.max(0, MAX_ATTEMPTS - entry.count);
  const allowed = entry.count <= MAX_ATTEMPTS;

  return {
    allowed,
    remaining,
    resetAt: entry.resetAt,
  };
}

// Reset rate limit (on successful login)
export function resetRateLimit(request: Request, endpoint: string): void {
  const clientId = `${getClientId(request)}:${endpoint}`;
  rateLimitStore.delete(clientId);
}

// Clean up old entries periodically
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of rateLimitStore.entries()) {
    if (entry.resetAt < now) {
      rateLimitStore.delete(key);
    }
  }
}, 60 * 1000); // Clean up every minute

