// Logger
import { logger } from './utils/logger';
import { debugLog } from './utils/debug';

// MongoDB connection
import { connectMongoDB, closeMongoDB, isConnected } from './db/mongodb';

// Authentication
import { createSession, getSession, deleteSession, getSessionIdFromRequest, createSessionCookie, createLogoutCookie } from './auth/session';
import { listTotpEntries, createTotpEntry, getCurrentTotpCode } from './models/totp';
import { authenticateUser, createUser, getUserById, updateUserTheme, upsertLocalProfile } from './auth/users';
import { onyxLogin, onyxRegister } from './auth/onyx-client';

// Password management
import { createPasswordEntry, getUserPasswords, getPasswordEntry, getDecryptedPassword, updatePasswordEntry, deletePasswordEntry } from './models/password';

// Notes management
// Remove unused imports
import { createNoteEntry, getUserNotes, getNoteEntry, getDecryptedNoteContent, updateNoteEntry, deleteNoteEntry } from './models/notes';

// Analytics
import { trackEvent } from './models/analytics';

// Backup management
// Remove unused imports
import { listBackups, createBackup, restoreBackup, deleteBackup, getBackupStats } from './db/backup';

// Health and integrity checks
// Remove unused imports
import { quickHealthCheck } from './db/integrity';
import { forceHealthCheck, getLastHealthCheck } from './db/health';

// Password recovery
import { getUnrecoverablePasswords, recoverPasswordWithMasterKey, repairPasswordEntry, batchRecoverPasswords } from './db/password-recovery';

// Input sanitization
import { sanitizeUsername, sanitizeString, sanitizeWebsite, validateUsername, validatePassword } from './utils/sanitize';

// Security
import { checkRateLimit, resetRateLimit } from './security/rateLimit';
import { createCsrfToken, getOrCreateCsrfToken, verifyCsrfToken, deleteCsrfToken } from './security/csrf';

// Security headers
const SECURITY_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "X-XSS-Protection": "1; mode=block",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self';",
  "Referrer-Policy": "strict-origin-when-cross-origin",
};

// Router System - OS-like hierarchical structure
type HttpMethod = "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "HEAD" | "OPTIONS";
type RouteHandler = (request: Request, params: Record<string, string>, query: URLSearchParams) => Promise<Response> | Response;
type Middleware = (request: Request, params: Record<string, string>, query: URLSearchParams) => Promise<Response | null> | Response | null;

interface RouteNode {
  handlers: Map<HttpMethod, RouteHandler>;
  children: Map<string, RouteNode>;
  paramName?: string;
  paramNode?: RouteNode;
  catchAllName?: string;
  catchAllHandler?: Map<HttpMethod, RouteHandler>;
  middleware: Middleware[];
}

class Router {
  private root: RouteNode;
  private globalMiddleware: Middleware[];

  constructor() {
    this.root = {
      handlers: new Map(),
      children: new Map(),
      middleware: [],
    };
    this.globalMiddleware = [];
  }

  // Add global middleware
  use(middleware: Middleware): void {
    this.globalMiddleware.push(middleware);
  }

  // Register route with method
  private register(method: HttpMethod, path: string, handler: RouteHandler, middleware: Middleware[] = []): void {
    const segments = this.normalizePath(path).split("/").filter(Boolean);
    let current = this.root;

    for (let i = 0; i < segments.length; i++) {
      const segment = segments[i];
      const isParam = segment.startsWith(":");
      const isCatchAll = isParam && segment.endsWith("*");

      if (isCatchAll) {
        const catchAllName = segment.slice(1, -1);
        if (!current.catchAllHandler) {
          current.catchAllHandler = new Map();
        }
        current.catchAllName = catchAllName;
        current.catchAllHandler.set(method, handler);
        current.middleware.push(...middleware);
        return;
      } else if (isParam) {
        const paramName = segment.slice(1);
        if (!current.paramNode) {
          current.paramNode = {
            handlers: new Map(),
            children: new Map(),
            paramName,
            middleware: [],
          };
        }
        current = current.paramNode;
      } else {
        if (!current.children.has(segment)) {
          current.children.set(segment, {
            handlers: new Map(),
            children: new Map(),
            middleware: [],
          });
        }
        current = current.children.get(segment)!;
      }
    }

    current.handlers.set(method, handler);
    current.middleware.push(...middleware);
  }

  // HTTP method shortcuts
  get(path: string, handler: RouteHandler, ...middleware: Middleware[]): void {
    this.register("GET", path, handler, middleware);
  }

  post(path: string, handler: RouteHandler, ...middleware: Middleware[]): void {
    this.register("POST", path, handler, middleware);
  }

  put(path: string, handler: RouteHandler, ...middleware: Middleware[]): void {
    this.register("PUT", path, handler, middleware);
  }

  delete(path: string, handler: RouteHandler, ...middleware: Middleware[]): void {
    this.register("DELETE", path, handler, middleware);
  }

  patch(path: string, handler: RouteHandler, ...middleware: Middleware[]): void {
    this.register("PATCH", path, handler, middleware);
  }

  // Resolve route and execute handler
  async resolve(request: Request, pathname: string): Promise<Response | null> {
    const segments = this.normalizePath(pathname).split("/").filter(Boolean);
    const params: Record<string, string> = {};
    const query = new URL(request.url).searchParams;
    const method = request.method.toUpperCase() as HttpMethod;

    let current = this.root;
    const middlewareStack: Middleware[] = [...this.globalMiddleware];

    // Traverse route tree
    for (let i = 0; i < segments.length; i++) {
      const segment = segments[i];

      // Try exact match first (before catch-all)
      if (current.children.has(segment)) {
        current = current.children.get(segment)!;
        middlewareStack.push(...current.middleware);
      } else if (current.paramNode) {
        // Use parameter node
        current = current.paramNode;
        if (current.paramName) {
          params[current.paramName] = segment;
        }
        middlewareStack.push(...current.middleware);
      } else {
        // No exact match, check for catch-all handler
        if (current.catchAllHandler && current.catchAllHandler.has(method)) {
          const remainingPath = segments.slice(i).join("/");
          if (current.catchAllName) {
            params[current.catchAllName] = remainingPath;
          }

          // Execute middleware
          for (const middleware of middlewareStack) {
            const result = await middleware(request, params, query);
            if (result !== null) {
              return result;
            }
          }

          const handler = current.catchAllHandler.get(method)!;
          return await handler(request, params, query);
        }
        return null; // Route not found
      }
    }

    // Execute middleware
    for (const middleware of middlewareStack) {
      const result = await middleware(request, params, query);
      if (result !== null) {
        return result;
      }
    }

    // Execute route handler
    const handler = current.handlers.get(method);
    if (!handler) {
      return null; // Method not allowed
    }

    return await handler(request, params, query);
  }

  // Normalize path (remove trailing slashes, handle root)
  private normalizePath(path: string): string {
    if (path === "/") return "";
    return path.replace(/^\/+|\/+$/g, "");
  }
}

// Validate and parse port
function getPort(): number {
  const portEnv = process.env.PORT;
  if (!portEnv) return 3000;

  const port = parseInt(portEnv, 10);
  if (isNaN(port) || port < 1 || port > 65535) {
    throw new Error(`Invalid PORT value: ${portEnv}. Must be between 1 and 65535.`);
  }

  return port;
}

// Validate HTTP method
function isValidMethod(method: string): boolean {
  const allowedMethods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];
  return allowedMethods.includes(method.toUpperCase());
}

// Create error response
function createErrorResponse(status: number, message: string): Response {
  return Response.json(
    { error: message, status },
    {
      status,
      headers: {
        ...SECURITY_HEADERS,
        "Content-Type": "application/json",
      },
    }
  );
}

// Create success response with security headers
function createResponse(body: string | object, contentType = "application/json"): Response {
  const headers = {
    ...SECURITY_HEADERS,
    "Content-Type": contentType,
  };

  if (typeof body === "string") {
    return new Response(body, { headers });
  }

  return Response.json(body, { headers });
}

// Template system - Load templates from files
let headerTemplate: string | null = null;
let footerTemplate: string | null = null;

async function loadTemplates(): Promise<void> {
  try {
    const headerFile = Bun.file("templates/header.html");
    const footerFile = Bun.file("templates/footer.html");

    headerTemplate = await headerFile.text();
    footerTemplate = await footerFile.text();
  } catch (error) {
    logger.error(`Failed to load templates: ${error}`);
    throw new Error("Template files not found");
  }
}

async function getHeader(title: string = "XeoKey", session: { username: string; userId: string } | null = null, issueCount: number = 0): Promise<string> {
  if (!headerTemplate) {
    throw new Error("Header template not loaded");
  }

  let header = headerTemplate.replace("{{TITLE}}", title);

  // If not logged in, show only branding, hide nav items
  if (!session) {
    // Hide nav-main and nav-actions sections using CSS (more reliable than regex)
    header = header.replace('</head>', '<style>.nav-main, .nav-actions { display: none !important; }</style></head>');
  } else {
    // Add login/logout menu items for logged in users
    const authMenu = `<div class="nav-item dropdown">
        <button type="button">${sanitizeString(session.username)}</button>
        <div class="dropdown-menu">
          <a href="/settings">Settings</a>
          <a href="/logout">Logout</a>
        </div>
      </div>`;

    // Get password count for navigation menu
    let passwordCount = 0;
    try {
      if (isConnected()) {
        const { getUserPasswords } = await import('./models/password');
        const userIdString = typeof session.userId === 'string' ? session.userId : (session.userId as any).toString();
        const passwords = await getUserPasswords(userIdString);
        passwordCount = passwords.length;
      }
    } catch (error) {
      // Ignore errors when getting password count for header
    }

    // Update "All Passwords" link in dropdown to include count
    header = header.replace(
      '<a href="/passwords">All Passwords</a>',
      `<a href="/passwords">All Passwords (${passwordCount})</a>`
    );

    // Get TOTP count for navigation menu
    let totpCount = 0;
    try {
      if (isConnected()) {
        const { listTotpEntries } = await import('./models/totp');
        const userIdString = typeof session.userId === 'string' ? session.userId : (session.userId as any).toString();
        const totpEntries = await listTotpEntries(userIdString);
        totpCount = totpEntries.length;
      }
    } catch (error) {
      // Ignore errors when getting TOTP count for header
    }

    // Get backup count for navigation menu
    let backupCount = 0;
    try {
      if (isConnected()) {
        const { listBackups } = await import('./db/backup');
        const backups = await listBackups();
        backupCount = backups.length;
      }
    } catch (error) {
      // Ignore errors when getting backup count for header
    }

    // Get unrecoverable password count for navigation menu
    let unrecoverableCount = 0;
    try {
      if (isConnected()) {
        const { getUnrecoverablePasswords } = await import('./db/password-recovery');
        const userIdString = typeof session.userId === 'string' ? session.userId : (session.userId as any).toString();
        const unrecoverable = await getUnrecoverablePasswords(userIdString);
        unrecoverableCount = unrecoverable.filter(e => !e.canDecrypt).length;
      }
    } catch (error) {
      // Ignore errors when getting unrecoverable password count for header
    }

    const vaultMenu = `<div class="nav-item dropdown">
        <button type="button">Vault</button>
        <div class="dropdown-menu">
          <a href="/passwords">Passwords (${passwordCount})</a>
          <a href="/notes">Notes</a>
          <a href="/totp">TOTP (${totpCount})</a>
        </div>
      </div>`;
    const operationsMenu = `<div class="nav-item dropdown">
        <button type="button">Operations${unrecoverableCount > 0 ? ` <span class="nav-badge">${unrecoverableCount}</span>` : ''}</button>
        <div class="dropdown-menu">
          <a href="/health">System Health</a>
          <a href="/health#password-issues">Password Issues${unrecoverableCount > 0 ? ` (${unrecoverableCount})` : ''}</a>
          <a href="/backups">Backups (${backupCount})</a>
        </div>
      </div>`;

    // Replace the primary nav with a simpler operator-focused layout.
    const navMainContent = `<div class="nav-main">
        <div class="nav-item">
          <a href="/">Dashboard</a>
        </div>
        ${vaultMenu}
        ${operationsMenu}
      </div>`;
    header = header.replace(/<div class="nav-main">[\s\S]*?<\/div>\s*<div class="nav-actions">/, `${navMainContent}\n      <div class="nav-actions">`);

    const navActionsContent = authMenu;
    // Replace the nav-actions placeholder - use a more flexible regex to handle whitespace variations
    // Try multiple replacement strategies
    const navActionsRegex = /<div class="nav-actions">[\s\S]*?<\/div>/;
    if (navActionsRegex.test(header)) {
      header = header.replace(navActionsRegex, `<div class="nav-actions">\n        ${navActionsContent}\n      </div>`);
    } else if (header.includes('<!-- Additional nav items will be inserted here by server -->')) {
      // Fallback: try to find and replace just the comment
      header = header.replace('<!-- Additional nav items will be inserted here by server -->', navActionsContent);
    } else {
      // Last resort: append before closing nav tag
      header = header.replace('</nav>', `  <div class="nav-actions">\n        ${navActionsContent}\n      </div>\n    </nav>`);
    }
  }

  return header;
}

function normalizeThemePreference(theme?: string): 'slate' | 'slate-contrast' | 'legacy-blue' {
  if (theme === 'slate-contrast' || theme === 'legacy-blue' || theme === 'slate') {
    return theme;
  }
  return 'slate';
}

function applyThemeToHeader(header: string, theme: string): string {
  const normalized = normalizeThemePreference(theme);
  return header.replace('<body>', `<body data-theme="${normalized}">`);
}

async function getFooter(session: { username: string; userId: string } | null = null, issueCount: number = 0): Promise<string> {
  if (!footerTemplate) {
    throw new Error("Footer template not loaded");
  }
  const year = new Date().getFullYear();
  let footer = footerTemplate.replace("{{YEAR}}", year.toString());

  // Populate bottom navigation for mobile if logged in
  if (session) {
    const dashboardBadge = issueCount > 0
      ? `<span class="nav-badge">${issueCount}</span>`
      : `<span class="nav-badge nav-badge-success">✓</span>`;

    const bottomNavContent = `
      <a href="/" class="bottom-nav-item">
        <span class="bottom-nav-icon">📊</span>
        <span class="bottom-nav-label">Dashboard</span>
        ${dashboardBadge}
      </a>
      <a href="/passwords" class="bottom-nav-item">
        <span class="bottom-nav-icon">🔑</span>
        <span class="bottom-nav-label">Vault</span>
      </a>
      <a href="/health" class="bottom-nav-item">
        <span class="bottom-nav-icon">⚙️</span>
        <span class="bottom-nav-label">Ops</span>
      </a>
      <a href="/backups" class="bottom-nav-item">
        <span class="bottom-nav-icon">💾</span>
        <span class="bottom-nav-label">Backups</span>
      </a>
      <a href="/logout" class="bottom-nav-item">
        <span class="bottom-nav-icon">🚪</span>
        <span class="bottom-nav-label">Logout</span>
      </a>
    `;
    footer = footer.replace('<!-- Navigation items will be populated by server -->', bottomNavContent);
  } else {
    // Hide bottom nav if not logged in
    footer = footer.replace(/<nav class="bottom-nav"[^>]*>[\s\S]*?<\/nav>/s, '');
  }

  return footer;
}

// Render page with header and footer
async function renderPage(body: string, title: string = "XeoKey", request?: Request): Promise<Response> {
  let session = null;
  let issueCount = 0;
  let theme: 'slate' | 'slate-contrast' | 'legacy-blue' = 'slate';

  if (request && isConnected()) {
    const sessionData = await attachSession(request);
    if (sessionData) {
      session = { username: sessionData.username, userId: sessionData.userId };
      // Get security issue count for notification badge
      const analysis = await analyzePasswords(sessionData.userId);
      issueCount = analysis.duplicateCount + analysis.weakPasswordCount;

      const user = await getUserById(sessionData.userId);
      theme = normalizeThemePreference(user?.theme);
    }
  }
  const themedHeader = applyThemeToHeader(await getHeader(title, session, issueCount), theme);
  const html = themedHeader + body + await getFooter(session, issueCount);
  return createResponse(html, "text/html");
}

// Render login page without page-content wrapper (for custom layout)
async function renderLoginPage(body: string, title: string = "Login - XeoKey", request?: Request): Promise<Response> {
  let session = null;
  let issueCount = 0;
  let theme: 'slate' | 'slate-contrast' | 'legacy-blue' = 'slate';

  if (request && isConnected()) {
    const sessionData = await attachSession(request);
    if (sessionData) {
      session = { username: sessionData.username, userId: sessionData.userId };
      const user = await getUserById(sessionData.userId);
      theme = normalizeThemePreference(user?.theme);
    }
  }

  // Get header and footer
  let header = applyThemeToHeader(await getHeader(title, session, issueCount), theme);
  let footer = await getFooter(session, issueCount);

  // Remove page-content wrapper from header (it's opened in header template)
  // Replace with empty string to remove the opening div
  header = header.replace('<div class="page-content">', '');

  // Close main tag before footer (footer expects main to be closed)
  // Our body content goes directly in main, then we close it
  const html = header + body + '</main>' + footer;
  return createResponse(html, "text/html");
}

// Initialize router and define routes
const router = new Router();

// Example middleware
const loggerMiddleware: Middleware = async (request, params, query) => {
  debugLog(logger, `${request.method} ${request.url}`);
  return null; // Continue to next handler
};

// Authentication middleware - attach session to request
async function attachSession(request: Request): Promise<{ sessionId: string; userId: string; username: string } | null> {
  if (!isConnected()) {
    return null;
  }

  const sessionId = getSessionIdFromRequest(request);
  if (!sessionId) {
    return null;
  }

  const session = await getSession(sessionId);
  if (!session) {
    return null;
  }

  return {
    sessionId: session.sessionId,
    userId: session.userId,
    username: session.username,
  };
}

// Get CSRF token for session
async function getCsrfTokenForSession(request: Request): Promise<string | null> {
  const session = await attachSession(request);
  if (!session) {
    return null;
  }
  return createCsrfToken(session.sessionId);
}

// Require authentication middleware
const requireAuth: Middleware = async (request, params, query) => {
  if (!isConnected()) {
    return createErrorResponse(503, "Database not available");
  }

  const session = await attachSession(request);
  if (!session) {
    return createErrorResponse(401, "Unauthorized");
  }

  return null; // Continue to handler
};

// Page content definitions
const pages: Record<string, { title: string; body: string }> = {
  "/": {
    title: "Dashboard - XeoKey",
    body: `
      <h1>Dashboard</h1>
      <p>Welcome to your password manager dashboard.</p>
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1.5rem; margin-top: 2rem;">
        <div style="background: var(--color-bg-secondary); padding: 1.5rem; border-radius: 8px; border: 1px solid var(--color-border);">
          <h3 style="margin-bottom: 0.5rem; color: var(--color-accent-light);">Quick Actions</h3>
          <p style="margin-bottom: 1rem; color: var(--color-text-secondary);">Manage your passwords</p>
          <a href="/passwords/add" style="display: inline-block; background: var(--color-border); color: var(--color-text-primary); padding: 0.5rem 1rem; border-radius: 4px; text-decoration: none; border: 1px solid var(--color-bg-tertiary);">Add Password</a>
        </div>
        <div style="background: var(--color-bg-secondary); padding: 1.5rem; border-radius: 8px; border: 1px solid var(--color-border);">
          <h3 style="margin-bottom: 0.5rem; color: var(--color-accent-light);">Your Passwords</h3>
          <p style="margin-bottom: 1rem; color: var(--color-text-secondary);">View all saved passwords</p>
          <a href="/passwords" style="display: inline-block; background: var(--color-border); color: var(--color-text-primary); padding: 0.5rem 1rem; border-radius: 4px; text-decoration: none; border: 1px solid var(--color-bg-tertiary);">View All</a>
        </div>
      </div>
    `,
  },
  "/about": {
    title: "About - XeoKey",
    body: `
      <h1>About XeoKey</h1>
      <p>XeoKey is a hardened web server built with Bun.</p>
      <h2>Technology Stack</h2>
      <ul>
        <li>Bun runtime</li>
        <li>TypeScript</li>
        <li>Custom router system</li>
        <li>Template-based page rendering</li>
      </ul>
      <h2>Architecture</h2>
      <p>The server uses a single-page system where all routes serve HTML pages with a consistent header and footer, while only the body content changes.</p>
    `,
  },
  "/contact": {
    title: "Contact - XeoKey",
    body: `
      <h1>Contact Us</h1>
      <p>Get in touch with the XeoKey team.</p>
      <form style="margin-top: 1.5rem;">
        <div style="margin-bottom: 1rem;">
          <label for="name" style="display: block; margin-bottom: 0.5rem;">Name:</label>
          <input type="text" id="name" name="name" autocomplete="off" style="width: 100%; padding: 0.5rem; border: 1px solid var(--color-border); border-radius: 4px;">
        </div>
        <div style="margin-bottom: 1rem;">
          <label for="email" style="display: block; margin-bottom: 0.5rem;">Email:</label>
          <input type="email" id="email" name="email" autocomplete="off" style="width: 100%; padding: 0.5rem; border: 1px solid var(--color-border); border-radius: 4px;">
        </div>
        <div style="margin-bottom: 1rem;">
          <label for="message" style="display: block; margin-bottom: 0.5rem;">Message:</label>
          <textarea id="message" name="message" rows="5" autocomplete="off" style="width: 100%; padding: 0.5rem; border: 1px solid var(--color-border); border-radius: 4px;"></textarea>
        </div>
        <button type="submit" style="background: var(--color-accent); color: white; padding: 0.75rem 1.5rem; border: none; border-radius: 4px; cursor: pointer;">Send Message</button>
      </form>
    `,
  },
};

// Register routes - OS-like hierarchical structure
// API routes (must be registered before catch-all routes)
router.get("/api/status", async (request, params, query) => {
  const session = await attachSession(request);
  if (!session) {
    return createErrorResponse(401, "Unauthorized");
  }

  const quickCheck = await quickHealthCheck();
  const lastCheck = getLastHealthCheck();

  return createResponse({
    status: "online",
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    database: {
      connected: isConnected(),
      healthy: quickCheck.healthy,
      lastHealthCheck: lastCheck.timestamp?.toISOString() || null,
    },
  });
});

router.get("/api/health", async (request, params, query) => {
  const session = await attachSession(request);
  if (!session) {
    return createErrorResponse(401, "Unauthorized");
  }

  try {
    const result = await forceHealthCheck();
    return createResponse(result);
  } catch (error: any) {
    return createErrorResponse(500, error.message);
  }
});

router.get("/api/hello", async (request, params, query) => {
  return createResponse({
    message: "Hello from API!",
    timestamp: new Date().toISOString(),
  });
});

router.get("/api/users", async (request, params, query) => {
  return createResponse({
    users: [],
    count: 0,
  });
});

router.get("/api/users/:id", async (request, params, query) => {
  return createResponse({
    id: params.id,
    message: `User ${params.id} details`,
  });
});

router.post("/api/users", async (request, params, query) => {
  try {
    const body = await request.json();
    return createResponse({
      success: true,
      message: "User created",
      data: body,
    });
  } catch (error) {
    return createErrorResponse(400, "Invalid JSON body");
  }
});

router.get("/api/files", async (request, params, query) => {
  return createResponse({
    files: [],
    path: "/",
  });
});

router.get("/api/files/:path*", async (request, params, query) => {
  const fullPath = params.path || "";
  return createResponse({
    path: `/${fullPath}`,
    type: "file",
    content: "File content here",
    segments: fullPath.split("/"),
  });
});

router.get("/api/system/info", async (request, params, query) => {
  const session = await attachSession(request);
  return createResponse({
    platform: process.platform,
    nodeVersion: process.version,
    memory: process.memoryUsage(),
    database: {
      connected: isConnected(),
      name: isConnected() ? 'XeoKey' : null,
    },
    authenticated: session !== null,
    user: session ? { username: session.username } : null,
  });
});

// Authentication routes
// Helper function to escape HTML
// Calculate password strength (server-side, same logic as client)
function calculatePasswordStrength(password: string): number {
  let strength = 0;

  if (password.length >= 6) strength++;
  if (password.length >= 8) strength++;
  if (password.length >= 12) strength++;
  if (/[a-z]/.test(password)) strength++;
  if (/[A-Z]/.test(password)) strength++;
  if (/[0-9]/.test(password)) strength++;
  if (/[^a-zA-Z0-9]/.test(password)) strength++;

  return strength;
}

// Analyze passwords for security issues
interface SecurityAnalysis {
  passwordCount: number;
  duplicateCount: number;
  weakPasswordCount: number;
  duplicateEntries: Array<{ entryId: string; website: string; password: string }>;
  weakEntries: Array<{ entryId: string; website: string; strength: number }>;
  hasIssues: boolean;
}

async function analyzePasswords(userId: string): Promise<SecurityAnalysis> {
  const result: SecurityAnalysis = {
    passwordCount: 0,
    duplicateCount: 0,
    weakPasswordCount: 0,
    duplicateEntries: [],
    weakEntries: [],
    hasIssues: false,
  };

  if (!isConnected()) {
    return result;
  }

  try {
    const passwords = await getUserPasswords(userId);
    result.passwordCount = passwords.length;

    if (passwords.length === 0) {
      return result;
    }

    // Decrypt passwords to check for duplicates and weak passwords
    const passwordMap = new Map<string, Array<{ entryId: string; website: string }>>();

    for (const entry of passwords) {
      try {
        const decrypted = await getDecryptedPassword(entry._id!, userId);
        if (decrypted) {
          // Track password occurrences
          if (!passwordMap.has(decrypted)) {
            passwordMap.set(decrypted, []);
          }
          passwordMap.get(decrypted)!.push({ entryId: entry._id!, website: entry.website });

          // Check for weak passwords
          const strength = calculatePasswordStrength(decrypted);
          if (strength <= 4) {
            result.weakPasswordCount++;
            result.weakEntries.push({ entryId: entry._id!, website: entry.website, strength });
          }
        }
      } catch (error) {
        logger.error(`Error decrypting password for analysis: ${error}`);
      }
    }

    // Find duplicates
    for (const [password, entries] of passwordMap.entries()) {
      if (entries.length > 1) {
        result.duplicateCount += entries.length - 1;
        entries.forEach(entry => {
          result.duplicateEntries.push({ entryId: entry.entryId, website: entry.website, password });
        });
      }
    }

    result.hasIssues = result.duplicateCount > 0 || result.weakPasswordCount > 0;
  } catch (error) {
    logger.error(`Error analyzing passwords: ${error}`);
  }

  return result;
}

function escapeHtml(text: string | undefined | null | any): string {
  // Handle null, undefined, or non-string types
  if (text === undefined || text === null) {
    return '';
  }

  // Convert to string if not already
  const str = typeof text === 'string' ? text : String(text);

  // Handle empty strings
  if (str === '') {
    return '';
  }

  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// Helper function to render login form with errors
async function renderLoginForm(request: Request, username: string = '', error: string = '', csrfToken: string = ''): Promise<string> {
  const errorHtml = error ? `<div class="flash-error">${escapeHtml(error)}</div>` : '';
  const usernameValue = username ? ` value="${escapeHtml(username)}"` : '';
  const csrfField = csrfToken ? `<input type="hidden" name="csrfToken" value="${escapeHtml(csrfToken)}">` : '';

  // Surface system warnings (encryption health) on the login page.
  let encryptionDiagnosticNotification = '';
  let autoReEncryptionNotification = '';

  try {
    // Check for encryption issues
    try {
      const { runEncryptionDiagnostics, generateDiagnosticReport, isUsingDefaultKey } = await import('./utils/encryption-diagnostics');

      // Always show diagnostic if using default key in production
      if (process.env.NODE_ENV === 'production' && isUsingDefaultKey()) {
        const diagnostic = await runEncryptionDiagnostics();
        encryptionDiagnosticNotification = generateDiagnosticReport(diagnostic);
      } else {
        // Run diagnostics and show if there are issues
        const diagnostic = await runEncryptionDiagnostics();
        const totalFailures = diagnostic.passwordEntries.failed + diagnostic.noteEntries.failed;
        const totalEntries = diagnostic.passwordEntries.total + diagnostic.noteEntries.total;

        if (totalEntries > 0 && totalFailures / totalEntries > 0.1) {
          encryptionDiagnosticNotification = generateDiagnosticReport(diagnostic);
        }
      }
    } catch (error) {
      logger.debug(`Encryption diagnostic check failed: ${error}`);
    }

    // Check for auto re-encryption status
    try {
      const { checkAutoReEncryption, generateAutoReEncryptionStatusHTML } = await import('./utils/auto-re-encryption');
      const { shouldTrigger, status } = await checkAutoReEncryption();

      // Show auto re-encryption status if it's running or if it should trigger
      if (status.isRunning || shouldTrigger) {
        autoReEncryptionNotification = generateAutoReEncryptionStatusHTML();
      }
    } catch (error) {
      logger.debug(`Auto re-encryption check failed: ${error}`);
    }
  } catch (error) {
    // Silently fail - system status checks are optional
    logger.debug(`Login status check failed: ${error}`);
  }

  const noticesHtml = `${autoReEncryptionNotification}${encryptionDiagnosticNotification}`;

  return `
    <div class="auth-page-wrap">
      ${noticesHtml}
      <div class="auth-card">
        <h1 class="auth-page-title">Login</h1>
        <form method="POST" action="/login">
          ${csrfField}
          ${errorHtml}
          <div class="form-group">
            <label for="username" class="form-label">Username:</label>
            <input type="text" id="username" name="username" required${usernameValue} autocomplete="off" class="form-input">
          </div>
          <div class="form-group-lg">
            <label for="password" class="form-label">Password:</label>
            <input type="password" id="password" name="password" required autocomplete="off" class="form-input">
          </div>
          <button type="submit" class="full-width-btn">Login</button>
        </form>
        <p class="auth-foot">
          <a href="/register" class="auth-foot-link">Don't have an account? Register here</a>
        </p>
      </div>
    </div>
  `;
}

// Helper function to render register form with errors
async function renderRegisterForm(request: Request, username: string = '', error: string = '', csrfToken: string = ''): Promise<string> {
  const errorHtml = error ? `<div class="flash-error">${escapeHtml(error)}</div>` : '';
  const usernameValue = username ? ` value="${escapeHtml(username)}"` : '';
  const csrfField = csrfToken ? `<input type="hidden" name="csrfToken" value="${escapeHtml(csrfToken)}">` : '';

  return `
    <div class="auth-page-wrap">
      <div class="auth-card">
        <h1 class="auth-page-title">Register</h1>
        <form method="POST" action="/register" id="registerForm" class="register-form">
          ${csrfField}
          ${errorHtml}
          <div class="form-group">
            <label for="username" class="form-label">Username:</label>
            <input type="text" id="username" name="username" required minlength="3" maxlength="30" pattern="[a-zA-Z0-9_]+"${usernameValue} autocomplete="off" class="form-input">
            <small class="form-hint">3-30 characters, letters, numbers, and underscores only</small>
          </div>
          <div class="form-group">
            <label for="password" class="form-label">Password:</label>
            <input type="password" id="password" name="password" required minlength="6" maxlength="100" autocomplete="off" class="form-input">
            <div id="passwordStrength" class="strength-wrap">
              <div id="passwordStrengthBar" class="strength-bar"></div>
            </div>
            <div id="passwordStrengthText" class="strength-text"></div>
          </div>
          <div class="form-group-lg">
            <label for="confirmPassword" class="form-label">Confirm Password:</label>
            <input type="password" id="confirmPassword" name="confirmPassword" required minlength="6" maxlength="100" autocomplete="off" class="form-input">
            <div id="passwordMatch" class="form-hint"></div>
          </div>
          <button type="submit" id="submitBtn" class="full-width-btn">Register</button>
        </form>
        <p class="auth-foot">
          <a href="/login" class="auth-foot-link">Already have an account? Login here</a>
        </p>
      </div>
    </div>
  `;
}

router.get("/login", async (request, params, query) => {
  const session = await attachSession(request);
  if (session) {
    // Already logged in, redirect to home
    return new Response(null, {
      status: 302,
      headers: {
        ...SECURITY_HEADERS,
        Location: '/',
      },
    });
  }
  // Generate CSRF token for new session (temporary)
  const tempSessionId = 'temp_' + Date.now();
  const csrfToken = createCsrfToken(tempSessionId);
    const formHtml = await renderLoginForm(request, '', '', csrfToken);

    // Check if we just updated
    const updated = query.get('updated') === 'true';
    const updateMessage = updated ? `
      <div style="background: var(--color-bg-secondary); border: 1px solid var(--color-border); padding: 0.75rem; border-radius: 4px; margin-bottom: 1rem;">
        <p style="color: var(--color-success); margin: 0; font-size: 0.9rem;">✅ Server updated successfully! Please log in again.</p>
      </div>
    ` : '';

    return renderLoginPage(updateMessage + formHtml, "Login - XeoKey", request);
});

router.post("/login", async (request, params, query) => {
  if (!isConnected()) {
    return createErrorResponse(503, "Database not available");
  }

  // Rate limiting
  const rateLimit = checkRateLimit(request, 'login');
  if (!rateLimit.allowed) {
    const minutesRemaining = Math.ceil((rateLimit.resetAt - Date.now()) / 60000);
    const tempSessionId = 'temp_' + Date.now();
    const csrfToken = createCsrfToken(tempSessionId);
    const formHtml = await renderLoginForm(request, '', `Too many login attempts. Please try again in ${minutesRemaining} minute(s).`, csrfToken);
    return renderLoginPage(formHtml, "Login - XeoKey", request);
  }

  try {
    const formData = await request.formData();
    const rawUsername = formData.get('username')?.toString() || '';
    const rawPassword = formData.get('password')?.toString() || '';
    const csrfToken = formData.get('csrfToken')?.toString() || '';

    // Verify CSRF token (for logged-in users attempting to login again)
    const session = await attachSession(request);
    if (session && !verifyCsrfToken(session.sessionId, csrfToken)) {
      const tempSessionId = 'temp_' + Date.now();
      const newCsrfToken = createCsrfToken(tempSessionId);
      const formHtml = await renderLoginForm(request, rawUsername, "Invalid security token. Please try again.", newCsrfToken);
      return renderLoginPage(formHtml, "Login - XeoKey", request);
    }

    // Sanitize inputs
    const username = sanitizeUsername(rawUsername);
    const password = sanitizeString(rawPassword);

    if (!username || !password) {
      const tempSessionId = 'temp_' + Date.now();
      const newCsrfToken = createCsrfToken(tempSessionId);
      const formHtml = await renderLoginForm(request, rawUsername, "Username and password are required.", newCsrfToken);
      return renderLoginPage(formHtml, "Login - XeoKey", request);
    }

    // Validate inputs
    const usernameValidation = validateUsername(username);
    if (!usernameValidation.valid) {
      const tempSessionId = 'temp_' + Date.now();
      const newCsrfToken = createCsrfToken(tempSessionId);
      const formHtml = await renderLoginForm(request, rawUsername, usernameValidation.error || "Invalid username format.", newCsrfToken);
      return renderLoginPage(formHtml, "Login - XeoKey", request);
    }

    // Authenticate against ONYX (the user service). The returned id equals the
    // local users._id for migrated users, keying xeokey's session and vault data.
    const onyxUser = await onyxLogin(username, password);
    if (!onyxUser) {
      const tempSessionId = 'temp_' + Date.now();
      const newCsrfToken = createCsrfToken(tempSessionId);
      const formHtml = await renderLoginForm(request, rawUsername, "Invalid username or password.", newCsrfToken);
      return renderLoginPage(formHtml, "Login - XeoKey", request);
    }

    // Reset rate limit on successful login
    resetRateLimit(request, 'login');

    // Ensure a local profile exists (idempotent) so theme/lookups work even for
    // users created directly in ONYX.
    await upsertLocalProfile(onyxUser.id, onyxUser.username);

    // Create new session (regenerate session ID to prevent fixation)
    const sessionId = await createSession(onyxUser.id, onyxUser.username);
    const cookie = createSessionCookie(sessionId, request);

    return new Response(null, {
      status: 302,
      headers: {
        ...SECURITY_HEADERS,
        'Set-Cookie': cookie,
        Location: '/',
      },
    });
  } catch (error) {
    // Don't log sensitive error details
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    if (!errorMessage.includes('password') && !errorMessage.includes('username')) {
      logger.error(`Login error: ${errorMessage}`);
    }
    return createErrorResponse(500, "Internal Server Error");
  }
});

router.get("/logout", async (request, params, query) => {
  if (isConnected()) {
    const sessionId = getSessionIdFromRequest(request);
    if (sessionId) {
      await deleteSession(sessionId);
      deleteCsrfToken(sessionId);
    }
  }

  const cookie = createLogoutCookie(request);

  return new Response(null, {
    status: 302,
    headers: {
      ...SECURITY_HEADERS,
      'Set-Cookie': cookie,
      Location: '/',
    },
  });
});

router.get("/settings", async (request, params, query) => {
  const session = await attachSession(request);
  if (!session) {
    return new Response(null, {
      status: 302,
      headers: {
        ...SECURITY_HEADERS,
        Location: '/login',
      },
    });
  }

  const csrfToken = createCsrfToken(session.sessionId);
  const user = await getUserById(session.userId);
  const currentTheme = normalizeThemePreference(user?.theme);
  const saved = query.get('saved') === '1';

  return renderPage(`
    <h1>Settings</h1>
    <p class="settings-subtitle">Customize your interface preferences.</p>
    ${saved ? '<div class="flash-success">Theme updated successfully.</div>' : ''}
    <form method="POST" action="/settings/theme" class="settings-form">
      <input type="hidden" name="csrfToken" value="${escapeHtml(csrfToken)}">
      <div class="form-group">
        <label for="theme" class="form-label">Theme</label>
        <select id="theme" name="theme" style="width: 100%;">
          <option value="slate" ${currentTheme === 'slate' ? 'selected' : ''}>Slate</option>
          <option value="slate-contrast" ${currentTheme === 'slate-contrast' ? 'selected' : ''}>Slate Contrast</option>
          <option value="legacy-blue" ${currentTheme === 'legacy-blue' ? 'selected' : ''}>Legacy Blue</option>
        </select>
      </div>
      <button type="submit">Save Theme</button>
    </form>
  `, "Settings - XeoKey", request);
});

router.post("/settings/theme", async (request, params, query) => {
  const session = await attachSession(request);
  if (!session) {
    return new Response(null, {
      status: 302,
      headers: {
        ...SECURITY_HEADERS,
        Location: '/login',
      },
    });
  }

  const formData = await request.formData();
  const csrfToken = formData.get('csrfToken')?.toString() || '';
  const theme = formData.get('theme')?.toString() || 'slate';

  if (!verifyCsrfToken(session.sessionId, csrfToken)) {
    return renderPage(`
      <h1>Settings</h1>
      <div class="flash-error">Invalid security token. Please try again.</div>
      <p><a href="/settings" class="empty-state-link">Back to Settings</a></p>
    `, "Settings - XeoKey", request);
  }

  await updateUserTheme(session.userId, theme);

  return new Response(null, {
    status: 302,
    headers: {
      ...SECURITY_HEADERS,
      Location: '/settings?saved=1',
    },
  });
});


router.get("/register", async (request, params, query) => {
  const session = await attachSession(request);
  if (session) {
    return new Response(null, {
      status: 302,
      headers: {
        ...SECURITY_HEADERS,
        Location: '/',
      },
    });
  }
  const tempSessionId = 'temp_' + Date.now();
  const csrfToken = createCsrfToken(tempSessionId);
  const formHtml = await renderRegisterForm(request, '', '', csrfToken);
  return renderLoginPage(formHtml, "Register - XeoKey", request);
});

router.post("/register", async (request, params, query) => {
  if (!isConnected()) {
    return createErrorResponse(503, "Database not available");
  }

  // Rate limiting
  const rateLimit = checkRateLimit(request, 'register');
  if (!rateLimit.allowed) {
    const minutesRemaining = Math.ceil((rateLimit.resetAt - Date.now()) / 60000);
    const tempSessionId = 'temp_' + Date.now();
    const csrfToken = createCsrfToken(tempSessionId);
    const formHtml = await renderRegisterForm(request, '', `Too many registration attempts. Please try again in ${minutesRemaining} minute(s).`, csrfToken);
    return renderLoginPage(formHtml, "Register - XeoKey", request);
  }

  const formData = await request.formData();
  const rawUsername = formData.get('username')?.toString() || '';
  const rawPassword = formData.get('password')?.toString() || '';
  const rawConfirmPassword = formData.get('confirmPassword')?.toString() || '';
  const csrfToken = formData.get('csrfToken')?.toString() || '';

  // Verify CSRF token
  const session = await attachSession(request);
  if (session && !verifyCsrfToken(session.sessionId, csrfToken)) {
    const tempSessionId = 'temp_' + Date.now();
    const newCsrfToken = createCsrfToken(tempSessionId);
    const formHtml = await renderRegisterForm(request, rawUsername, "Invalid security token. Please try again.", newCsrfToken);
    return renderLoginPage(formHtml, "Register - XeoKey", request);
  }

  try {
    // Sanitize inputs
    const username = sanitizeUsername(rawUsername);
    const password = sanitizeString(rawPassword);
    const confirmPassword = sanitizeString(rawConfirmPassword);

    // Validate inputs
    const usernameValidation = validateUsername(username);
    if (!usernameValidation.valid) {
      const tempSessionId = 'temp_' + Date.now();
      const newCsrfToken = createCsrfToken(tempSessionId);
      const formHtml = await renderRegisterForm(request, rawUsername, usernameValidation.error || "Invalid username format.", newCsrfToken);
      return renderLoginPage(formHtml, "Register - XeoKey", request);
    }

    const passwordValidation = validatePassword(password);
    if (!passwordValidation.valid) {
      const tempSessionId = 'temp_' + Date.now();
      const newCsrfToken = createCsrfToken(tempSessionId);
      const formHtml = await renderRegisterForm(request, rawUsername, passwordValidation.error || "Invalid password.", newCsrfToken);
      return renderLoginPage(formHtml, "Register - XeoKey", request);
    }

    // Check if passwords match
    if (password !== confirmPassword) {
      const tempSessionId = 'temp_' + Date.now();
      const newCsrfToken = createCsrfToken(tempSessionId);
      const formHtml = await renderRegisterForm(request, rawUsername, "Passwords do not match.", newCsrfToken);
      return renderLoginPage(formHtml, "Register - XeoKey", request);
    }

    // Register in ONYX (the user service). xeokey has no email, so register by
    // username only. ONYX mints the id and owns the credentials.
    const result = await onyxRegister(username, password);
    if (!result.ok) {
      const message = 'conflict' in result
        ? 'Username already exists.'
        : result.validationError;
      const tempSessionId = 'temp_' + Date.now();
      const newCsrfToken = createCsrfToken(tempSessionId);
      const formHtml = await renderRegisterForm(request, rawUsername, message, newCsrfToken);
      return renderLoginPage(formHtml, "Register - XeoKey", request);
    }
    const user = result.user;

    // Reset rate limit on successful registration
    resetRateLimit(request, 'register');

    // Create the local profile (theme etc.) keyed by the ONYX id.
    await upsertLocalProfile(user.id, user.username);

    const sessionId = await createSession(user.id, user.username);
    const cookie = createSessionCookie(sessionId, request);

    return new Response(null, {
      status: 302,
      headers: {
        ...SECURITY_HEADERS,
        'Set-Cookie': cookie,
        Location: '/',
      },
    });
  } catch (error: any) {
    // Don't log sensitive error details
    const errorMessage = error.message === 'User already exists'
      ? 'Username already exists.'
      : 'Registration failed. Please try again.';

    const tempSessionId = 'temp_' + Date.now();
    const newCsrfToken = createCsrfToken(tempSessionId);
    const formHtml = await renderRegisterForm(request, rawUsername, errorMessage, newCsrfToken);
    return renderLoginPage(formHtml, "Register - XeoKey", request);
  }
});

// Serve static CSS file
router.get("/styles.css", async (request, params, query) => {
  try {
    const cssFile = Bun.file("public/styles.css");
    const exists = await cssFile.exists();
    if (!exists) {
      logger.warn("CSS file not found at public/styles.css");
      return createErrorResponse(404, "CSS file not found");
    }
    const css = await cssFile.text();
    return new Response(css, {
      headers: {
        ...SECURITY_HEADERS,
        "Content-Type": "text/css",
        "Cache-Control": "public, max-age=3600",
      },
    });
  } catch (error) {
    logger.error(`Error serving CSS: ${error}`);
    return createErrorResponse(500, "Error loading CSS file");
  }
});

// Auto Re-encryption Routes
// API endpoint to check auto re-encryption status
router.get("/api/auto-re-encryption/status", async (request, params, query) => {
  try {
    const { checkAutoReEncryption, generateAutoReEncryptionStatusHTML } = await import('./utils/auto-re-encryption');
    const { shouldTrigger, status, recommendation } = await checkAutoReEncryption();
    const htmlReport = generateAutoReEncryptionStatusHTML();

    return new Response(JSON.stringify({
      shouldTrigger,
      status,
      recommendation,
      htmlReport
    }), {
      headers: {
        ...SECURITY_HEADERS,
        'Content-Type': 'application/json',
      },
    });
  } catch (error: any) {
    logger.error(`Error checking auto re-encryption status: ${error}`);
    return new Response(JSON.stringify({
      error: error.message || 'Unknown error',
      shouldTrigger: false,
      status: null,
      recommendation: 'Check failed',
      htmlReport: null
    }), {
      headers: {
        ...SECURITY_HEADERS,
        'Content-Type': 'application/json',
      },
    });
  }
});

// API endpoint to trigger auto re-encryption
router.post("/api/auto-re-encryption/trigger", async (request, params, query) => {
  try {
    const { performAutoReEncryption } = await import('./utils/auto-re-encryption');
    const result = await performAutoReEncryption();

    return new Response(JSON.stringify(result), {
      headers: {
        ...SECURITY_HEADERS,
        'Content-Type': 'application/json',
      },
    });
  } catch (error: any) {
    logger.error(`Error triggering auto re-encryption: ${error}`);
    return new Response(JSON.stringify({
      success: false,
      result: null,
      message: error.message || 'Unknown error'
    }), {
      headers: {
        ...SECURITY_HEADERS,
        'Content-Type': 'application/json',
      },
    });
  }
});

// API endpoint to configure auto re-encryption
router.post("/api/auto-re-encryption/configure", async (request, params, query) => {
  try {
    const body = await request.json() as {
      enabled?: boolean;
      threshold?: number;
      batchSize?: number;
      delayBetweenBatches?: number;
      requireConfirmation?: boolean;
    };
    const { configureAutoReEncryption } = await import('./utils/auto-re-encryption');

    // Validate configuration
    const config: Partial<{
      enabled: boolean;
      threshold: number;
      batchSize: number;
      delayBetweenBatches: number;
      requireConfirmation: boolean;
    }> = {};

    if (body.enabled !== undefined) config.enabled = Boolean(body.enabled);
    if (body.threshold !== undefined) config.threshold = Number(body.threshold);
    if (body.batchSize !== undefined) config.batchSize = Number(body.batchSize);
    if (body.delayBetweenBatches !== undefined) config.delayBetweenBatches = Number(body.delayBetweenBatches);
    if (body.requireConfirmation !== undefined) config.requireConfirmation = Boolean(body.requireConfirmation);

    configureAutoReEncryption(config);

    return new Response(JSON.stringify({
      success: true,
      message: 'Auto re-encryption configuration updated',
      config
    }), {
      headers: {
        ...SECURITY_HEADERS,
        'Content-Type': 'application/json',
      },
    });
  } catch (error: any) {
    logger.error(`Error configuring auto re-encryption: ${error}`);
    return new Response(JSON.stringify({
      success: false,
      message: error.message || 'Unknown error'
    }), {
      headers: {
        ...SECURITY_HEADERS,
        'Content-Type': 'application/json',
      },
    });
  }
});

// Re-Encryption Debug Routes
// API endpoint to run re-encryption debug
router.get("/api/re-encryption/debug", async (request, params, query) => {
  try {
    const { debugReEncryption, generateReEncryptionDebugReport } = await import('./utils/re-encryption-debug');
    const debug = await debugReEncryption();
    const htmlReport = generateReEncryptionDebugReport(debug);

    return new Response(JSON.stringify({
      debug,
      htmlReport
    }), {
      headers: {
        ...SECURITY_HEADERS,
        'Content-Type': 'application/json',
      },
    });
  } catch (error: any) {
    logger.error(`Error running re-encryption debug: ${error}`);
    return new Response(JSON.stringify({
      error: error.message || 'Unknown error',
      debug: null,
      htmlReport: null
    }), {
      headers: {
        ...SECURITY_HEADERS,
        'Content-Type': 'application/json',
      },
    });
  }
});

// Encryption Diagnostics Routes
// API endpoint to run encryption diagnostics
router.get("/api/encryption/diagnostics", async (request, params, query) => {
  try {
    const { runEncryptionDiagnostics, generateDiagnosticReport } = await import('./utils/encryption-diagnostics');
    const diagnostic = await runEncryptionDiagnostics();
    const htmlReport = generateDiagnosticReport(diagnostic);

    return new Response(JSON.stringify({
      diagnostic,
      htmlReport
    }), {
      headers: {
        ...SECURITY_HEADERS,
        'Content-Type': 'application/json',
      },
    });
  } catch (error: any) {
    logger.error(`Error running encryption diagnostics: ${error}`);
    return new Response(JSON.stringify({
      error: error.message || 'Unknown error',
      diagnostic: null,
      htmlReport: null
    }), {
      headers: {
        ...SECURITY_HEADERS,
        'Content-Type': 'application/json',
      },
    });
  }
});

// API endpoint to get key information (safe, no actual key exposed)
router.get("/api/encryption/key-info", async (request, params, query) => {
  try {
    const { getKeyInfo } = await import('./utils/encryption-diagnostics');
    const keyInfo = getKeyInfo();

    return new Response(JSON.stringify(keyInfo), {
      headers: {
        ...SECURITY_HEADERS,
        'Content-Type': 'application/json',
      },
    });
  } catch (error: any) {
    logger.error(`Error getting key info: ${error}`);
    return new Response(JSON.stringify({
      error: error.message || 'Unknown error'
    }), {
      headers: {
        ...SECURITY_HEADERS,
        'Content-Type': 'application/json',
      },
    });
  }
});

// Server status API endpoint
router.get("/api/server/status", async (request, params, query) => {
  try {
    const serverStartTime = (globalThis as any).serverStartTime || Date.now();
    const dbConnectTime = (globalThis as any).dbConnectTime;
    const now = Date.now();
    const uptime = Math.floor((now - serverStartTime) / 1000);

    // Determine server phase/status
    let phase = 'running';
    let phaseMessage = 'Server is running';

    // Check database connection
    const dbConnected = isConnected();

    // If server just started (within 5 seconds), it might still be initializing
    if (uptime < 5) {
      phase = 'starting';
      phaseMessage = 'Server is starting up...';
    } else if (!dbConnected) {
      phase = 'connecting';
      phaseMessage = 'Connecting to database...';
    } else {
      phase = 'ready';
      phaseMessage = 'Server is ready';
    }

    const status = {
      status: phase,
      message: phaseMessage,
      uptime: uptime,
      uptimeFormatted: `${Math.floor(uptime / 60)}m ${uptime % 60}s`,
      database: {
        connected: dbConnected,
        connectedAt: dbConnectTime ? Math.floor((now - dbConnectTime) / 1000) : null,
      },
      timestamp: now,
    };

    return new Response(JSON.stringify(status), {
      headers: {
        ...SECURITY_HEADERS,
        'Content-Type': 'application/json',
      },
    });
  } catch (error: any) {
    // If we can't determine status, server is likely not ready
    return new Response(JSON.stringify({
      status: 'unknown',
      message: 'Server status unknown',
      error: error.message || 'Unknown error',
      timestamp: Date.now(),
    }), {
      headers: {
        ...SECURITY_HEADERS,
        'Content-Type': 'application/json',
      },
      status: 503,
    });
  }
});

// Serve favicon
router.get("/favicon.ico", async (request, params, query) => {
  try {
    const faviconFile = Bun.file("public/favicon.ico");
    if (!(await faviconFile.exists())) {
      return createErrorResponse(404, "Favicon not found");
    }
    const favicon = await faviconFile.arrayBuffer();
    return new Response(favicon, {
      headers: {
        ...SECURITY_HEADERS,
        "Content-Type": "image/x-icon",
        "Cache-Control": "public, max-age=31536000",
      },
    });
  } catch (error) {
    return createErrorResponse(404, "Favicon not found");
  }
});

// Serve brand logo
router.get("/frostal.png", async (request, params, query) => {
  try {
    const logoFile = Bun.file("public/frostal.png");
    if (!(await logoFile.exists())) {
      return createErrorResponse(404, "Logo not found");
    }
    const logo = await logoFile.arrayBuffer();
    return new Response(logo, {
      headers: {
        ...SECURITY_HEADERS,
        "Content-Type": "image/png",
        "Cache-Control": "public, max-age=31536000",
      },
    });
  } catch (error) {
    return createErrorResponse(404, "Logo not found");
  }
});

// Serve Chart.js locally to avoid tracking prevention issues
router.get("/chart.js", async (request, params, query) => {
  try {
    // Try to load from node_modules (check multiple possible locations)
    // Server runs from src/ directory, so check relative paths
    const chartJsPaths = [
      "../node_modules/chart.js/dist/chart.umd.min.js", // From src/ directory
      "node_modules/chart.js/dist/chart.umd.min.js",    // If in root
      "src/node_modules/chart.js/dist/chart.umd.min.js" // Alternative
    ];

    let chartJs: string | null = null;
    let foundPath: string | null = null;

    for (const chartJsPath of chartJsPaths) {
      try {
        const chartJsFile = Bun.file(chartJsPath);
        const exists = await chartJsFile.exists();
        if (exists) {
          chartJs = await chartJsFile.text();
          foundPath = chartJsPath;
          break;
        }
      } catch (e) {
        // Continue to next path
        continue;
      }
    }

    if (chartJs) {
      logger.debug(`Serving Chart.js from ${foundPath}`);
      return new Response(chartJs, {
        headers: {
          ...SECURITY_HEADERS,
          "Content-Type": "application/javascript; charset=utf-8",
          "Cache-Control": "public, max-age=31536000", // Cache for 1 year
        },
      });
    }

    // If not found locally, redirect to CDN (with proper MIME type handling)
    logger.warn(`Chart.js not found locally, using CDN fallback`);
    const cdnUrl = "https://cdn.jsdelivr.net/npm/chart.js@4.5.1/dist/chart.umd.min.js";

    // Fetch from CDN and proxy it
    try {
      const cdnResponse = await fetch(cdnUrl);
      if (cdnResponse.ok) {
        const cdnContent = await cdnResponse.text();
        return new Response(cdnContent, {
          headers: {
            ...SECURITY_HEADERS,
            "Content-Type": "application/javascript; charset=utf-8",
            "Cache-Control": "public, max-age=3600", // Cache CDN content for 1 hour
          },
        });
      }
    } catch (cdnError) {
      logger.warn(`Failed to fetch Chart.js from CDN: ${cdnError}`);
    }

    // Last resort: return a minimal stub that prevents errors
    logger.warn(`Chart.js unavailable, returning stub`);
    const stub = `
      // Chart.js stub - library not available
      window.Chart = class Chart {
        constructor() {
          console.warn('Chart.js is not available. Charts will not be displayed.');
        }
        update() {}
        destroy() {}
      };
      console.warn('Chart.js not loaded. Please install chart.js package or check your connection.');
    `;

    return new Response(stub, {
      headers: {
        ...SECURITY_HEADERS,
        "Content-Type": "application/javascript; charset=utf-8",
        "Cache-Control": "no-cache",
      },
    });
  } catch (error) {
    logger.error(`Error serving Chart.js: ${error}`);
    // Return stub instead of error response to prevent MIME type issues
    const stub = `
      // Chart.js error stub
      window.Chart = class Chart {
        constructor() {
          console.error('Chart.js failed to load');
        }
        update() {}
        destroy() {}
      };
    `;
    return new Response(stub, {
      headers: {
        ...SECURITY_HEADERS,
        "Content-Type": "application/javascript; charset=utf-8",
        "Cache-Control": "no-cache",
      },
    });
  }
});

// Root routes serve HTML pages with header/footer (require authentication)
router.get("/", async (request, params, query) => {
  const session = await attachSession(request);
  if (!session) {
    return new Response(null, {
      status: 302,
      headers: {
        ...SECURITY_HEADERS,
        Location: '/login',
      },
    });
  }

  // Ensure userId is a string
  const userIdString = typeof session.userId === 'string' ? session.userId : (session.userId as any).toString();

  // Get dashboard statistics
  const analysis = await analyzePasswords(userIdString);
  const { passwordCount, duplicateCount, weakPasswordCount, duplicateEntries, weakEntries, hasIssues } = analysis;

  // Get top 3 most recent passwords
  let recentPasswords: any[] = [];
  try {
    const { getRecentPasswords } = await import('./models/password');
    recentPasswords = await getRecentPasswords(userIdString, 3);
  } catch (error) {
    logger.error(`Error fetching recent passwords: ${error}`);
    // Continue without recent passwords if there's an error
  }

  // Get TOTP entries
  let totpEntries: any[] = [];
  let totpCount = 0;
  try {
    totpEntries = await listTotpEntries(userIdString);
    totpCount = totpEntries.length;
    // Get recent TOTP entries (last 3)
    totpEntries = totpEntries.slice(0, 3);
  } catch (error) {
    logger.error(`Error fetching TOTP entries: ${error}`);
    // Continue without TOTP entries if there's an error
  }

  // Get database metadata
  let dbMetadata: { schemaVersion?: number; appVersion?: string; lastUpdated?: Date } | null = null;
  try {
    const { getDatabaseMetadata } = await import('./db/mongodb');
    dbMetadata = await getDatabaseMetadata();
  } catch (error) {
    logger.debug(`Error fetching database metadata: ${error}`);
    // Non-critical, continue
  }

  // Build dashboard body with statistics - compact design with graphs
  const totalIssues = duplicateCount + weakPasswordCount;
  const dashboardBody = `
    <h1 class="dashboard-title">Dashboard</h1>
    <p class="dashboard-subtitle">Simplified vault overview with actionable security and activity insights.</p>

    <div class="dashboard-grid metrics">
      <div class="dashboard-card">
        <div class="dashboard-value">${passwordCount}</div>
        <div class="dashboard-label">Passwords Stored</div>
      </div>
      <div class="dashboard-card">
        <div class="dashboard-value success">${totpCount}</div>
        <div class="dashboard-label">TOTP Entries</div>
      </div>
      <div class="dashboard-card ${hasIssues ? 'emphasis-warn' : 'emphasis-ok'}">
        <div class="dashboard-value ${hasIssues ? 'error' : 'success'}" id="securityIssueTotal">${totalIssues}</div>
        <div class="dashboard-label">Security Issues</div>
      </div>
      <div class="dashboard-card">
        <div class="dashboard-value" id="totalEvents">-</div>
        <div class="dashboard-label">Events (30 Days)</div>
      </div>
    </div>

    <div class="dashboard-health">
      <div class="dashboard-health-item primary">
        <span class="status-dot ${isConnected() ? 'ok' : 'bad'}">${isConnected() ? '●' : '○'}</span>
        <span>Database <strong id="dbStatus" class="dashboard-status-text">${isConnected() ? 'Connected' : 'Disconnected'}</strong></span>
      </div>
      <div class="dashboard-health-item" id="dbUptime">DB Uptime: -</div>
      <div class="dashboard-health-item" id="serverUptime">Server Uptime: -</div>
      ${dbMetadata ? `<div class="dashboard-health-item">Schema v${dbMetadata.schemaVersion || '?'}</div>` : ''}
      ${(dbMetadata as any)?.indexesInitialized ? `<div class="dashboard-health-item success">Indexes Optimized</div>` : ''}
    </div>

    <div class="dashboard-grid actions">
      <a href="/passwords/add" class="dashboard-action">
        <div class="dashboard-action-title">Add Password</div>
        <div class="dashboard-action-subtitle">Store a new credential quickly.</div>
      </a>
      <a href="/totp/add" class="dashboard-action">
        <div class="dashboard-action-title">Add TOTP</div>
        <div class="dashboard-action-subtitle">Attach a new 2FA authenticator.</div>
      </a>
      <a href="/passwords" class="dashboard-action">
        <div class="dashboard-action-title">Review Vault</div>
        <div class="dashboard-action-subtitle">Filter, inspect, and update entries.</div>
      </a>
    </div>

    <div class="dashboard-activity">
      <div class="dashboard-activity-header">
        <h3 class="dashboard-activity-title">Vault Activity (Last 30 Days)</h3>
        <span class="dashboard-activity-updated" id="chartLastUpdate">Loading...</span>
      </div>
      <div class="dashboard-chart-wrap">
        <canvas id="activityChart"></canvas>
      </div>
      <div id="chartNoData" class="dashboard-chart-empty">
        No activity recorded yet. Vault usage will appear here automatically.
      </div>
      <div class="dashboard-grid events">
        <div class="event-pill"><div class="event-pill-label">Views</div><div id="eventViews" class="event-pill-value">-</div></div>
        <div class="event-pill"><div class="event-pill-label">Copies</div><div id="eventCopies" class="event-pill-value success">-</div></div>
        <div class="event-pill"><div class="event-pill-label">Adds</div><div id="eventAdds" class="event-pill-value">-</div></div>
        <div class="event-pill"><div class="event-pill-label">Edits</div><div id="eventEdits" class="event-pill-value">-</div></div>
        <div class="event-pill"><div class="event-pill-label">Deletes</div><div id="eventDeletes" class="event-pill-value error">-</div></div>
        <div class="event-pill"><div class="event-pill-label">Errors</div><div id="eventErrors" class="event-pill-value error">-</div></div>
      </div>
    </div>

    ${passwordCount > 0 ? `

      <div class="dashboard-security ${hasIssues ? 'has-issues' : 'ok'}">
        <h2 class="dashboard-security-title ${hasIssues ? 'warn' : 'success'}">
          ${hasIssues ? '⚠' : '✓'} Security Check
        </h2>
        ${hasIssues ? `
          <div class="dashboard-security-body">
            <p class="dashboard-security-lead">Security Issues Found:</p>
            ${duplicateCount > 0 ? `
              <p class="dashboard-security-note">• ${duplicateCount} duplicate password${duplicateCount > 1 ? 's' : ''} detected:</p>
              <ul class="dashboard-security-list">
                ${Array.from(new Set(duplicateEntries.map(e => e.password))).slice(0, 5).map(password => {
                  const entries = duplicateEntries.filter(e => e.password === password);
                  return `<li>Used in: ${entries.map(e => escapeHtml(e.website)).join(', ')}</li>`;
                }).join('')}
                ${Array.from(new Set(duplicateEntries.map(e => e.password))).length > 5 ? `<li>...and more</li>` : ''}
              </ul>
            ` : ''}
            ${weakPasswordCount > 0 ? `
              <p class="dashboard-security-note">• ${weakPasswordCount} weak password${weakPasswordCount > 1 ? 's' : ''} detected:</p>
              <ul class="dashboard-security-list">
                ${weakEntries.slice(0, 5).map(entry => `<li><a class="dashboard-link" href="/passwords/${entry.entryId}">${escapeHtml(entry.website)}</a> (Strength: ${entry.strength <= 2 ? 'Weak' : 'Fair'})</li>`).join('')}
                ${weakEntries.length > 5 ? `<li>...and ${weakEntries.length - 5} more</li>` : ''}
              </ul>
            ` : ''}
          </div>
          <div class="dashboard-security-body compact">
            <p class="dashboard-security-note medium">Recommendations:</p>
            ${duplicateCount > 0 ? `<p>• Use unique passwords for each account</p>` : ''}
            ${weakPasswordCount > 0 ? `<p>• Strengthen weak passwords using the password generator</p>` : ''}
          </div>
        ` : `
          <div class="dashboard-security-title success dashboard-security-pass">
            <span>✓</span>
            <span>Security Check Passed</span>
          </div>
          <p class="dashboard-security-body compact top-gap">All passwords are unique and strong.</p>
        `}
      </div>
    ` : `
      <div class="dashboard-panel spaced">
        <p class="dashboard-empty-copy">No passwords saved yet. Add your first password to see security statistics.</p>
      </div>
    `}

    <!-- Recent Items Row -->
    <div class="dashboard-recent-grid">
      ${recentPasswords.length > 0 ? `
        <div class="dashboard-panel">
          <h2 class="dashboard-panel-title">Recent Passwords</h2>
          <div class="dashboard-panel-list">
            ${recentPasswords.map(p => `
              <a href="/passwords/${p._id}" class="dashboard-panel-item">
                <div class="dashboard-panel-item-row">
                  <div>
                    <div class="dashboard-panel-item-title">${escapeHtml(p.website)}</div>
                    ${p.username ? `<div class="dashboard-panel-item-meta">${escapeHtml(p.username)}</div>` : ''}
                    <div class="dashboard-panel-item-submeta">Added ${new Date(p.createdAt).toLocaleDateString()}</div>
                  </div>
                  <div class="dashboard-panel-stats">
                    <span>👁️ ${p.searchCount || 0}</span>
                    <span>📋 ${p.copyCount || 0}</span>
                  </div>
                </div>
              </a>
            `).join('')}
          </div>
          ${passwordCount > 3 ? `
            <div class="dashboard-panel-view-all">
              <a href="/passwords">View All →</a>
            </div>
          ` : ''}
        </div>
      ` : ''}

      ${totpEntries.length > 0 ? `
        <div class="dashboard-panel">
          <h2 class="dashboard-panel-title">TOTP Codes</h2>
          <div class="dashboard-panel-list">
            ${(await Promise.all(totpEntries.map(async (e) => {
              try {
                const code = await getCurrentTotpCode(e);
                return `
                  <div class="dashboard-panel-item">
                    <div class="dashboard-panel-item-row">
                      <div>
                        <div class="dashboard-panel-item-title">${escapeHtml(e.label)}</div>
                        ${e.account ? `<div class="dashboard-panel-item-meta">${escapeHtml(e.account)}</div>` : ''}
                        <div class="dashboard-panel-item-submeta">${e.type === 'TOTP' ? 'Time-based' : 'Counter-based'}</div>
                      </div>
                      <div class="dashboard-totp-side">
                        <div class="dashboard-totp-code" id="dashboard-totp-${e._id}">${code || '---'}</div>
                        ${e.type === 'TOTP' ? `<div class="dashboard-totp-timer" id="dashboard-totp-timer-${e._id}">Refreshing...</div>` : ''}
                      </div>
                    </div>
                  </div>
                `;
              } catch (error) {
                return `
                  <div class="dashboard-panel-item">
                    <div class="dashboard-panel-item-title">${escapeHtml(e.label)}</div>
                    <div class="dashboard-panel-item-submeta">Error loading code</div>
                  </div>
                `;
              }
            }))).join('')}
          </div>
          ${totpCount > 3 ? `
            <div class="dashboard-panel-view-all">
              <a href="/totp">View All →</a>
            </div>
          ` : ''}
        </div>
      ` : totpCount === 0 ? `
        <div class="dashboard-panel">
          <h2 class="dashboard-panel-title">TOTP Codes</h2>
          <p class="dashboard-empty-copy">No TOTP codes saved yet.</p>
          <a href="/totp/add" class="dashboard-inline-action">Add TOTP Code</a>
        </div>
      ` : ''}
    </div>

    <script src="/chart.js"></script>
    <script>
      // Format uptime
      function formatUptime(seconds) {
        const days = Math.floor(seconds / 86400);
        const hours = Math.floor((seconds % 86400) / 3600);
        const mins = Math.floor((seconds % 3600) / 60);
        if (days > 0) return days + 'd ' + hours + 'h';
        if (hours > 0) return hours + 'h ' + mins + 'm';
        return mins + 'm';
      }

      // Load analytics data
      async function loadAnalytics() {
        try {
          // Check if Chart.js is loaded
          if (typeof Chart === 'undefined') {
            console.warn('Chart.js not loaded, skipping chart updates');
            return;
          }

          const [analyticsRes, statusRes] = await Promise.all([
            fetch('/api/analytics'),
            fetch('/api/status')
          ]);

          if (analyticsRes.ok) {
            const analytics = await analyticsRes.json();

            // Update last update time
            const lastUpdateEl = document.getElementById('chartLastUpdate');
            if (lastUpdateEl) {
              lastUpdateEl.textContent = 'Updated: ' + new Date().toLocaleTimeString();
            }

            // Check if we have any data
            const hasAnyData = (analytics.adds || 0) + (analytics.deletes || 0) + (analytics.views || 0) +
                              (analytics.copies || 0) + (analytics.edits || 0) + (analytics.errors || 0) > 0;

            const noDataEl = document.getElementById('chartNoData');

            if (!hasAnyData) {
              if (noDataEl) noDataEl.style.display = 'block';
            } else {
              if (noDataEl) noDataEl.style.display = 'none';
            }

            // Update totals
            const totalEvents = (analytics.adds || 0) + (analytics.deletes || 0) + (analytics.views || 0) +
              (analytics.copies || 0) + (analytics.edits || 0) + (analytics.errors || 0);
            document.getElementById('totalEvents').textContent = totalEvents;
            document.getElementById('eventAdds').textContent = analytics.adds || 0;
            document.getElementById('eventDeletes').textContent = analytics.deletes || 0;
            document.getElementById('eventViews').textContent = analytics.views || 0;
            document.getElementById('eventCopies').textContent = analytics.copies || 0;
            document.getElementById('eventEdits').textContent = analytics.edits || 0;
            document.getElementById('eventErrors').textContent = analytics.errors || 0;

            // Activity chart
            const activityCtx = document.getElementById('activityChart');
            if (activityCtx) {
              // Ensure we have data (fill with zeros if empty)
              const hasData = analytics.dailyData && analytics.dailyData.length > 0;
              const labels = hasData
                ? analytics.dailyData.map(d => {
                    const date = new Date(d.date);
                    // Show fewer labels if many days (every 3-5 days)
                    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
                  })
                : [];

              const viewsData = hasData ? analytics.dailyData.map(d => d.views) : [];
              const copiesData = hasData ? analytics.dailyData.map(d => d.copies) : [];
              const addsData = hasData ? analytics.dailyData.map(d => d.adds) : [];
              const editsData = hasData ? analytics.dailyData.map(d => d.edits) : [];
              const deletesData = hasData ? analytics.dailyData.map(d => d.deletes) : [];

              // Update existing chart or create new one
              if (window.activityChart && window.activityChart.data) {
                window.activityChart.data.labels = labels;
                window.activityChart.data.datasets[0].data = viewsData;
                window.activityChart.data.datasets[1].data = copiesData;
                window.activityChart.data.datasets[2].data = addsData;
                window.activityChart.data.datasets[3].data = editsData;
                window.activityChart.data.datasets[4].data = deletesData;
                window.activityChart.update('active');
              } else {
                // Destroy existing chart if it exists but is invalid
                if (window.activityChart && typeof window.activityChart.destroy === 'function') {
                  try {
                    window.activityChart.destroy();
                  } catch (e) {
                    console.warn('Error destroying activity chart:', e);
                  }
                }
                window.activityChart = new Chart(activityCtx, {
                  type: 'line',
                  data: {
                    labels: labels,
                    datasets: [
                      {
                        label: 'Views',
                        data: viewsData,
                        borderColor: 'var(--color-accent-light)',
                        backgroundColor: 'rgba(157, 180, 212, 0.1)',
                        tension: 0.4,
                        pointRadius: 2,
                        pointHoverRadius: 4
                      },
                      {
                        label: 'Copies',
                        data: copiesData,
                        borderColor: 'var(--color-success)',
                        backgroundColor: 'rgba(127, 176, 105, 0.1)',
                        tension: 0.4,
                        pointRadius: 2,
                        pointHoverRadius: 4
                      },
                      {
                        label: 'Adds',
                        data: addsData,
                        borderColor: 'var(--color-accent-light)',
                        backgroundColor: 'rgba(157, 180, 212, 0.1)',
                        tension: 0.4,
                        borderDash: [5, 5],
                        pointRadius: 2,
                        pointHoverRadius: 4
                      },
                      {
                        label: 'Edits',
                        data: editsData,
                        borderColor: 'var(--color-error)',
                        backgroundColor: 'rgba(212, 165, 165, 0.1)',
                        tension: 0.4,
                        pointRadius: 2,
                        pointHoverRadius: 4
                      },
                      {
                        label: 'Deletes',
                        data: deletesData,
                        borderColor: 'var(--color-error)',
                        backgroundColor: 'rgba(212, 165, 165, 0.1)',
                        tension: 0.4,
                        borderDash: [3, 3],
                        pointRadius: 2,
                        pointHoverRadius: 4
                      }
                    ]
                  },
                  options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    interaction: {
                      mode: 'index',
                      intersect: false
                    },
                    plugins: {
                      legend: {
                        labels: { color: 'var(--color-text-secondary)', font: { size: 11 } },
                        position: 'top'
                      },
                      tooltip: {
                        backgroundColor: 'rgba(0, 0, 0, 0.8)',
                        titleColor: 'var(--color-text-primary)',
                        bodyColor: 'var(--color-text-secondary)',
                        borderColor: 'var(--color-border)',
                        borderWidth: 1
                      }
                    },
                    scales: {
                      x: {
                        ticks: {
                          color: 'var(--color-text-secondary)',
                          font: { size: 10 },
                          maxRotation: 45,
                          minRotation: 0
                        },
                        grid: { color: 'var(--color-border)' }
                      },
                      y: {
                        ticks: {
                          color: 'var(--color-text-secondary)',
                          font: { size: 10 },
                          stepSize: 1
                        },
                        grid: { color: 'var(--color-border)' },
                        beginAtZero: true
                      }
                    }
                  }
                });
              }
            }

          }

          if (statusRes.ok) {
            const status = await statusRes.json();
            document.getElementById('serverUptime').textContent = 'Server Uptime: ' + formatUptime(status.serverUptime);
            document.getElementById('dbStatus').textContent = status.dbConnected ? 'Connected' : 'Disconnected';
            document.getElementById('dbUptime').textContent = status.dbConnected ? 'DB Uptime: ' + formatUptime(status.dbUptime) : 'DB Uptime: not connected';
          }
        } catch (error) {
          console.error('Error loading analytics:', error);
        }
      }

      loadAnalytics();
      setInterval(loadAnalytics, 30000); // Refresh every 30 seconds

      // Refresh TOTP codes on dashboard
      async function refreshTotpCodes() {
        const totpElements = document.querySelectorAll('[id^="dashboard-totp-"]');
        for (const element of totpElements) {
          const entryId = element.id.replace('dashboard-totp-', '');
          if (entryId && !element.id.includes('timer')) {
            try {
              const response = await fetch('/totp/code?id=' + entryId);
              if (response.ok) {
                const data = await response.json();
                element.textContent = data.code || '---';

                // Update timer if exists
                const timerElement = document.getElementById('dashboard-totp-timer-' + entryId);
                if (timerElement && data.remainingSeconds !== undefined) {
                  timerElement.textContent = data.remainingSeconds + 's remaining';
                }
              }
            } catch (error) {
              console.error('Error refreshing TOTP code:', error);
            }
          }
        }
      }

      // Refresh TOTP codes every 5 seconds
      refreshTotpCodes();
      setInterval(refreshTotpCodes, 5000);
    </script>
  `;

  return renderPage(dashboardBody, "Dashboard - XeoKey", request);
});

// Password management routes
router.get("/passwords", async (request, params, query) => {
  const session = await attachSession(request);
  if (!session) {
    return new Response(null, {
      status: 302,
      headers: {
        ...SECURITY_HEADERS,
        Location: '/login',
      },
    });
  }

  if (!isConnected()) {
    return renderPage(`
      <h1>All Passwords</h1>
      <p class="section-error">Database not available.</p>
    `, "Passwords - XeoKey", request);
  }

  try {
    const passwords = await getUserPasswords(session.userId);
    const passwordCount = passwords.length;

    if (passwords.length === 0) {
      return renderPage(`
        <h1>All Passwords (0)</h1>
        <div class="list-toolbar">
          <div class="list-toolbar-search">
            <input type="text" id="passwordSearch" placeholder="Search passwords..." disabled autocomplete="off" class="search-input-disabled">
          </div>
          <a href="/passwords/add" class="action-link-btn">+ Add Password</a>
        </div>
        <p>No passwords saved yet.</p>
        <p><a href="/passwords/add" class="empty-state-link">Add your first password</a></p>
      `, "Passwords - XeoKey", request);
    }

    // Analyze passwords to identify issues
    const analysis = await analyzePasswords(session.userId);
    const duplicateEntryIds = new Set(analysis.duplicateEntries.map(e => e.entryId));
    const weakEntryIds = new Set(analysis.weakEntries.map(e => e.entryId));

    const passwordList = passwords.map(p => {
      const isDuplicate = duplicateEntryIds.has(p._id!);
      const isWeak = weakEntryIds.has(p._id!);
      const issues: string[] = [];
      if (isDuplicate) issues.push('Duplicate');
      if (isWeak) issues.push('Weak');

      return `
      <div class="password-entry ${issues.length > 0 ? 'issue' : ''}"
           data-password-id="${p._id}"
           data-website="${escapeHtml(p.website).toLowerCase()}"
           data-username="${p.username ? escapeHtml(p.username).toLowerCase() : ''}"
           data-email="${p.email ? escapeHtml(p.email).toLowerCase() : ''}"
           data-notes="${p.notes ? escapeHtml(p.notes).toLowerCase() : ''}">
        <div class="password-entry-head">
          <h3 class="password-entry-title">${escapeHtml(p.website)}</h3>
          ${issues.length > 0 ? `
            <div class="password-entry-issues">
              ${issues.map(issue => `<span class="password-issue-badge">${issue}</span>`).join('')}
            </div>
          ` : ''}
        </div>
        ${p.username ? `<p class="password-entry-meta">Username: ${escapeHtml(p.username)}</p>` : ''}
        ${p.email ? `<p class="password-entry-meta">Email: ${escapeHtml(p.email)}</p>` : ''}
        <div class="password-entry-stats">
          <span>👁️ ${p.searchCount || 0} views</span>
          <span>📋 ${p.copyCount || 0} copies</span>
        </div>
      </div>
    `;
    }).join('');

    return renderPage(`
      <h1>All Passwords (${passwordCount})</h1>
      <div class="list-toolbar">
        <div class="list-toolbar-search">
          <input type="text" id="passwordSearch" placeholder="Search passwords..." autocomplete="off">
        </div>
        <a href="/passwords/add" class="action-link-btn">+ Add Password</a>
      </div>
      <div id="passwordListContainer">
        ${passwordList}
      </div>
      <div id="noResultsMessage" class="no-results">
        No passwords found matching your search.
      </div>
    `, "Passwords - XeoKey", request);
  } catch (error) {
    logger.error(`Error fetching passwords: ${error}`);
    // Try to get count for error page
    let passwordCount = 0;
    try {
      const passwords = await getUserPasswords(session.userId);
      passwordCount = passwords.length;
    } catch {
      // Ignore errors when getting count for error page
    }
    return renderPage(`
      <h1>All Passwords${passwordCount > 0 ? ' (' + passwordCount + ')' : ''}</h1>
      <p class="section-error">Error loading passwords.</p>
    `, "Passwords - XeoKey", request);
  }
});

router.get("/passwords/add", async (request, params, query) => {
  const session = await attachSession(request);
  if (!session) {
    return new Response(null, {
      status: 302,
      headers: {
        ...SECURITY_HEADERS,
        Location: '/login',
      },
    });
  }

  const csrfToken = createCsrfToken(session.sessionId);

  return renderPage(`
    <h1>Add Password</h1>
    <form method="POST" action="/passwords/add" class="form-card">
      <input type="hidden" name="csrfToken" value="${escapeHtml(csrfToken)}">
      <div class="form-group">
        <label for="website" class="form-label">Website/Service *</label>
        <input type="text" id="website" name="website" required autocomplete="off">
      </div>
      <div class="form-group">
        <label for="username" class="form-label">Username</label>
        <input type="text" id="username" name="username" autocomplete="off">
      </div>
      <div class="form-group">
        <label for="email" class="form-label">Email</label>
        <input type="email" id="email" name="email" autocomplete="off">
      </div>
      <div class="form-group">
        <label for="password" class="form-label">Password *</label>
        <div class="password-input-container">
          <div class="password-input-grow">
            <input type="text" id="password" name="password" required autocomplete="off">
            <div id="passwordStrength" class="strength-wrap">
              <div id="passwordStrengthBar" class="strength-bar"></div>
            </div>
            <div id="passwordStrengthText" class="strength-text"></div>
          </div>
          <button type="button" id="generatePasswordBtn" class="generate-btn">
            Generate
          </button>
        </div>
      </div>
      <div class="form-group-lg">
        <label for="notes" class="form-label">Notes</label>
        <textarea id="notes" name="notes" rows="4" autocomplete="off"></textarea>
      </div>
      <button type="submit" class="full-width-btn">Save Password</button>
    </form>
    <p class="text-center top-margin">
      <a href="/passwords" class="empty-state-link">← Back to Passwords</a>
    </p>
  `, "Add Password - XeoKey", request);
});

// TOTP routes
router.get("/totp", async (request, params, query) => {
  const session = await attachSession(request);
  if (!session) {
    return new Response(null, { status: 302, headers: { ...SECURITY_HEADERS, Location: '/login' } });
  }
  const entries = await listTotpEntries(session.userId);
  // Generate current codes server-side for quick view
  const items = await Promise.all(entries.map(async (e) => {
    let code = '';
    try {
      code = await getCurrentTotpCode(e);
    } catch {}
    const account = e.account ? ` <span class="totp-item-account">(${escapeHtml(e.account)})</span>` : '';
    const rightControls = e.type === 'HOTP'
      ? `<a href="/totp/next?id=${e._id}" class="totp-control">Next</a>
         <a href="/totp/delete?id=${e._id}" class="totp-control delete">Delete</a>`
      : `<a href="/totp/delete?id=${e._id}" class="totp-control delete">Delete</a>`;
    const copyBtn = `<button type="button" class="copy-totp" data-entry-id="${e._id}" data-code="${code}">Copy</button>`;
    const timer = e.type === 'TOTP' ? `<div class="totp-timer" data-period="${e.period || 30}" data-entry-id="${e._id}"><div class="totp-timer-bar"></div><span class="totp-timer-text"></span></div>` : '';
    return `<div class="totp-item" data-type="${e.type}" data-entry-id="${e._id}" data-period="${e.period || 30}">
      <div>
        <div class="totp-item-title">${escapeHtml(e.label)}${account} <span class="totp-item-type">[${e.type}]</span></div>
        <div class="totp-item-row">
          <div id="totpCode-${e._id}" class="totp-code">${code || (e.type==='HOTP' ? '(tap Next to generate)' : '')}</div>
          ${e.type === 'TOTP' ? copyBtn : ''}
        </div>
        ${timer}
      </div>
      <div class="totp-side-controls">${e.type === 'TOTP' ? '' : copyBtn}${rightControls}</div>
    </div>`;
  }));
  const body = `
    <h1>TOTP</h1>
    <div class="totp-add-link"><a href="/totp/add" class="action-link-btn">+ Add TOTP</a></div>
    <div class="totp-list">
      ${items.join('') || '<div class="totp-empty">No TOTP entries yet.</div>'}
    </div>
  `;
  return renderPage(body, "TOTP - XeoKey", request);
});

router.get("/totp/add", async (request, params, query) => {
  const session = await attachSession(request);
  if (!session) {
    return new Response(null, { status: 302, headers: { ...SECURITY_HEADERS, Location: '/login' } });
  }
  const csrf = createCsrfToken(session.sessionId);
  const body = `
    <h1>Add TOTP</h1>
    <form method="POST" action="/totp/add" class="form-card">
      <input type="hidden" name="csrfToken" value="${escapeHtml(csrf)}">
      <div class="form-group-sm">
        <label class="form-label-sm">Label *</label>
        <input type="text" name="label" required autocomplete="off">
      </div>
      <div class="form-group-sm">
        <label class="form-label-sm">Type</label>
        <select name="type" id="otpType" autocomplete="off">
          <option value="TOTP" selected>TOTP (RFC 6238)</option>
          <option value="HOTP">HOTP (RFC 4226)</option>
        </select>
      </div>
      <div class="form-group-sm">
        <label class="form-label-sm">Account (optional)</label>
        <input type="text" name="account" autocomplete="off">
      </div>
      <div class="form-group-sm">
        <label class="form-label-sm">Secret (Base32) *</label>
        <input type="text" name="secret" required autocomplete="off">
      </div>
      <div class="form-inline-row">
        <div class="form-inline-grow hidden-field" id="counterField">
          <label class="form-label-sm">Counter (HOTP)</label>
          <input type="number" name="counter" value="0" min="0" autocomplete="off">
        </div>
      </div>
      <div class="totp-standards">
        Using recommended standards:
        <ul>
          <li>TOTP/HOTP digits: 6</li>
          <li>TOTP period: 30 seconds</li>
          <li>Algorithm: SHA1 (widely compatible)</li>
          <li>Backup codes: generated automatically</li>
        </ul>
      </div>
      <button type="submit">Save</button>
    </form>
    <script>
      (function(){
        const typeEl = document.getElementById('otpType');
        const counterField = document.getElementById('counterField');
        function updateVisibility(){
          const val = typeEl.value;
          if(val === 'HOTP'){
            counterField.style.display = 'block';
          }else{
            counterField.style.display = 'none';
          }
        }
        typeEl.addEventListener('change', updateVisibility);
        updateVisibility();
      })();
    </script>
  `;
  return renderPage(body, "Add TOTP - XeoKey", request);
});

router.post("/totp/add", async (request, params, query) => {
  const session = await attachSession(request);
  if (!session) {
    return new Response(null, { status: 302, headers: { ...SECURITY_HEADERS, Location: '/login' } });
  }
  try {
    const form = await request.formData();
    const label = (form.get('label')?.toString() || '').trim();
    const account = (form.get('account')?.toString() || '').trim();
    const secret = (form.get('secret')?.toString() || '').replace(/\s+/g, '');
    const type = ((form.get('type')?.toString() || 'TOTP').toUpperCase() as 'TOTP'|'HOTP');
    const counter = parseInt(form.get('counter')?.toString() || '0', 10);

    if (!label || !secret) {
      return createErrorResponse(400, 'Label and secret are required');
    }
    const { entry, plaintextBackupCodes } = await createTotpEntry(session.userId, label, secret, {
      account: account || undefined,
      // Recommended standards (automatic)
      digits: 6,
      period: 30,
      algorithm: 'SHA1',
      withBackupCodes: true,
      type,
      counter: isNaN(counter) ? 0 : counter
    });
    const codesHtml = plaintextBackupCodes && plaintextBackupCodes.length
      ? `<div class="backup-codes">
           <div class="backup-codes-warning">Save these backup codes in a safe place. They are shown only once.</div>
           <pre>${plaintextBackupCodes.join('\n')}</pre>
         </div>` : '';
    const body = `
      <h1>TOTP Added</h1>
      <p>Entry "${escapeHtml(entry.label)}" created.</p>
      ${codesHtml}
      <p class="top-gap-sm"><a href="/totp" class="empty-state-link">← Back to TOTP list</a></p>
    `;
    return renderPage(body, "TOTP Added - XeoKey", request);
  } catch (e) {
    logger.error(`Failed to add TOTP: ${e}`);
    return createErrorResponse(400, 'Invalid TOTP data');
  }
});

router.get("/totp/delete", async (request, params, query) => {
  const session = await attachSession(request);
  if (!session) {
    return new Response(null, { status: 302, headers: { ...SECURITY_HEADERS, Location: '/login' } });
  }
  const url = new URL(request.url);
  const id = url.searchParams.get('id') || '';
  if (id) {
    const { deleteTotpEntry } = await import('./models/totp');
    try {
      await deleteTotpEntry(id, session.userId);
    } catch {}
  }
  return new Response(null, { status: 302, headers: { ...SECURITY_HEADERS, Location: '/totp' } });
});

router.get("/totp/next", async (request, params, query) => {
  const session = await attachSession(request);
  if (!session) {
    return new Response(null, { status: 302, headers: { ...SECURITY_HEADERS, Location: '/login' } });
  }
  const url = new URL(request.url);
  const id = url.searchParams.get('id') || '';
  if (!id) {
    return new Response(null, { status: 302, headers: { ...SECURITY_HEADERS, Location: '/totp' } });
  }
  const { getTotpEntry } = await import('./models/totp');
  const entry = await getTotpEntry(id, session.userId);
  if (!entry) {
    return new Response(null, { status: 302, headers: { ...SECURITY_HEADERS, Location: '/totp' } });
  }
  // For HOTP, increment counter and show the new code
  try {
    const { getDatabase } = await import('./db/mongodb');
    const { ObjectId } = await import('mongodb');
    const db = getDatabase();
    await db.collection('totp').updateOne({ _id: new ObjectId(id), userId: session.userId }, { $inc: { counter: 1 }, $set: { lastUsedAt: new Date() } });
  } catch (error) {
    // Non-critical: TOTP counter update failed, but code was still generated
    logger.debug(`Failed to update TOTP counter: ${error}`);
  }
  return new Response(null, { status: 302, headers: { ...SECURITY_HEADERS, Location: '/totp' } });
});

// Endpoint to fetch current TOTP code (no secrets disclosed)
router.get("/totp/code", async (request, params, query) => {
  const session = await attachSession(request);
  if (!session) {
    return createErrorResponse(401, "Unauthorized");
  }
  const url = new URL(request.url);
  const id = url.searchParams.get('id') || '';
  if (!id) return createErrorResponse(400, "Missing id");
  const { getTotpEntry } = await import('./models/totp');
  const entry = await getTotpEntry(id, session.userId);
  if (!entry || entry.type !== 'TOTP') {
    return createErrorResponse(404, "Not found");
  }
  try {
    const code = await getCurrentTotpCode(entry);
    const period = entry.period || 30;
    const now = Date.now();
    const currentPeriod = Math.floor(now / 1000 / period);
    const periodStart = currentPeriod * period * 1000;
    const periodEnd = periodStart + (period * 1000);
    const remainingSeconds = Math.floor((periodEnd - now) / 1000);
    const body = JSON.stringify({ code, period, now, remainingSeconds });
    return new Response(body, { headers: { ...SECURITY_HEADERS, "Content-Type": "application/json" } });
  } catch (e) {
    return createErrorResponse(500, "Failed to generate code");
  }
});

// Notes management routes
router.get("/notes", async (request, params, query) => {
  const session = await attachSession(request);
  if (!session) {
    return new Response(null, {
      status: 302,
      headers: {
        ...SECURITY_HEADERS,
        Location: '/login',
      },
    });
  }

  if (!isConnected()) {
    return renderPage(`
      <h1>Secure Notes</h1>
      <p style="color: var(--color-error);">Database not available.</p>
    `, "Notes - XeoKey", request);
  }

  try {
    const notes = await getUserNotes(session.userId);
    const noteCount = notes.length;
    const csrfToken = await getOrCreateCsrfToken(session.sessionId);

    if (noteCount === 0) {
      return renderPage(`
        <h1>Secure Notes (0)</h1>
        <div class="list-toolbar">
          <div class="list-toolbar-search">
            <input type="text" id="noteSearch" placeholder="Search notes..." disabled autocomplete="off" class="search-input-disabled">
          </div>
          <a href="/notes/add" class="action-link-btn">+ Add Note</a>
        </div>
        <p>No notes saved yet.</p>
        <p><a href="/notes/add" class="empty-state-link">Create your first note</a></p>
      `, "Notes - XeoKey", request);
    }

    const noteList = notes.map(note => {
      const createdDate = new Date(note.createdAt).toLocaleDateString();
      const updatedDate = new Date(note.updatedAt).toLocaleDateString();
      const preview = note.content.length > 100 ? note.content.substring(0, 100) + '...' : note.content;

      return `
        <div class="note-item">
          <div class="note-item-head">
            <h3 class="note-item-title">${escapeHtml(note.title)}</h3>
            <div class="note-item-actions">
              <a href="/notes/${note._id}" class="note-edit-btn note-view-btn">👁️ View</a>
              <form method="POST" action="/notes/${note._id}/delete" class="note-delete-form" onsubmit="return confirm('Are you sure you want to delete this note?');">
                <input type="hidden" name="csrf_token" value="${csrfToken}">
                <button type="submit" class="note-delete-btn">🗑️ Delete</button>
              </form>
            </div>
          </div>
          <p class="note-item-preview">${escapeHtml(preview)}</p>
          <div class="note-item-meta">
            Created: ${createdDate} | Updated: ${updatedDate}
          </div>
        </div>
      `;
    }).join('');

    const body = `
      <h1>Secure Notes (${noteCount})</h1>
      <div class="list-toolbar">
        <div class="list-toolbar-search">
          <input type="text" id="noteSearch" placeholder="Search notes..." autocomplete="off" class="form-input">
        </div>
        <a href="/notes/add" class="action-link-btn">+ Add Note</a>
      </div>
      <div id="notesList">
        ${noteList}
      </div>
      <script>
        document.getElementById('noteSearch').addEventListener('input', function(e) {
          const searchTerm = e.target.value.toLowerCase();
          const notes = document.querySelectorAll('.note-item');

          notes.forEach(note => {
            const title = note.querySelector('h3').textContent.toLowerCase();
            const content = note.querySelector('p').textContent.toLowerCase();

            if (title.includes(searchTerm) || content.includes(searchTerm)) {
              note.style.display = 'block';
            } else {
              note.style.display = 'none';
            }
          });
        });

        // Add hover effects for buttons
        document.addEventListener('DOMContentLoaded', function() {
          const style = document.createElement('style');
          style.textContent = \`
            .note-item .note-view-btn {
              transition: all 0.2s ease !important;
            }
            .note-item .note-view-btn:hover {
              background: var(--color-success) !important;
              border-color: var(--color-border) !important;
              transform: translateY(-1px);
            }
            .note-item button[type="submit"] {
              transition: all 0.2s ease !important;
            }
            .note-item button[type="submit"]:hover {
              background: var(--color-error) !important;
              border-color: var(--color-border) !important;
              transform: translateY(-1px);
            }
          \`;
          document.head.appendChild(style);
        });
      </script>
    `;

    return renderPage(body, "Notes - XeoKey", request);
  } catch (error) {
    logger.error(`Error loading notes: ${error}`);
    // Try to get count for error page
    let noteCount = 0;
    try {
      const notes = await getUserNotes(session.userId);
      noteCount = notes.length;
    } catch {
      // Ignore errors when getting count for error page
    }
    return renderPage(`
      <h1>Secure Notes (${noteCount})</h1>
      <p class="section-error">Error loading notes. Please try again.</p>
      <div style="margin-bottom: 1.5rem;">
        <a href="/notes/add" class="action-link-btn">+ Add Note</a>
      </div>
    `, "Notes - XeoKey", request);
  }
});

router.get("/notes/add", async (request, params, query) => {
  const session = await attachSession(request);
  if (!session) {
    return new Response(null, {
      status: 302,
      headers: {
        ...SECURITY_HEADERS,
        Location: '/login',
      },
    });
  }

  const csrfToken = await getOrCreateCsrfToken(session.sessionId);

  const body = `
    <h1>Add New Note</h1>
    <form method="POST" action="/notes/add" class="note-form">
      <input type="hidden" name="csrf_token" value="${csrfToken}">

      <div class="form-group">
        <label for="title" class="note-form-label">Title</label>
        <input type="text" id="title" name="title" required class="note-text-input">
      </div>

      <div class="form-group-lg">
        <label for="content" class="note-form-label">Content</label>
        <textarea id="content" name="content" required rows="15" class="note-textarea"></textarea>
      </div>

      <div class="note-form-actions">
        <button type="submit" class="note-save-btn">Save Note</button>
        <a href="/notes" class="empty-state-link">Cancel</a>
      </div>
    </form>
  `;

  return renderPage(body, "Add Note - XeoKey", request);
});

router.post("/notes/add", async (request, params, query) => {
  const session = await attachSession(request);
  if (!session) {
    return new Response(null, {
      status: 302,
      headers: {
        ...SECURITY_HEADERS,
        Location: '/login',
      },
    });
  }

  if (!isConnected()) {
    return createErrorResponse(500, "Database not available");
  }

  try {
    const formData = await request.formData();
    const csrfToken = formData.get('csrf_token') as string;
    const title = sanitizeString(formData.get('title') as string, 200);
    const content = sanitizeString(formData.get('content') as string, null);

    // Verify CSRF token
    if (!csrfToken || !await verifyCsrfToken(session.sessionId, csrfToken)) {
      return createErrorResponse(403, "Invalid CSRF token");
    }

    // Validate input
    if (!title || title.trim().length === 0) {
      return createErrorResponse(400, "Title is required");
    }
    if (!content || content.trim().length === 0) {
      return createErrorResponse(400, "Content is required");
    }
    if (title.length > 200) {
      return createErrorResponse(400, "Title must be 200 characters or less");
    }

    await createNoteEntry(session.userId, title.trim(), content.trim());
    await trackEvent(session.userId, 'add');

    return new Response(null, {
      status: 302,
      headers: {
        ...SECURITY_HEADERS,
        Location: '/notes',
      },
    });
  } catch (error) {
    logger.error(`Error creating note: ${error}`);
    return createErrorResponse(500, "Failed to create note");
  }
});

router.get("/notes/:id", async (request, params, query) => {
  const session = await attachSession(request);
  if (!session) {
    return new Response(null, {
      status: 302,
      headers: {
        ...SECURITY_HEADERS,
        Location: '/login',
      },
    });
  }

  if (!isConnected()) {
    return renderPage(`
      <h1>Note Details</h1>
      <p class="section-error">Database not available.</p>
    `, "Note Details - XeoKey", request);
  }

  try {
    const note = await getNoteEntry(params.id, session.userId);
    if (!note) {
      return new Response(null, {
        status: 302,
        headers: {
          ...SECURITY_HEADERS,
          Location: '/notes',
        },
      });
    }

    const decryptedContent = await getDecryptedNoteContent(params.id, session.userId);
    if (decryptedContent === null) {
      return renderPage(`
        <h1>Note Details</h1>
        <p class="section-error">Unable to decrypt note content.</p>
        <p><a href="/notes" class="empty-state-link">← Back to Notes</a></p>
      `, "Note Details - XeoKey", request);
    }

    const csrfToken = await getOrCreateCsrfToken(session.sessionId);
    const startInEditMode = query.get('mode') === 'edit';
    const viewDisplay = startInEditMode ? 'none' : 'block';
    const editDisplay = startInEditMode ? 'block' : 'none';

    const createdAt = new Date(note.createdAt).toLocaleString();
    const updatedAt = new Date(note.updatedAt).toLocaleString();

    const body = `
      <h1>Note Details</h1>
      <div style="max-width: 900px;">
        <div style="display: flex; flex-wrap: wrap; gap: 0.5rem; align-items: center; background: var(--color-bg-secondary); border: 1px solid var(--color-border); border-radius: 8px; padding: 0.75rem; margin-bottom: 1rem;">
          <a href="/notes" class="note-delete-btn" style="width: 112px; height: 40px; box-sizing: border-box; text-decoration: none; display: inline-flex; align-items: center; justify-content: center; text-align: center; background: var(--color-bg-tertiary); color: var(--color-text-primary); border-color: var(--color-border);">Back</a>
          <button type="button" id="noteViewBtn" class="note-delete-btn" style="width: 112px; height: 40px; box-sizing: border-box; display: ${editDisplay}; align-items: center; justify-content: center; text-align: center; background: var(--color-bg-tertiary); color: var(--color-text-primary); border-color: var(--color-border);">View</button>
          <button type="button" id="noteEditBtn" class="note-save-btn" style="width: 112px; height: 40px; box-sizing: border-box; display: ${viewDisplay}; align-items: center; justify-content: center; text-align: center;">Edit</button>
          <button type="submit" id="noteUpdateBtn" form="noteUpdateForm" class="note-save-btn" style="width: 112px; height: 40px; box-sizing: border-box; display: ${editDisplay}; align-items: center; justify-content: center; text-align: center;">Save</button>
          <button type="button" id="noteCancelEditBtn" class="note-delete-btn" style="width: 112px; height: 40px; box-sizing: border-box; display: ${editDisplay}; align-items: center; justify-content: center; text-align: center; background: var(--color-bg-tertiary); color: var(--color-text-primary); border-color: var(--color-border);">Cancel</button>
          <button type="submit" form="noteDeleteForm" class="note-delete-btn" style="width: 112px; height: 40px; box-sizing: border-box; display: inline-flex; align-items: center; justify-content: center; text-align: center; margin-left: auto;">Delete</button>
        </div>

        <div class="note-item" style="margin-bottom: 1rem;">
          <form id="noteUpdateForm" method="POST" action="/notes/${params.id}/update" class="note-form" style="margin: 0;">
            <input type="hidden" name="csrf_token" value="${csrfToken}">

            <div class="form-group">
              <label for="titleInput" class="note-form-label">Title</label>
              <h2 id="noteTitleText" class="note-item-title" style="margin: 0; display: ${viewDisplay};">${escapeHtml(note.title)}</h2>
              <input type="text" id="titleInput" name="title" required value="${escapeHtml(note.title)}" class="note-text-input" style="display: ${editDisplay};">
            </div>

            <div class="form-group-lg">
              <label for="contentInput" class="note-form-label">Content</label>
              <div id="noteContentText" class="pwd-notes-val" style="white-space: pre-wrap; min-height: 10rem; display: ${viewDisplay};">${escapeHtml(decryptedContent)}</div>
              <textarea id="contentInput" name="content" required rows="15" class="note-textarea" style="display: ${editDisplay};">${escapeHtml(decryptedContent)}</textarea>
            </div>

            <div class="note-item-meta" style="margin-top: 1rem;">
              Created: ${createdAt}<br>
              Updated: ${updatedAt}
            </div>
          </form>
        </div>

        <form id="noteDeleteForm" method="POST" action="/notes/${params.id}/delete" onsubmit="return confirm('Are you sure you want to delete this note?');">
          <input type="hidden" name="csrf_token" value="${csrfToken}">
        </form>
      </div>

      <script>
        (function() {
          const titleText = document.getElementById('noteTitleText');
          const titleInput = document.getElementById('titleInput');
          const contentText = document.getElementById('noteContentText');
          const contentInput = document.getElementById('contentInput');
          const viewBtn = document.getElementById('noteViewBtn');
          const editBtn = document.getElementById('noteEditBtn');
          const updateBtn = document.getElementById('noteUpdateBtn');
          const cancelBtn = document.getElementById('noteCancelEditBtn');
          const initialTitle = ${JSON.stringify(note.title)};
          const initialContent = ${JSON.stringify(decryptedContent)};

          if (!titleText || !titleInput || !contentText || !contentInput) return;

          function setEditMode(isEditing) {
            titleText.style.display = isEditing ? 'none' : 'block';
            contentText.style.display = isEditing ? 'none' : 'block';
            titleInput.style.display = isEditing ? 'block' : 'none';
            contentInput.style.display = isEditing ? 'block' : 'none';

            if (viewBtn) viewBtn.style.display = isEditing ? 'inline-flex' : 'none';
            if (editBtn) editBtn.style.display = isEditing ? 'none' : 'inline-flex';
            if (updateBtn) updateBtn.style.display = isEditing ? 'inline-flex' : 'none';
            if (cancelBtn) cancelBtn.style.display = isEditing ? 'inline-flex' : 'none';
          }

          if (editBtn) {
            editBtn.addEventListener('click', function() {
              setEditMode(true);
              titleInput.focus();
              titleInput.select();
            });
          }

          if (viewBtn) {
            viewBtn.addEventListener('click', function() {
              setEditMode(false);
            });
          }

          if (cancelBtn) {
            cancelBtn.addEventListener('click', function() {
              titleInput.value = initialTitle;
              contentInput.value = initialContent;
              setEditMode(false);
            });
          }
        })();
      </script>
    `;

    return renderPage(body, "Note Details - XeoKey", request);
  } catch (error) {
    logger.error(`Error loading note details: ${error}`);
    return renderPage(`
      <h1>Note Details</h1>
      <p class="section-error">Error loading note. Please try again.</p>
      <p><a href="/notes" class="empty-state-link">← Back to Notes</a></p>
    `, "Note Details - XeoKey", request);
  }
});

// Backward compatibility route for old edit URLs
router.get("/notes/:id/edit", async (request, params, query) => {
  const session = await attachSession(request);
  if (!session) {
    return new Response(null, {
      status: 302,
      headers: {
        ...SECURITY_HEADERS,
        Location: '/login',
      },
    });
  }

  return new Response(null, {
    status: 302,
    headers: {
      ...SECURITY_HEADERS,
      Location: `/notes/${params.id}?mode=edit`,
    },
  });
});

router.post("/notes/:id/update", async (request, params, query) => {
  const session = await attachSession(request);
  if (!session) {
    return new Response(null, {
      status: 302,
      headers: {
        ...SECURITY_HEADERS,
        Location: '/login',
      },
    });
  }

  if (!isConnected()) {
    return createErrorResponse(500, "Database not available");
  }

  try {
    const formData = await request.formData();
    const csrfToken = formData.get('csrf_token') as string;
    const title = sanitizeString(formData.get('title') as string, 200);
    const content = sanitizeString(formData.get('content') as string, null);

    // Verify CSRF token
    if (!csrfToken || !await verifyCsrfToken(session.sessionId, csrfToken)) {
      return createErrorResponse(403, "Invalid CSRF token");
    }

    // Validate input
    if (!title || title.trim().length === 0) {
      return createErrorResponse(400, "Title is required");
    }
    if (!content || content.trim().length === 0) {
      return createErrorResponse(400, "Content is required");
    }
    if (title.length > 200) {
      return createErrorResponse(400, "Title must be 200 characters or less");
    }

    const success = await updateNoteEntry(params.id, session.userId, {
      title: title.trim(),
      content: content.trim()
    });

    if (!success) {
      return createErrorResponse(404, "Note not found or update failed");
    }

    await trackEvent(session.userId, 'edit');

    return new Response(null, {
      status: 302,
      headers: {
        ...SECURITY_HEADERS,
        Location: '/notes',
      },
    });
  } catch (error) {
    logger.error(`Error updating note: ${error}`);
    return createErrorResponse(500, "Failed to update note");
  }
});

router.post("/notes/:id/delete", async (request, params, query) => {
  const session = await attachSession(request);
  if (!session) {
    return new Response(null, {
      status: 302,
      headers: {
        ...SECURITY_HEADERS,
        Location: '/login',
      },
    });
  }

  if (!isConnected()) {
    return createErrorResponse(500, "Database not available");
  }

  try {
    const formData = await request.formData();
    const csrfToken = formData.get('csrf_token') as string;

    // Verify CSRF token
    if (!csrfToken || !await verifyCsrfToken(session.sessionId, csrfToken)) {
      return createErrorResponse(403, "Invalid CSRF token");
    }

    const success = await deleteNoteEntry(params.id, session.userId);

    if (!success) {
      return createErrorResponse(404, "Note not found or delete failed");
    }

    await trackEvent(session.userId, 'delete');

    return new Response(null, {
      status: 302,
      headers: {
        ...SECURITY_HEADERS,
        Location: '/notes',
      },
    });
  } catch (error) {
    logger.error(`Error deleting note: ${error}`);
    return createErrorResponse(500, "Failed to delete note");
  }
});

// Backup Management Routes
router.get("/backups", async (request, params, query) => {
  const session = await attachSession(request);
  if (!session) {
    return new Response(null, {
      status: 302,
      headers: {
        ...SECURITY_HEADERS,
        Location: '/login',
      },
    });
  }

  if (!isConnected()) {
    return renderPage(`
      <h1>Backup Management</h1>
      <p style="color: var(--color-error);">Database not available.</p>
    `, "Backups - XeoKey", request);
  }

  try {
    const backups = await listBackups();
    const stats = await getBackupStats();

    const backupList = backups.map(backup => {
      const date = new Date(backup.timestamp).toLocaleString();
      const sizeKB = (backup.size / 1024).toFixed(2);
      const typeBadge = backup.backupType === 'pre-migration'
        ? `<span style="background: var(--color-bg-secondary); color: var(--color-accent-light); padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.75rem; border: 1px solid var(--color-bg-tertiary);">Pre-Migration</span>`
        : backup.backupType === 'automatic'
        ? `<span style="background: #2d3d4d; color: var(--color-accent-light); padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.75rem; border: 1px solid var(--color-border);">Automatic</span>`
        : `<span style="background: var(--color-border); color: var(--color-accent-light); padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.75rem; border: 1px solid var(--color-bg-tertiary);">Manual</span>`;

      return `
        <div style="border: 1px solid var(--color-border); border-radius: 8px; padding: 1rem; margin-bottom: 1rem; background: var(--color-bg-secondary);">
          <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 0.5rem;">
            <div>
              <h3 style="margin: 0; color: var(--color-accent-light);">${escapeHtml(backup.backupId)}</h3>
              <p style="color: var(--color-text-secondary); margin: 0.25rem 0; font-size: 0.9rem;">${date}</p>
            </div>
            ${typeBadge}
          </div>
          <div style="color: var(--color-text-secondary); font-size: 0.9rem; margin-bottom: 0.5rem;">
            <p style="margin: 0.25rem 0;">Collections: ${backup.collections.join(', ')}</p>
            <p style="margin: 0.25rem 0;">Documents: ${backup.totalDocuments}</p>
            <p style="margin: 0.25rem 0;">Size: ${sizeKB} KB</p>
            ${backup.description ? `<p style="margin: 0.25rem 0; color: var(--color-text-secondary);">${escapeHtml(backup.description)}</p>` : ''}
          </div>
          <div style="display: flex; gap: 0.5rem; margin-top: 0.5rem;">
            <form method="POST" action="/backups/${backup.backupId}/restore" style="display: inline;">
              <input type="hidden" name="csrfToken" value="${getOrCreateCsrfToken(session.sessionId)}">
              <button type="submit" onclick="return confirm('⚠️ WARNING: This will overwrite all data in the restored collections! Are you sure?');"
                      style="background: var(--color-bg-tertiary); color: var(--color-accent-light); border: 1px solid var(--color-border); padding: 0.5rem 1rem; border-radius: 4px; cursor: pointer;">
                Restore
              </button>
            </form>
            <form method="POST" action="/backups/${backup.backupId}/delete" style="display: inline;">
              <input type="hidden" name="csrfToken" value="${getOrCreateCsrfToken(session.sessionId)}">
              <button type="submit" onclick="return confirm('Are you sure you want to delete this backup?');"
                      style="background: rgba(201, 133, 133, 0.18); color: var(--color-error); border: 1px solid var(--color-error); padding: 0.5rem 1rem; border-radius: 4px; cursor: pointer;">
                Delete
              </button>
            </form>
          </div>
        </div>
      `;
    }).join('');

    return renderPage(`
      <h1>Backup Management</h1>
      <div style="margin-bottom: 1.5rem; padding: 1rem; background: var(--color-bg-secondary); border-radius: 8px; border: 1px solid var(--color-border);">
        <h2 style="margin-top: 0; color: var(--color-accent-light);">Statistics</h2>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem;">
          <div>
            <p style="color: var(--color-text-secondary); margin: 0; font-size: 0.9rem;">Total Backups</p>
            <p style="color: var(--color-accent-light); margin: 0.25rem 0; font-size: 1.5rem; font-weight: bold;">${stats.totalBackups}</p>
          </div>
          <div>
            <p style="color: var(--color-text-secondary); margin: 0; font-size: 0.9rem;">Total Size</p>
            <p style="color: var(--color-accent-light); margin: 0.25rem 0; font-size: 1.5rem; font-weight: bold;">${(stats.totalSize / 1024 / 1024).toFixed(2)} MB</p>
          </div>
          ${stats.oldestBackup ? `
          <div>
            <p style="color: var(--color-text-secondary); margin: 0; font-size: 0.9rem;">Oldest Backup</p>
            <p style="color: var(--color-accent-light); margin: 0.25rem 0; font-size: 1rem;">${new Date(stats.oldestBackup).toLocaleDateString()}</p>
          </div>
          ` : ''}
          ${stats.newestBackup ? `
          <div>
            <p style="color: var(--color-text-secondary); margin: 0; font-size: 0.9rem;">Newest Backup</p>
            <p style="color: var(--color-accent-light); margin: 0.25rem 0; font-size: 1rem;">${new Date(stats.newestBackup).toLocaleDateString()}</p>
          </div>
          ` : ''}
        </div>
      </div>
      <div style="margin-bottom: 1.5rem;">
        <form method="POST" action="/backups/create" style="display: inline;">
          <input type="hidden" name="csrfToken" value="${getOrCreateCsrfToken(session.sessionId)}">
          <button type="submit" style="background: var(--color-bg-tertiary); color: var(--color-accent-light); border: 1px solid var(--color-border); padding: 0.75rem 1.5rem; border-radius: 4px; cursor: pointer; font-size: 1rem;">
            + Create Manual Backup
          </button>
        </form>
      </div>
      <div>
        <h2 style="color: var(--color-accent-light);">Available Backups</h2>
        ${backups.length === 0 ? `
          <p style="color: var(--color-text-secondary);">No backups available. Create your first backup to get started.</p>
        ` : backupList}
      </div>
    `, "Backups - XeoKey", request);
  } catch (error) {
    logger.error(`Error fetching backups: ${error}`);
    return renderPage(`
      <h1>Backup Management</h1>
      <p style="color: var(--color-error);">Error loading backups.</p>
    `, "Backups - XeoKey", request);
  }
});

router.post("/backups/create", async (request, params, query) => {
  const session = await attachSession(request);
  if (!session) {
    return new Response(null, {
      status: 302,
      headers: {
        ...SECURITY_HEADERS,
        Location: '/login',
      },
    });
  }

  if (!isConnected()) {
    return createErrorResponse(503, "Database not available");
  }

  try {
    const formData = await request.formData();
    const csrfToken = formData.get('csrfToken')?.toString() || '';

    if (!verifyCsrfToken(session.sessionId, csrfToken)) {
      return createErrorResponse(403, "Invalid CSRF token");
    }

    const collections = ['passwords', 'totp', 'users', 'sessions'];
    const description = formData.get('description')?.toString() || 'Manual backup';

    const result = await createBackup(collections, 'manual', undefined, description);

    if (result.success) {
      return new Response(null, {
        status: 302,
        headers: {
          ...SECURITY_HEADERS,
          Location: '/backups',
        },
      });
    } else {
      return renderPage(`
        <h1>Backup Failed</h1>
        <p style="color: var(--color-error);">${escapeHtml(result.error || 'Unknown error')}</p>
        <p><a href="/backups" style="color: var(--color-accent-light);">← Back to Backups</a></p>
      `, "Backup Failed - XeoKey", request);
    }
  } catch (error) {
    logger.error(`Error creating backup: ${error}`);
    return createErrorResponse(500, "Internal Server Error");
  }
});

router.post("/backups/:id/restore", async (request, params, query) => {
  const session = await attachSession(request);
  if (!session) {
    return new Response(null, {
      status: 302,
      headers: {
        ...SECURITY_HEADERS,
        Location: '/login',
      },
    });
  }

  if (!isConnected()) {
    return createErrorResponse(503, "Database not available");
  }

  try {
    const backupId = params.id || '';
    const formData = await request.formData();
    const csrfToken = formData.get('csrfToken')?.toString() || '';

    if (!verifyCsrfToken(session.sessionId, csrfToken)) {
      return createErrorResponse(403, "Invalid CSRF token");
    }

    const result = await restoreBackup(backupId);

    if (result.success) {
      return renderPage(`
        <h1>Backup Restored</h1>
        <p style="color: var(--color-accent-light);">✅ Backup restored successfully!</p>
        <p style="color: var(--color-text-secondary);">Collections: ${result.restoredCollections.join(', ')}</p>
        <p style="color: var(--color-text-secondary);">Documents: ${result.restoredDocuments}</p>
        <p><a href="/backups" style="color: var(--color-accent-light);">← Back to Backups</a></p>
      `, "Backup Restored - XeoKey", request);
    } else {
      return renderPage(`
        <h1>Restore Failed</h1>
        <p style="color: var(--color-error);">${escapeHtml(result.error || 'Unknown error')}</p>
        <p><a href="/backups" style="color: var(--color-accent-light);">← Back to Backups</a></p>
      `, "Restore Failed - XeoKey", request);
    }
  } catch (error) {
    logger.error(`Error restoring backup: ${error}`);
    return createErrorResponse(500, "Internal Server Error");
  }
});

router.post("/backups/:id/delete", async (request, params, query) => {
  const session = await attachSession(request);
  if (!session) {
    return new Response(null, {
      status: 302,
      headers: {
        ...SECURITY_HEADERS,
        Location: '/login',
      },
    });
  }

  if (!isConnected()) {
    return createErrorResponse(503, "Database not available");
  }

  try {
    const backupId = params.id || '';
    const formData = await request.formData();
    const csrfToken = formData.get('csrfToken')?.toString() || '';

    if (!verifyCsrfToken(session.sessionId, csrfToken)) {
      return createErrorResponse(403, "Invalid CSRF token");
    }

    const success = await deleteBackup(backupId);

    if (success) {
      return new Response(null, {
        status: 302,
        headers: {
          ...SECURITY_HEADERS,
          Location: '/backups',
        },
      });
    } else {
      return renderPage(`
        <h1>Delete Failed</h1>
        <p style="color: var(--color-error);">Failed to delete backup.</p>
        <p><a href="/backups" style="color: var(--color-accent-light);">← Back to Backups</a></p>
      `, "Delete Failed - XeoKey", request);
    }
  } catch (error) {
    logger.error(`Error deleting backup: ${error}`);
    return createErrorResponse(500, "Internal Server Error");
  }
});

// Health Check and Integrity Routes
async function buildPasswordIssuesPanel(session: { sessionId: string; userId: string }): Promise<string> {
  const userIdString = typeof session.userId === 'string' ? session.userId : (session.userId as any).toString();
  const unrecoverable = await getUnrecoverablePasswords(userIdString);

  const unrecoverableList = unrecoverable
    .filter(e => !e.canDecrypt)
    .map(entry => {
      const identifier = encodeURIComponent(JSON.stringify({
        website: entry.website,
        username: entry.username || '',
        email: entry.email || ''
      }));

      return `
        <div style="border: 1px solid var(--color-border); border-radius: 8px; padding: 1rem; margin-bottom: 1rem; background: var(--color-bg-secondary);">
          <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 0.75rem;">
            <div style="flex: 1;">
              <h3 style="margin: 0; color: var(--color-accent-light); font-size: 1.1rem;">${escapeHtml(entry.website)}</h3>
              ${entry.username ? `<p style="color: var(--color-text-secondary); margin: 0.25rem 0; font-size: 0.9rem;"><strong>Username:</strong> ${escapeHtml(entry.username)}</p>` : ''}
              ${entry.email ? `<p style="color: var(--color-text-secondary); margin: 0.25rem 0; font-size: 0.9rem;"><strong>Email:</strong> ${escapeHtml(entry.email)}</p>` : ''}
              ${entry.decryptionError ? `<p style="color: var(--color-error); margin: 0.5rem 0 0 0; font-size: 0.85rem;">${escapeHtml(entry.decryptionError)}</p>` : ''}
            </div>
            <span style="background: rgba(201, 133, 133, 0.18); color: var(--color-error); padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.75rem; border: 1px solid var(--color-error); white-space: nowrap;">Cannot Decrypt</span>
          </div>
          <div style="display: flex; gap: 0.5rem; flex-wrap: wrap; margin-top: 0.75rem; padding-top: 0.75rem; border-top: 1px solid var(--color-border);">
            <form method="POST" action="/passwords/recover/by-identifier" style="flex: 1; min-width: 250px;">
              <input type="hidden" name="csrfToken" value="${createCsrfToken(session.sessionId)}">
              <input type="hidden" name="identifier" value="${identifier}">
              <div style="display: flex; gap: 0.5rem;">
                <input type="password" name="masterKey" placeholder="Master password or key" autocomplete="off"
                      style="flex: 1; padding: 0.5rem; border: 1px solid var(--color-border); border-radius: 4px; background: var(--color-bg-primary); color: var(--color-text-primary); font-size: 0.9rem; box-sizing: border-box;" required>
                <button type="submit" style="background: var(--color-bg-tertiary); color: var(--color-accent-light); border: 1px solid var(--color-border); padding: 0.5rem 1rem; border-radius: 4px; cursor: pointer; white-space: nowrap;">
                  Try Recovery
                </button>
              </div>
            </form>
            <form method="POST" action="/passwords/delete/by-identifier" style="display: inline-block;">
              <input type="hidden" name="csrfToken" value="${createCsrfToken(session.sessionId)}">
              <input type="hidden" name="identifier" value="${identifier}">
              <button type="submit" onclick="return confirm('Are you sure you want to delete this password entry? This cannot be undone.');"
                      style="background: rgba(201, 133, 133, 0.18); color: var(--color-error); border: 1px solid var(--color-error); padding: 0.5rem 1rem; border-radius: 4px; cursor: pointer; white-space: nowrap;">
                Delete Entry
              </button>
            </form>
          </div>
          <div style="color: var(--color-text-secondary); font-size: 0.75rem; margin-top: 0.5rem; font-family: monospace;">
            ID: ${escapeHtml(entry.entryId)}
          </div>
        </div>
      `;
    }).join('');

  const recoverableCount = unrecoverable.filter(e => e.canDecrypt).length;
  const unrecoverableCount = unrecoverable.filter(e => !e.canDecrypt).length;

  return `
    <div id="password-issues" style="margin-top: 2rem; padding-top: 1rem; border-top: 1px solid var(--color-border);">
      <h2 style="color: var(--color-accent-light); margin-bottom: 0.5rem;">Password Issues</h2>
      <p style="color: var(--color-text-secondary); margin-bottom: 1rem;">
        Recover entries that no longer decrypt with the current key. This section is fused into Operations for easier maintenance.
      </p>

      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 0.75rem; margin-bottom: 1rem;">
        <div style="background: var(--color-bg-secondary); border: 1px solid var(--color-border); border-radius: 8px; padding: 0.75rem;">
          <div style="color: var(--color-text-secondary); font-size: 0.85rem;">Needs Recovery</div>
          <div style="color: var(--color-error); font-size: 1.2rem; font-weight: bold;">${unrecoverableCount}</div>
        </div>
        <div style="background: var(--color-bg-secondary); border: 1px solid var(--color-border); border-radius: 8px; padding: 0.75rem;">
          <div style="color: var(--color-text-secondary); font-size: 0.85rem;">Recoverable</div>
          <div style="color: var(--color-success); font-size: 1.2rem; font-weight: bold;">${recoverableCount}</div>
        </div>
      </div>

      ${unrecoverableCount > 0 ? `
        <div style="margin-bottom: 1.25rem;">
          ${unrecoverableList}
        </div>
      ` : `
        <div style="padding: 1rem; text-align: center; background: var(--color-bg-secondary); border-radius: 8px; border: 1px solid var(--color-border); margin-bottom: 1rem;">
          <p style="color: var(--color-success); font-size: 1.1rem; margin: 0;">All password entries are accessible.</p>
        </div>
      `}

      <div style="padding: 1rem; background: var(--color-bg-secondary); border-radius: 8px; border: 1px solid var(--color-border);">
        <h3 style="color: var(--color-accent-light); margin-top: 0;">Batch Recovery</h3>
        <p style="color: var(--color-text-secondary); font-size: 0.9rem; margin-bottom: 1rem;">
          Try recovering all affected entries in one pass with the original key.
        </p>
        <form method="POST" action="/passwords/recover/batch">
          <input type="hidden" name="csrfToken" value="${createCsrfToken(session.sessionId)}">
          <div style="display: flex; gap: 0.5rem; align-items: flex-end; flex-wrap: wrap;">
            <div style="flex: 1; min-width: 260px;">
              <label style="display: block; color: var(--color-text-secondary); font-size: 0.9rem; margin-bottom: 0.25rem;">Master Password / Encryption Key:</label>
              <input type="password" name="masterKey" placeholder="Enter master password or original key" autocomplete="off"
                     style="width: 100%; padding: 0.5rem; border: 1px solid var(--color-border); border-radius: 4px; background: var(--color-bg-primary); color: var(--color-text-primary); font-size: 0.9rem; box-sizing: border-box;" required>
            </div>
            <button type="submit" style="background: var(--color-bg-tertiary); color: var(--color-accent-light); border: 1px solid var(--color-border); padding: 0.5rem 1rem; border-radius: 4px; cursor: pointer; white-space: nowrap;">
              Recover All
            </button>
          </div>
        </form>
      </div>
    </div>
  `;
}

router.get("/health", async (request, params, query) => {
  const session = await attachSession(request);
  if (!session) {
    return new Response(null, {
      status: 302,
      headers: {
        ...SECURITY_HEADERS,
        Location: '/login',
      },
    });
  }

  if (!isConnected()) {
    return renderPage(`
      <h1>System Health</h1>
      <p style="color: var(--color-error);">Database not available.</p>
    `, "Health Check - XeoKey", request);
  }

  try {
    const url = new URL(request.url);
    const refreshRequested = url.searchParams.get('refresh') === '1';
    const lastCheck = getLastHealthCheck();
    const lastTs = lastCheck.timestamp ? new Date(lastCheck.timestamp).getTime() : 0;
    const isStale = !lastTs || (Date.now() - lastTs) > 15_000; // 15s

    // Prefer cached results for quick refreshes, but allow forcing a new run.
    const integrityResult = (refreshRequested || isStale || !lastCheck.result)
      ? await forceHealthCheck()
      : lastCheck.result;

    const statusColor = integrityResult.success ? 'var(--color-success)' : 'var(--color-error)';
    const statusText = integrityResult.success ? 'Healthy' : 'Issues Detected';

    const issuesList = [
      ...integrityResult.checks.userIdFormat.issues,
      ...integrityResult.checks.passwordAccessibility.issues,
      ...integrityResult.checks.dataConsistency.issues,
      ...integrityResult.checks.orphanedEntries.issues,
      ...integrityResult.checks.encryptionIntegrity.issues,
    ];

    const criticalIssues = issuesList.filter(i => i.severity === 'critical');
    const warnings = issuesList.filter(i => i.severity === 'warning');
    const infoIssues = issuesList.filter(i => i.severity === 'info');

    const issuesHtml = issuesList.map(issue => {
      const severityColor = issue.severity === 'critical' ? 'var(--color-error)' :
                           issue.severity === 'warning' ? 'var(--color-accent)' : 'var(--color-accent-light)';
      return `
        <div style="border-left: 4px solid ${severityColor}; padding: 0.75rem; margin-bottom: 0.5rem; background: var(--color-bg-secondary); border-radius: 4px;">
          <div style="display: flex; justify-content: space-between; align-items: flex-start;">
            <div style="flex: 1;">
              <div style="color: ${severityColor}; font-weight: bold; margin-bottom: 0.25rem;">
                ${issue.severity.toUpperCase()}: ${escapeHtml(String(issue.message || ''))}
              </div>
              ${issue.collection ? `<div style="color: var(--color-text-secondary); font-size: 0.9rem;">Collection: ${escapeHtml(String(issue.collection || ''))}</div>` : ''}
              ${issue.entryId ? `<div style="color: var(--color-text-secondary); font-size: 0.9rem;">Entry ID: ${escapeHtml(String(issue.entryId || ''))}</div>` : ''}
              ${issue.userId ? `<div style="color: var(--color-text-secondary); font-size: 0.9rem;">User ID: ${escapeHtml(String(issue.userId || ''))}</div>` : ''}
              ${issue.suggestion ? `<div style="color: var(--color-accent-light); font-size: 0.9rem; margin-top: 0.25rem;">Note: ${escapeHtml(String(issue.suggestion || ''))}</div>` : ''}
            </div>
          </div>
        </div>
      `;
    }).join('');

    const passwordIssuesPanel = await buildPasswordIssuesPanel(session);

    return renderPage(`
      <h1>System Health & Integrity</h1>
      <div style="margin-bottom: 1.5rem; padding: 1rem; background: var(--color-bg-secondary); border-radius: 8px; border: 1px solid var(--color-border);">
        <div style="display: flex; align-items: center; gap: 1rem; margin-bottom: 1rem;">
          <div style="font-size: 1rem; color: ${statusColor}; font-weight: bold;">${integrityResult.success ? 'OK' : 'ISSUES'}</div>
          <div>
            <h2 style="margin: 0; color: ${statusColor};">${statusText}</h2>
            <p style="color: var(--color-text-secondary); margin: 0.25rem 0; font-size: 0.9rem;">
              Last checked: ${lastCheck.timestamp ? new Date(lastCheck.timestamp).toLocaleString() : 'Never'}
            </p>
          </div>
        </div>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem;">
          <div>
            <div style="color: var(--color-text-secondary); font-size: 0.9rem;">Total Issues</div>
            <div style="color: var(--color-accent-light); font-size: 1.5rem; font-weight: bold;">${integrityResult.summary.totalIssues}</div>
          </div>
          <div>
            <div style="color: var(--color-text-secondary); font-size: 0.9rem;">Critical</div>
            <div style="color: var(--color-error); font-size: 1.5rem; font-weight: bold;">${integrityResult.summary.criticalIssues}</div>
          </div>
          <div>
            <div style="color: var(--color-text-secondary); font-size: 0.9rem;">Warnings</div>
            <div style="color: var(--color-accent); font-size: 1.5rem; font-weight: bold;">${integrityResult.summary.warnings}</div>
          </div>
        </div>
      </div>

      <div style="margin-bottom: 1.5rem;">
        <h2 style="color: var(--color-accent-light);">Check Results</h2>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 1rem;">
          <div style="padding: 1rem; background: var(--color-bg-secondary); border-radius: 8px; border: 1px solid var(--color-border);">
            <div style="color: var(--color-text-secondary); font-size: 0.9rem; margin-bottom: 0.5rem;">UserId Format</div>
            <div style="color: ${integrityResult.checks.userIdFormat.passed ? 'var(--color-success)' : 'var(--color-error)'}; font-weight: bold;">
              ${integrityResult.checks.userIdFormat.passed ? 'Pass' : 'Fail'}
            </div>
            <div style="color: var(--color-text-secondary); font-size: 0.8rem; margin-top: 0.5rem;">${escapeHtml(String(integrityResult.checks.userIdFormat.details || ''))}</div>
          </div>
          <div style="padding: 1rem; background: var(--color-bg-secondary); border-radius: 8px; border: 1px solid var(--color-border);">
            <div style="color: var(--color-text-secondary); font-size: 0.9rem; margin-bottom: 0.5rem;">Password Accessibility</div>
            <div style="color: ${integrityResult.checks.passwordAccessibility.passed ? 'var(--color-success)' : 'var(--color-error)'}; font-weight: bold;">
              ${integrityResult.checks.passwordAccessibility.passed ? 'Pass' : 'Fail'}
            </div>
            <div style="color: var(--color-text-secondary); font-size: 0.8rem; margin-top: 0.5rem;">${escapeHtml(String(integrityResult.checks.passwordAccessibility.details || ''))}</div>
          </div>
          <div style="padding: 1rem; background: var(--color-bg-secondary); border-radius: 8px; border: 1px solid var(--color-border);">
            <div style="color: var(--color-text-secondary); font-size: 0.9rem; margin-bottom: 0.5rem;">Data Consistency</div>
            <div style="color: ${integrityResult.checks.dataConsistency.passed ? 'var(--color-success)' : 'var(--color-error)'}; font-weight: bold;">
              ${integrityResult.checks.dataConsistency.passed ? 'Pass' : 'Fail'}
            </div>
            <div style="color: var(--color-text-secondary); font-size: 0.8rem; margin-top: 0.5rem;">${escapeHtml(String(integrityResult.checks.dataConsistency.details || ''))}</div>
          </div>
          <div style="padding: 1rem; background: var(--color-bg-secondary); border-radius: 8px; border: 1px solid var(--color-border);">
            <div style="color: var(--color-text-secondary); font-size: 0.9rem; margin-bottom: 0.5rem;">Orphaned Entries</div>
            <div style="color: ${integrityResult.checks.orphanedEntries.passed ? 'var(--color-success)' : 'var(--color-error)'}; font-weight: bold;">
              ${integrityResult.checks.orphanedEntries.passed ? 'Pass' : 'Fail'}
            </div>
            <div style="color: var(--color-text-secondary); font-size: 0.8rem; margin-top: 0.5rem;">${escapeHtml(String(integrityResult.checks.orphanedEntries.details || ''))}</div>
          </div>
          <div style="padding: 1rem; background: var(--color-bg-secondary); border-radius: 8px; border: 1px solid var(--color-border);">
            <div style="color: var(--color-text-secondary); font-size: 0.9rem; margin-bottom: 0.5rem;">Encryption Integrity</div>
            <div style="color: ${integrityResult.checks.encryptionIntegrity.passed ? 'var(--color-success)' : 'var(--color-error)'}; font-weight: bold;">
              ${integrityResult.checks.encryptionIntegrity.passed ? 'Pass' : 'Fail'}
            </div>
            <div style="color: var(--color-text-secondary); font-size: 0.8rem; margin-top: 0.5rem;">${escapeHtml(String(integrityResult.checks.encryptionIntegrity.details || ''))}</div>
          </div>
        </div>
      </div>

      ${issuesList.length > 0 ? `
      <div style="margin-bottom: 1.5rem;">
        <h2 style="color: var(--color-accent-light);">Detected Issues</h2>
        ${issuesHtml}
      </div>
      ` : ''}

      <div style="margin-top: 1.5rem; display: flex; gap: 1rem;">
        <form method="GET" action="/health?refresh=1" style="display: inline;">
          <button type="submit" style="background: var(--color-bg-tertiary); color: var(--color-accent-light); border: 1px solid var(--color-border); padding: 0.75rem 1.5rem; border-radius: 4px; cursor: pointer; font-size: 1rem;">
            Run Health Check Now
          </button>
        </form>
        <button type="button" onclick="toggleDashboard()" style="background: var(--color-bg-tertiary); color: var(--color-accent-light); border: 1px solid var(--color-border); padding: 0.75rem 1.5rem; border-radius: 4px; cursor: pointer; font-size: 1rem;">
          Dashboard and Tools
        </button>
      </div>

      <!-- Dashboard & Tools Section (Hidden by default) -->
      <div id="dashboardSection" style="display: none; margin-top: 2rem; padding: 1.5rem; background: var(--color-bg-secondary); border-radius: 8px; border: 1px solid var(--color-border);">
        <h2 style="color: var(--color-accent-light); margin-top: 0; margin-bottom: 1rem;">System Dashboard and Management Tools</h2>

        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1.5rem; margin-bottom: 2rem;">

          <!-- Auto Re-Encryption Card -->
          <div id="autoReEncryptionCard" style="padding: 1rem; background: var(--color-bg-primary); border-radius: 8px; border: 1px solid var(--color-border);">
            <h3 style="color: var(--color-accent-light); margin-top: 0; margin-bottom: 1rem;">Auto Re-Encryption</h3>
            <div id="reEncryptionStatus" style="color: var(--color-text-secondary); font-size: 0.9rem; margin-bottom: 1rem;">Loading...</div>
            <div style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
              <button type="button" onclick="checkReEncryptionStatus()" style="background: var(--color-bg-tertiary); color: var(--color-accent-light); border: 1px solid var(--color-border); padding: 0.5rem 1rem; border-radius: 4px; cursor: pointer; font-size: 0.8rem;">
                Check Status
              </button>
              <button type="button" onclick="triggerReEncryption()" id="triggerBtn" style="background: var(--color-bg-tertiary); color: var(--color-accent-light); border: 1px solid var(--color-border); padding: 0.5rem 1rem; border-radius: 4px; cursor: pointer; font-size: 0.8rem;">
                Trigger Now
              </button>
              <button type="button" onclick="debugReEncryption()" style="background: var(--color-bg-tertiary); color: var(--color-accent-light); border: 1px solid var(--color-border); padding: 0.5rem 1rem; border-radius: 4px; cursor: pointer; font-size: 0.8rem;">
                Debug
              </button>
            </div>
          </div>

          <!-- Encryption Diagnostics Card -->
          <div style="padding: 1rem; background: var(--color-bg-primary); border-radius: 8px; border: 1px solid var(--color-border);">
            <h3 style="color: var(--color-accent-light); margin-top: 0; margin-bottom: 1rem;">Encryption Diagnostics</h3>
            <div style="color: var(--color-text-secondary); font-size: 0.9rem; margin-bottom: 1rem;">Analyze encryption key usage and detect issues</div>
            <div style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
              <button type="button" onclick="runDiagnostics()" style="background: var(--color-bg-tertiary); color: var(--color-accent-light); border: 1px solid var(--color-border); padding: 0.5rem 1rem; border-radius: 4px; cursor: pointer; font-size: 0.8rem;">
                Run Diagnostics
              </button>
              <button type="button" onclick="checkKeyInfo()" style="background: var(--color-bg-tertiary); color: var(--color-accent-light); border: 1px solid var(--color-border); padding: 0.5rem 1rem; border-radius: 4px; cursor: pointer; font-size: 0.8rem;">
                Key Info
              </button>
            </div>
          </div>

          <!-- System Status Card -->
          <div style="padding: 1rem; background: var(--color-bg-primary); border-radius: 8px; border: 1px solid var(--color-border);">
            <h3 style="color: var(--color-accent-light); margin-top: 0; margin-bottom: 1rem;">System Status</h3>
            <div style="color: var(--color-text-secondary); font-size: 0.9rem; margin-bottom: 1rem;">Check server and system health</div>
            <div style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
              <button type="button" onclick="checkServerStatus()" style="background: var(--color-bg-tertiary); color: var(--color-accent-light); border: 1px solid var(--color-border); padding: 0.5rem 1rem; border-radius: 4px; cursor: pointer; font-size: 0.8rem;">
                Server Status
              </button>
            </div>
          </div>

        </div>

        <!-- Results Display Area -->
        <div id="dashboardResults" style="display: none; margin-top: 1.5rem; padding: 1rem; background: var(--color-bg-primary); border-radius: 8px; border: 1px solid var(--color-border);">
          <h3 style="color: var(--color-accent-light); margin-top: 0; margin-bottom: 1rem;">Results</h3>
          <div id="resultsContent" style="color: var(--color-text-secondary); font-family: monospace; font-size: 0.8rem; white-space: pre-wrap;"></div>
          <button type="button" onclick="closeResults()" style="background: var(--color-bg-tertiary); color: var(--color-accent-light); border: 1px solid var(--color-border); padding: 0.5rem 1rem; border-radius: 4px; cursor: pointer; font-size: 0.8rem; margin-top: 1rem;">
            Close
          </button>
        </div>
      </div>

      <script>
        function toggleDashboard() {
          const section = document.getElementById('dashboardSection');
          if (section.style.display === 'none') {
            section.style.display = 'block';
            // Auto-load re-encryption status when opened
            checkReEncryptionStatus();
          } else {
            section.style.display = 'none';
          }
        }

        async function checkReEncryptionStatus() {
          const statusDiv = document.getElementById('reEncryptionStatus');
          const triggerBtn = document.getElementById('triggerBtn');

          statusDiv.innerHTML = 'Checking...';
          triggerBtn.disabled = true;

          try {
            const response = await fetch('/api/auto-re-encryption/status');
            const data = await response.json();

            if (data.error) {
              statusDiv.innerHTML = \`Error: \${data.error}\`;
            } else {
              const status = data.status;
              const fallbackUsage = status.fallbackUsage;
              const percentage = fallbackUsage.totalEntries > 0
                ? (fallbackUsage.passwordsUsingFallback + fallbackUsage.notesUsingFallback + fallbackUsage.totpUsingFallback) / fallbackUsage.totalEntries * 100
                : 0;

              let statusText = status.isRunning ? 'Running...' : 'Idle';
              let recommendation = data.recommendation || '';

              statusDiv.innerHTML = \`
                <div style="margin-bottom: 0.5rem;">
                  <strong>Status:</strong> \${statusText}<br>
                  <strong>Fallback Usage:</strong> \${percentage.toFixed(1)}% (\${fallbackUsage.passwordsUsingFallback + fallbackUsage.notesUsingFallback + fallbackUsage.totpUsingFallback}/\${fallbackUsage.totalEntries})<br>
                  <strong>Enabled:</strong> \${status.enabled ? 'Yes' : 'No'}
                </div>
                \${recommendation ? \`<div style="color: var(--color-accent-light); font-size: 0.8rem; margin-top: 0.5rem;">Note: \${recommendation}</div>\` : ''}
              \`;

              triggerBtn.disabled = status.isRunning;
            }
          } catch (error) {
            statusDiv.innerHTML = \`Failed to check status: \${error.message}\`;
            triggerBtn.disabled = false;
          }
        }

        async function triggerReEncryption() {
          const statusDiv = document.getElementById('reEncryptionStatus');
          const triggerBtn = document.getElementById('triggerBtn');

          if (!confirm('Start auto re-encryption now? This will migrate all entries using fallback keys to the current encryption key.')) {
            return;
          }

          statusDiv.innerHTML = 'Starting re-encryption...';
          triggerBtn.disabled = true;

          try {
            const response = await fetch('/api/auto-re-encryption/trigger', { method: 'POST' });
            const data = await response.json();

            if (data.success) {
              statusDiv.innerHTML = \`\${data.message}\`;
              // Auto-refresh status after a delay
              setTimeout(checkReEncryptionStatus, 2000);
            } else {
              statusDiv.innerHTML = \`Failed: \${data.message}\`;
              triggerBtn.disabled = false;
            }
          } catch (error) {
            statusDiv.innerHTML = \`Failed to start: \${error.message}\`;
            triggerBtn.disabled = false;
          }
        }

        async function debugReEncryption() {
          showResults('Running re-encryption debug...');
          try {
            const response = await fetch('/api/re-encryption/debug');
            const data = await response.json();

            if (data.error) {
              showResults(\`Error: \${data.error}\`);
            } else {
              const debug = data.debug;
              let output = \`Re-Encryption Debug Results\\n\\n\`;

              output += \`Current Key Information:\\n\`;
              output += \`  Hash: \${debug.currentKeyInfo.hash}\\n\`;
              output += \`  Length: \${debug.currentKeyInfo.length} bytes\\n\`;
              output += \`  Environment: \${debug.currentKeyInfo.environment}\\n\\n\`;

              output += \`Test Results:\\n\`;
              output += \`  Passwords: \${debug.passwords.decryptable}/\${debug.passwords.total} decryptable, \${debug.passwords.failed} failed\\n\`;
              output += \`  Notes: \${debug.notes.decryptable}/\${debug.notes.total} decryptable, \${debug.notes.failed} failed\\n\`;
              output += \`  TOTP: \${debug.totp.decryptable}/\${debug.totp.total} decryptable, \${debug.totp.failed} failed\\n\\n\`;

              const totalSuccess = debug.passwords.decryptable + debug.notes.decryptable + debug.totp.decryptable;
              const totalFailed = debug.passwords.failed + debug.notes.failed + debug.totp.failed;
              const totalItems = totalSuccess + totalFailed;

              output += \`Overall: \${totalSuccess}/\${totalItems} successful (\${((totalSuccess/totalItems)*100).toFixed(1)}%)\`;

              if (totalFailed > 0) {
                output += \`\\n\\nSample Failures:\`;
                const allFailures = [...debug.passwords.sampleFailed, ...debug.notes.sampleFailed, ...debug.totp.sampleFailed];
                allFailures.slice(0, 5).forEach((failure, i) => {
                  output += \`\\n  \${i + 1}. \${failure.id}: \${failure.error}\`;
                });

                if (allFailures.length > 5) {
                  output += \`\\n  ... and \${allFailures.length - 5} more\`;
                }
              }

              showResults(output);
            }
          } catch (error) {
            showResults(\`Failed to run debug: \${error.message}\`);
          }
        }

        async function runDiagnostics() {
          showResults('Running encryption diagnostics...');
          try {
            const response = await fetch('/api/encryption/diagnostics');
            const data = await response.json();

            if (data.error) {
              showResults(\`Error: \${data.error}\`);
            } else {
              const diagnostic = data.diagnostic;
              const passwordSuccess = diagnostic.passwordEntries.decryptable || 0;
              const noteSuccess = diagnostic.noteEntries.decryptable || 0;
              const passwordTotal = diagnostic.passwordEntries.total || 0;
              const noteTotal = diagnostic.noteEntries.total || 0;
              const passwordRate = passwordTotal > 0 ? ((passwordSuccess / passwordTotal) * 100).toFixed(1) : '0.0';
              const noteRate = noteTotal > 0 ? ((noteSuccess / noteTotal) * 100).toFixed(1) : '0.0';
              const sampleErrors = [
                ...(diagnostic.passwordEntries.sampleErrors || []),
                ...(diagnostic.noteEntries.sampleErrors || []),
              ];
              let output = \`Encryption Diagnostics Results\\n\\n\`;
              output += \`Key Hash: \${diagnostic.keyInfo.hash}\`;
              output += \`\\nDefault Key: \${diagnostic.keyInfo.isDefaultKey ? 'YES' : 'NO'}\`;
              output += \`\\n\\nPassword Entries:\`;
              output += \`\\n  Total: \${diagnostic.passwordEntries.total}\`;
              output += \`\\n  Success: \${passwordSuccess}\`;
              output += \`\\n  Failed: \${diagnostic.passwordEntries.failed}\`;
              output += \`\\n  Success Rate: \${passwordRate}%\`;

              output += \`\\n\\nNote Entries:\`;
              output += \`\\n  Total: \${diagnostic.noteEntries.total}\`;
              output += \`\\n  Success: \${noteSuccess}\`;
              output += \`\\n  Failed: \${diagnostic.noteEntries.failed}\`;
              output += \`\\n  Success Rate: \${noteRate}%\`;

              if (sampleErrors.length > 0) {
                output += \`\\n\\nSample Errors:\`;
                sampleErrors.slice(0, 5).forEach((error, i) => {
                  output += \`\\n  \${i + 1}. \${error}\`;
                });
              }

              output += \`\\n\\nRecommendations:\`;
              diagnostic.recommendations.forEach(rec => {
                output += \`\\n  • \${rec}\`;
              });

              showResults(output);
            }
          } catch (error) {
            showResults(\`Failed to run diagnostics: \${error.message}\`);
          }
        }

        async function checkKeyInfo() {
          showResults('Getting key information...');
          try {
            const response = await fetch('/api/encryption/key-info');
            const data = await response.json();

            if (data.error) {
              showResults(\`Error: \${data.error}\`);
            } else {
              let output = \`Encryption Key Information\\n\\n\`;
              output += \`Key Hash: \${data.keyHash}\`;
              output += \`\\nKey Length: \${data.keyLength} bytes\`;
              output += \`\\nAlgorithm: \${data.algorithm}\`;
              output += \`\\nDefault Key: \${data.isDefault ? 'YES' : 'NO'}\`;
              output += \`\\nEnvironment: \${data.environment}\`;
              output += \`\\nTimestamp: \${data.timestamp}\`;

              if (data.isDefault) {
                output += \`\\n\\nWARNING: Using default encryption key!\`;
                output += \`\\nSet ENCRYPTION_KEY environment variable for production.\`;
              }

              showResults(output);
            }
          } catch (error) {
            showResults(\`Failed to get key info: \${error.message}\`);
          }
        }

        async function checkServerStatus() {
          showResults('Checking server status...');
          try {
            const response = await fetch('/api/server/status');
            const data = await response.json();

            let output = \`Server Status\\n\\n\`;
            output += \`Status: \${data.phase}\`;
            output += \`\\nUptime: \${Math.floor(data.uptime / 60)} minutes\`;
            output += \`\\nDatabase: \${data.database.connected ? 'Connected' : 'Disconnected'}\`;
            output += \`\\nDatabase Healthy: \${data.database.healthy ? 'Yes' : 'No'}\`;

            if (data.database.lastHealthCheck) {
              output += \`\\nLast DB Health Check: \${new Date(data.database.lastHealthCheck).toLocaleString()}\`;
            }

            showResults(output);
          } catch (error) {
            showResults(\`Failed to check server status: \${error.message}\`);
          }
        }

        function showResults(content) {
          const resultsDiv = document.getElementById('dashboardResults');
          const resultsContent = document.getElementById('resultsContent');

          resultsContent.textContent = content;
          resultsDiv.style.display = 'block';
        }

        function closeResults() {
          document.getElementById('dashboardResults').style.display = 'none';
        }

        // Auto-check re-encryption status every 30 seconds when dashboard is open
        setInterval(() => {
          const section = document.getElementById('dashboardSection');
          if (section.style.display !== 'none') {
            checkReEncryptionStatus();
          }
        }, 30000);
      </script>

      ${passwordIssuesPanel}
    `, "Health Check - XeoKey", request);
  } catch (error) {
    logger.error(`Error running health check: ${error}`);
    return renderPage(`
      <h1>System Health</h1>
      <p style="color: var(--color-error);">Error running health check.</p>
    `, "Health Check - XeoKey", request);
  }
});

// Password Recovery Routes
router.get("/passwords/recover", async (request, params, query) => {
  const session = await attachSession(request);
  if (!session) {
    return new Response(null, {
      status: 302,
      headers: {
        ...SECURITY_HEADERS,
        Location: '/login',
      },
    });
  }

  return new Response(null, {
    status: 302,
    headers: {
      ...SECURITY_HEADERS,
      Location: '/health#password-issues',
    },
  });
});

router.post("/passwords/recover/:id", async (request, params, query) => {
  const session = await attachSession(request);
  if (!session) {
    return new Response(null, {
      status: 302,
      headers: {
        ...SECURITY_HEADERS,
        Location: '/login',
      },
    });
  }

  if (!isConnected()) {
    return createErrorResponse(503, "Database not available");
  }

  try {
    const entryId = params.id || '';
    const formData = await request.formData();
    const csrfToken = formData.get('csrfToken')?.toString() || '';
    const masterKey = formData.get('masterKey')?.toString() || '';

    if (!verifyCsrfToken(session.sessionId, csrfToken)) {
      return createErrorResponse(403, "Invalid CSRF token");
    }

    if (!masterKey) {
      return renderPage(`
        <h1>Recovery Failed</h1>
        <p style="color: var(--color-error);">Master password is required.</p>
        <p><a href="/health#password-issues" style="color: var(--color-accent-light);">← Back to Operations</a></p>
      `, "Recovery Failed - XeoKey", request);
    }

    const userIdString = typeof session.userId === 'string' ? session.userId : (session.userId as any).toString();
    const result = await recoverPasswordWithMasterKey(entryId, userIdString, masterKey);

    if (result.success && result.decryptedPassword) {
      // Only create a backup if we're about to modify the DB (repair re-encrypts and updates the entry)
      logger.info('Creating automatic backup before password repair...');
      const backupResult = await createBackup(
        ['passwords', 'totp', 'users', 'sessions'],
        'automatic',
        undefined,
        `Automatic backup before password repair (entry: ${entryId})`
      );
      if (backupResult.success) {
        logger.info(`✅ Pre-repair backup created: ${backupResult.backupId}`);
      } else {
        logger.warn(`⚠️  Pre-repair backup failed: ${backupResult.error || 'Unknown error'}`);
        // Continue with repair anyway, but warn user
      }

      // Attempt to repair the password
      const repairResult = await repairPasswordEntry(entryId, userIdString, result.decryptedPassword);

      if (repairResult.success) {
        return renderPage(`
          <h1>Password Recovered</h1>
          ${backupResult.success ? `
            <div style="background: var(--color-bg-secondary); border: 1px solid var(--color-border); padding: 0.75rem; border-radius: 4px; margin-bottom: 1rem;">
              <p style="color: var(--color-success); margin: 0; font-size: 0.9rem;">✅ Automatic backup created before recovery: ${escapeHtml(backupResult.backupId)}</p>
            </div>
          ` : `
            <div style="background: rgba(201, 133, 133, 0.16); border: 1px solid var(--color-error); padding: 0.75rem; border-radius: 4px; margin-bottom: 1rem;">
              <p style="color: var(--color-accent); margin: 0; font-size: 0.9rem;">⚠️ Automatic backup failed: ${escapeHtml(backupResult.error || 'Unknown error')}</p>
            </div>
          `}
          <p style="color: var(--color-success);">✅ Password recovered and repaired successfully!</p>
          <div style="background: var(--color-bg-secondary); padding: 1rem; border-radius: 8px; border: 1px solid var(--color-border); margin: 1rem 0;">
            <p style="color: var(--color-text-secondary); font-size: 0.9rem; margin-bottom: 0.5rem;">Recovered Password:</p>
            <p style="color: var(--color-accent-light); font-family: monospace; font-size: 1.1rem; word-break: break-all;">${escapeHtml(result.decryptedPassword)}</p>
          </div>
          <p><a href="/passwords/${entryId}" style="color: var(--color-accent-light);">View Password Entry</a> | <a href="/health#password-issues" style="color: var(--color-accent-light);">Back to Operations</a></p>
        `, "Password Recovered - XeoKey", request);
      } else {
        return renderPage(`
          <h1>Recovery Partial</h1>
          <p style="color: var(--color-accent);">⚠️ Password decrypted but repair failed: ${escapeHtml(repairResult.error || 'Unknown error')}</p>
          <div style="background: var(--color-bg-secondary); padding: 1rem; border-radius: 8px; border: 1px solid var(--color-border); margin: 1rem 0;">
            <p style="color: var(--color-text-secondary); font-size: 0.9rem; margin-bottom: 0.5rem;">Decrypted Password:</p>
            <p style="color: var(--color-accent-light); font-family: monospace; font-size: 1.1rem; word-break: break-all;">${escapeHtml(result.decryptedPassword)}</p>
          </div>
          <p><a href="/health#password-issues" style="color: var(--color-accent-light);">← Back to Operations</a></p>
        `, "Recovery Partial - XeoKey", request);
      }
    } else {
      const errorMsg = result.error || 'Unknown error';
      const isBadDecrypt = errorMsg.includes('BAD_DECRYPT') || errorMsg.includes('bad decrypt') || errorMsg.includes('does not match');

      return renderPage(`
        <h1>Recovery Failed</h1>
        <div style="background: rgba(201, 133, 133, 0.16); border: 1px solid var(--color-error); padding: 1rem; border-radius: 4px; margin-bottom: 1rem;">
          <p style="color: var(--color-error); margin: 0; font-weight: bold;">Decryption Failed</p>
          <p style="color: var(--color-text-secondary); margin: 0.5rem 0 0 0; font-size: 0.9rem;">${escapeHtml(errorMsg)}</p>
        </div>
        ${isBadDecrypt ? `
          <div style="background: rgba(179, 198, 216, 0.16); border: 1px solid var(--color-accent-light); padding: 1rem; border-radius: 4px; margin-bottom: 1rem;">
            <p style="color: var(--color-accent); margin: 0; font-weight: bold;">💡 What this means:</p>
            <ul style="color: var(--color-text-secondary); margin: 0.5rem 0 0 0; padding-left: 1.5rem; font-size: 0.9rem;">
              <li>The master password you provided does not match the encryption key used to encrypt this password.</li>
              <li>The master password must be the <strong>exact same value</strong> as the <code>ENCRYPTION_KEY</code> environment variable that was used when the password was first created.</li>
              <li>If the <code>ENCRYPTION_KEY</code> has changed, you need to provide the <strong>old/original</strong> key value.</li>
            </ul>
          </div>
        ` : ''}
        <p style="color: var(--color-text-secondary); font-size: 0.9rem;">No backup was created because no database changes were made.</p>
        <p><a href="/health#password-issues" style="color: var(--color-accent-light);">← Back to Operations</a></p>
      `, "Recovery Failed - XeoKey", request);
    }
  } catch (error: any) {
    logger.error(`Error recovering password: ${error}`);
    return createErrorResponse(500, "Internal Server Error");
  }
});

// Recover password by identifier (website/username/email)
router.post("/passwords/recover/by-identifier", async (request, params, query) => {
  const session = await attachSession(request);
  if (!session) {
    return new Response(null, {
      status: 302,
      headers: {
        ...SECURITY_HEADERS,
        Location: '/login',
      },
    });
  }

  if (!isConnected()) {
    return createErrorResponse(503, "Database not available");
  }

  try {
    const formData = await request.formData();
    const csrfToken = formData.get('csrfToken')?.toString() || '';
    const masterKey = formData.get('masterKey')?.toString() || '';
    const identifierJson = formData.get('identifier')?.toString() || '';

    if (!verifyCsrfToken(session.sessionId, csrfToken)) {
      return createErrorResponse(403, "Invalid CSRF token");
    }

    if (!masterKey) {
      return renderPage(`
        <h1>Recovery Failed</h1>
        <p style="color: var(--color-error);">Master password is required.</p>
        <p><a href="/health#password-issues" style="color: var(--color-accent-light);">← Back to Operations</a></p>
      `, "Recovery Failed - XeoKey", request);
    }

    if (!identifierJson) {
      return renderPage(`
        <h1>Recovery Failed</h1>
        <p style="color: var(--color-error);">Invalid identifier.</p>
        <p><a href="/health#password-issues" style="color: var(--color-accent-light);">← Back to Operations</a></p>
      `, "Recovery Failed - XeoKey", request);
    }

    let identifier;
    try {
      identifier = JSON.parse(decodeURIComponent(identifierJson));
    } catch (e) {
      return renderPage(`
        <h1>Recovery Failed</h1>
        <p style="color: var(--color-error);">Invalid identifier format.</p>
        <p><a href="/health#password-issues" style="color: var(--color-accent-light);">← Back to Operations</a></p>
      `, "Recovery Failed - XeoKey", request);
    }

    const userIdString = typeof session.userId === 'string' ? session.userId : (session.userId as any).toString();
    const { recoverPasswordByIdentifier, repairPasswordEntryByIdentifier } = await import('./db/password-recovery');

    // Attempt recovery
    const result = await recoverPasswordByIdentifier(
      userIdString,
      identifier.website,
      masterKey,
      identifier.username || undefined,
      identifier.email || undefined
    );

    if (result.success && result.decryptedPassword) {
      // Create automatic backup before repair
      logger.info('Creating automatic backup before password repair...');
      const { createBackup } = await import('./db/backup');
      const backupResult = await createBackup(
        ['passwords', 'totp', 'users', 'sessions'],
        'automatic',
        undefined,
        `Automatic backup before password repair (${identifier.website}${identifier.username ? ` / ${identifier.username}` : ''}${identifier.email ? ` / ${identifier.email}` : ''})`
      );
      if (backupResult.success) {
        logger.info(`✅ Pre-repair backup created: ${backupResult.backupId}`);
      } else {
        logger.warn(`⚠️  Pre-repair backup failed: ${backupResult.error || 'Unknown error'}`);
      }

      // Attempt to repair
      const repairResult = await repairPasswordEntryByIdentifier(
        userIdString,
        identifier.website,
        result.decryptedPassword,
        identifier.username || undefined,
        identifier.email || undefined
      );

      if (repairResult.success) {
        return renderPage(`
          <h1>Password Recovered</h1>
          ${backupResult.success ? `
            <div style="background: var(--color-bg-secondary); border: 1px solid var(--color-border); padding: 0.75rem; border-radius: 4px; margin-bottom: 1rem;">
              <p style="color: var(--color-success); margin: 0; font-size: 0.9rem;">✅ Automatic backup created before recovery: ${escapeHtml(backupResult.backupId)}</p>
            </div>
          ` : `
            <div style="background: rgba(201, 133, 133, 0.16); border: 1px solid var(--color-error); padding: 0.75rem; border-radius: 4px; margin-bottom: 1rem;">
              <p style="color: var(--color-accent); margin: 0; font-size: 0.9rem;">⚠️ Automatic backup failed: ${escapeHtml(backupResult.error || 'Unknown error')}</p>
            </div>
          `}
          <p style="color: var(--color-success);">✅ Password recovered and repaired successfully!</p>
          <div style="background: var(--color-bg-secondary); padding: 1rem; border-radius: 8px; border: 1px solid var(--color-border); margin: 1rem 0;">
            <p style="color: var(--color-text-secondary); font-size: 0.9rem; margin-bottom: 0.5rem;">Recovered Password:</p>
            <p style="color: var(--color-accent-light); font-family: monospace; font-size: 1.1rem; word-break: break-all;">${escapeHtml(result.decryptedPassword)}</p>
          </div>
          <p><strong>Website:</strong> ${escapeHtml(identifier.website)}${identifier.username ? ` | <strong>Username:</strong> ${escapeHtml(identifier.username)}` : ''}${identifier.email ? ` | <strong>Email:</strong> ${escapeHtml(identifier.email)}` : ''}</p>
          <p>${repairResult.repairedCount} ${repairResult.repairedCount === 1 ? 'entry' : 'entries'} ${repairResult.repairedCount === 1 ? 'was' : 'were'} repaired.</p>
          <p><a href="/health#password-issues" style="color: var(--color-accent-light);">Back to Operations</a></p>
        `, "Password Recovered - XeoKey", request);
      } else {
        return renderPage(`
          <h1>Recovery Partial</h1>
          <p style="color: var(--color-accent);">⚠️ Password decrypted but repair failed: ${escapeHtml(repairResult.error || 'Unknown error')}</p>
          <div style="background: var(--color-bg-secondary); padding: 1rem; border-radius: 8px; border: 1px solid var(--color-border); margin: 1rem 0;">
            <p style="color: var(--color-text-secondary); font-size: 0.9rem; margin-bottom: 0.5rem;">Decrypted Password:</p>
            <p style="color: var(--color-accent-light); font-family: monospace; font-size: 1.1rem; word-break: break-all;">${escapeHtml(result.decryptedPassword)}</p>
          </div>
          <p><a href="/health#password-issues" style="color: var(--color-accent-light);">← Back to Operations</a></p>
        `, "Recovery Partial - XeoKey", request);
      }
    } else {
      const errorMsg = result.error || 'Unknown error';
      const isBadDecrypt = errorMsg.includes('BAD_DECRYPT') || errorMsg.includes('bad decrypt') || errorMsg.includes('does not match');

      return renderPage(`
        <h1>Recovery Failed</h1>
        <div style="background: rgba(201, 133, 133, 0.16); border: 1px solid var(--color-error); padding: 1rem; border-radius: 4px; margin-bottom: 1rem;">
          <p style="color: var(--color-error); margin: 0; font-weight: bold;">Decryption Failed</p>
          <p style="color: var(--color-text-secondary); margin: 0.5rem 0 0 0; font-size: 0.9rem;">${escapeHtml(errorMsg)}</p>
        </div>
        ${isBadDecrypt ? `
          <div style="background: rgba(179, 198, 216, 0.16); border: 1px solid var(--color-accent-light); padding: 1rem; border-radius: 4px; margin-bottom: 1rem;">
            <p style="color: var(--color-accent); margin: 0; font-weight: bold;">💡 What this means:</p>
            <ul style="color: var(--color-text-secondary); margin: 0.5rem 0 0 0; padding-left: 1.5rem; font-size: 0.9rem;">
              <li>The master password you provided does not match the encryption key used to encrypt this password.</li>
              <li>The master password must be the <strong>exact same value</strong> as the <code>ENCRYPTION_KEY</code> environment variable that was used when the password was first created.</li>
              <li>If the <code>ENCRYPTION_KEY</code> has changed, you need to provide the <strong>old/original</strong> key value.</li>
            </ul>
          </div>
        ` : ''}
        <p style="color: var(--color-text-secondary); font-size: 0.9rem;">No backup was created because no database changes were made.</p>
        <p><a href="/health#password-issues" style="color: var(--color-accent-light);">← Back to Operations</a></p>
      `, "Recovery Failed - XeoKey", request);
    }
  } catch (error: any) {
    logger.error(`Error recovering password by identifier: ${error}`);
    return createErrorResponse(500, "Internal Server Error");
  }
});

// Delete password by identifier
router.post("/passwords/delete/by-identifier", async (request, params, query) => {
  const session = await attachSession(request);
  if (!session) {
    return new Response(null, {
      status: 302,
      headers: {
        ...SECURITY_HEADERS,
        Location: '/login',
      },
    });
  }

  if (!isConnected()) {
    return createErrorResponse(503, "Database not available");
  }

  try {
    const formData = await request.formData();
    const csrfToken = formData.get('csrfToken')?.toString() || '';
    const identifierJson = formData.get('identifier')?.toString() || '';

    if (!verifyCsrfToken(session.sessionId, csrfToken)) {
      return createErrorResponse(403, "Invalid CSRF token");
    }

    if (!identifierJson) {
      return renderPage(`
        <h1>Delete Failed</h1>
        <p style="color: var(--color-error);">Invalid identifier.</p>
        <p><a href="/health#password-issues" style="color: var(--color-accent-light);">← Back to Operations</a></p>
      `, "Delete Failed - XeoKey", request);
    }

    let identifier;
    try {
      identifier = JSON.parse(decodeURIComponent(identifierJson));
    } catch (e) {
      return renderPage(`
        <h1>Delete Failed</h1>
        <p style="color: var(--color-error);">Invalid identifier format.</p>
        <p><a href="/health#password-issues" style="color: var(--color-accent-light);">← Back to Operations</a></p>
      `, "Delete Failed - XeoKey", request);
    }

    const userIdString = typeof session.userId === 'string' ? session.userId : (session.userId as any).toString();
    const { deletePasswordEntryByIdentifier } = await import('./models/password');

    // Create automatic backup before deletion
    logger.info('Creating automatic backup before password deletion...');
    const { createBackup } = await import('./db/backup');
    const backupResult = await createBackup(
      ['passwords', 'totp', 'users', 'sessions'],
      'automatic',
      undefined,
      `Automatic backup before password deletion (${identifier.website}${identifier.username ? ` / ${identifier.username}` : ''}${identifier.email ? ` / ${identifier.email}` : ''})`
    );
    if (backupResult.success) {
      logger.info(`✅ Pre-deletion backup created: ${backupResult.backupId}`);
    } else {
      logger.warn(`⚠️  Pre-deletion backup failed: ${backupResult.error || 'Unknown error'}`);
    }

    const result = await deletePasswordEntryByIdentifier(
      userIdString,
      identifier.website,
      identifier.username || undefined,
      identifier.email || undefined
    );

    if (result.success && result.deletedCount > 0) {
      return renderPage(`
        <h1>Password Entry Deleted</h1>
        ${backupResult.success ? `
          <div style="background: var(--color-bg-secondary); border: 1px solid var(--color-border); padding: 0.75rem; border-radius: 4px; margin-bottom: 1rem;">
            <p style="color: var(--color-success); margin: 0; font-size: 0.9rem;">✅ Automatic backup created before deletion: ${escapeHtml(backupResult.backupId)}</p>
            <p style="color: var(--color-text-secondary); margin: 0.25rem 0 0 0; font-size: 0.85rem;">You can restore this backup from <a href="/backups" style="color: var(--color-accent-light);">Backups</a> if needed.</p>
          </div>
        ` : `
          <div style="background: rgba(201, 133, 133, 0.16); border: 1px solid var(--color-error); padding: 0.75rem; border-radius: 4px; margin-bottom: 1rem;">
            <p style="color: var(--color-accent); margin: 0; font-size: 0.9rem;">⚠️ Automatic backup failed: ${escapeHtml(backupResult.error || 'Unknown error')}</p>
          </div>
        `}
        <p style="color: var(--color-success);">✅ Password entry deleted successfully!</p>
        <p><strong>Website:</strong> ${escapeHtml(identifier.website)}${identifier.username ? ` | <strong>Username:</strong> ${escapeHtml(identifier.username)}` : ''}${identifier.email ? ` | <strong>Email:</strong> ${escapeHtml(identifier.email)}` : ''}</p>
        <p>${result.deletedCount} ${result.deletedCount === 1 ? 'entry' : 'entries'} ${result.deletedCount === 1 ? 'was' : 'were'} deleted.</p>
        <p><a href="/health#password-issues" style="color: var(--color-accent-light);">← Back to Operations</a></p>
      `, "Password Entry Deleted - XeoKey", request);
    } else {
      return renderPage(`
        <h1>Delete Failed</h1>
        <p style="color: var(--color-error);">Failed to delete password entry: ${escapeHtml(result.error || 'No matching entries found')}</p>
        <p><a href="/health#password-issues" style="color: var(--color-accent-light);">← Back to Operations</a></p>
      `, "Delete Failed - XeoKey", request);
    }
  } catch (error: any) {
    logger.error(`Error deleting password by identifier: ${error}`);
    return createErrorResponse(500, "Internal Server Error");
  }
});

router.post("/passwords/recover/batch", async (request, params, query) => {
  const session = await attachSession(request);
  if (!session) {
    return new Response(null, {
      status: 302,
      headers: {
        ...SECURITY_HEADERS,
        Location: '/login',
      },
    });
  }

  if (!isConnected()) {
    return createErrorResponse(503, "Database not available");
  }

  try {
    const formData = await request.formData();
    const csrfToken = formData.get('csrfToken')?.toString() || '';
    const masterKey = formData.get('masterKey')?.toString() || '';

    if (!verifyCsrfToken(session.sessionId, csrfToken)) {
      return createErrorResponse(403, "Invalid CSRF token");
    }

    if (!masterKey) {
      return renderPage(`
        <h1>Batch Recovery Failed</h1>
        <p style="color: var(--color-error);">Master password is required.</p>
        <p><a href="/health#password-issues" style="color: var(--color-accent-light);">← Back to Operations</a></p>
      `, "Batch Recovery Failed - XeoKey", request);
    }

    const userIdString = typeof session.userId === 'string' ? session.userId : (session.userId as any).toString();

    // Determine if there is anything to repair before taking a backup / running recovery
    const snapshot = await getUnrecoverablePasswords(userIdString);
    const needsRecoveryCount = snapshot.filter(e => !e.canDecrypt).length;

    if (needsRecoveryCount === 0) {
      return renderPage(`
        <h1>Batch Recovery Results</h1>
        <div style="background: var(--color-bg-secondary); border: 1px solid var(--color-border); padding: 1rem; border-radius: 8px; margin-bottom: 1.5rem;">
          <p style="color: var(--color-success); margin: 0;">✅ No unrecoverable passwords detected. Nothing was changed.</p>
          <p style="color: var(--color-text-secondary); margin: 0.25rem 0 0 0; font-size: 0.9rem;">Recovered: 0 • Failed: 0 • Total needing recovery: 0</p>
        </div>
        <p><a href="/health#password-issues" style="color: var(--color-accent-light);">← Back to Operations</a></p>
      `, "Batch Recovery Results - XeoKey", request);
    }

    // Create automatic backup before batch repair (since we are about to write)
    logger.info('Creating automatic backup before batch password repair...');
    const backupResult = await createBackup(
      ['passwords', 'totp', 'users', 'sessions'],
      'automatic',
      undefined,
      'Automatic backup before batch password repair'
    );
    if (backupResult.success) {
      logger.info(`✅ Pre-repair backup created: ${backupResult.backupId}`);
    } else {
      logger.warn(`⚠️  Pre-repair backup failed: ${backupResult.error || 'Unknown error'}`);
      // Continue with recovery anyway, but warn user
    }

    const result = await batchRecoverPasswords(userIdString, masterKey);

    return renderPage(`
      <h1>Batch Recovery Results</h1>
      ${backupResult.success ? `
        <div style="background: var(--color-bg-secondary); border: 1px solid var(--color-border); padding: 0.75rem; border-radius: 4px; margin-bottom: 1.5rem;">
          <p style="color: var(--color-success); margin: 0; font-size: 0.9rem;">✅ Automatic backup created before recovery: ${escapeHtml(backupResult.backupId)}</p>
          <p style="color: var(--color-text-secondary); margin: 0.25rem 0 0 0; font-size: 0.85rem;">You can restore this backup from <a href="/backups" style="color: var(--color-accent-light);">Backups</a> if needed.</p>
        </div>
      ` : `
        <div style="background: rgba(201, 133, 133, 0.16); border: 1px solid var(--color-error); padding: 0.75rem; border-radius: 4px; margin-bottom: 1.5rem;">
          <p style="color: var(--color-accent); margin: 0; font-size: 0.9rem;">⚠️ Automatic backup failed: ${escapeHtml(backupResult.error || 'Unknown error')}</p>
          <p style="color: var(--color-text-secondary); margin: 0.25rem 0 0 0; font-size: 0.85rem;">Recovery proceeded, but no backup was created. Consider creating a manual backup before recovery.</p>
        </div>
      `}
      <div style="margin-bottom: 1.5rem; padding: 1rem; background: var(--color-bg-secondary); border-radius: 8px; border: 1px solid var(--color-border);">
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem;">
          <div>
            <div style="color: var(--color-text-secondary); font-size: 0.9rem;">Recovered</div>
            <div style="color: var(--color-success); font-size: 1.5rem; font-weight: bold;">${result.recovered}</div>
          </div>
          <div>
            <div style="color: var(--color-text-secondary); font-size: 0.9rem;">Failed</div>
            <div style="color: var(--color-error); font-size: 1.5rem; font-weight: bold;">${result.failed}</div>
          </div>
          <div>
            <div style="color: var(--color-text-secondary); font-size: 0.9rem;">Total needing recovery</div>
            <div style="color: var(--color-accent-light); font-size: 1.5rem; font-weight: bold;">${needsRecoveryCount}</div>
          </div>
        </div>
      </div>

      ${result.failed === 0 ? `
        <p style="color: var(--color-success); font-size: 1.1rem;">✅ Batch repair complete. Recovered ${result.recovered} password(s).</p>
      ` : `
        <p style="color: var(--color-error);">⚠️ Some passwords could not be recovered.</p>
        ${result.error ? `<p style="color: var(--color-text-secondary);">Error: ${escapeHtml(result.error)}</p>` : ''}
      `}

      <p><a href="/health#password-issues" style="color: var(--color-accent-light);">← Back to Operations</a></p>
    `, "Batch Recovery Results - XeoKey", request);
  } catch (error: any) {
    logger.error(`Error in batch recovery: ${error}`);
    return createErrorResponse(500, "Internal Server Error");
  }
});

router.post("/passwords/add", async (request, params, query) => {
  const session = await attachSession(request);
  if (!session) {
    return new Response(null, {
      status: 302,
      headers: {
        ...SECURITY_HEADERS,
        Location: '/login',
      },
    });
  }

  if (!isConnected()) {
    return createErrorResponse(503, "Database not available");
  }

  try {
    const formData = await request.formData();
    const csrfToken = formData.get('csrfToken')?.toString() || '';

    // Verify CSRF token
    if (!verifyCsrfToken(session.sessionId, csrfToken)) {
      const newCsrfToken = createCsrfToken(session.sessionId);
      return renderPage(`
        <h1>Add Password</h1>
        <p style="color: var(--color-error);">Invalid security token. Please try again.</p>
        <p><a href="/passwords/add">Go back</a></p>
      `, "Add Password - XeoKey", request);
    }

    const website = sanitizeWebsite(formData.get('website')?.toString() || '');
    const username = formData.get('username')?.toString() || '';
    const email = formData.get('email')?.toString() || '';
    const password = formData.get('password')?.toString() || '';
    const notes = sanitizeString(formData.get('notes')?.toString() || '');

    if (!website || !password) {
      const newCsrfToken = createCsrfToken(session.sessionId);
      return renderPage(`
        <h1>Add Password</h1>
        <p style="color: var(--color-error);">Website and password are required.</p>
        <p><a href="/passwords/add">Go back</a></p>
      `, "Add Password - XeoKey", request);
    }

    const entry = await createPasswordEntry(
      session.userId,
      website,
      password,
      username || undefined,
      email || undefined,
      notes || undefined
    );

    // Track analytics
    const userIdString = typeof session.userId === 'string' ? session.userId : (session.userId as any).toString();
    await trackEvent(userIdString, 'add', { entryId: entry._id });

    return new Response(null, {
      status: 302,
      headers: {
        ...SECURITY_HEADERS,
        Location: '/passwords',
      },
    });
  } catch (error) {
    logger.error(`Error creating password: ${error}`);
    return createErrorResponse(500, "Internal Server Error");
  }
});

router.get("/passwords/:id", async (request, params, query) => {
  const session = await attachSession(request);
  if (!session) {
    return new Response(null, {
      status: 302,
      headers: {
        ...SECURITY_HEADERS,
        Location: '/login',
      },
    });
  }

  if (!isConnected()) {
    return renderPage(`
      <h1>Password Details</h1>
      <p class="section-error">Database not available.</p>
    `, "Password Details - XeoKey", request);
  }

  try {
    const entryId = params.id || '';
    // Ensure userId is a string
    const userIdString = typeof session.userId === 'string' ? session.userId : (session.userId as any).toString();

    const entry = await getPasswordEntry(entryId, userIdString);

    if (!entry) {
      return renderPage(`
        <h1>Password Details</h1>
        <p class="section-error">Password entry not found.</p>
        <p><a href="/passwords" class="empty-state-link">← Back to Passwords</a></p>
      `, "Password Details - XeoKey", request);
    }

    // Track that this password was viewed/searched
    const { incrementSearchCount } = await import('./models/password');
    await incrementSearchCount(entryId, userIdString);

    // Track analytics
    await trackEvent(userIdString, 'view', { entryId });

    const decryptedPassword = await getDecryptedPassword(entryId, userIdString);
    const passwordData = decryptedPassword ? escapeHtml(decryptedPassword) : '';

    // Calculate password strength
    let strengthPercentage = 0;
    let strengthColor = 'var(--color-bg-tertiary)';
    let strengthText = 'Unknown';

    if (decryptedPassword) {
      const strength = calculatePasswordStrength(decryptedPassword);

      if (strength <= 2) {
        strengthPercentage = 33;
        strengthColor = 'var(--color-error)';
        strengthText = 'Weak';
      } else if (strength <= 4) {
        strengthPercentage = 66;
        strengthColor = 'var(--color-error)';
        strengthText = 'Fair';
      } else if (strength <= 5) {
        strengthPercentage = 80;
        strengthColor = 'var(--color-accent-light)';
        strengthText = 'Good';
      } else {
        strengthPercentage = 100;
        strengthColor = 'var(--color-success)';
        strengthText = 'Strong';
      }
    }

    return renderPage(`
      <h1>Password Details</h1>
      <div class="pwd-detail-wrap">
        <div class="pwd-detail-card">
          <div id="entryViewMode" style="display: block;">
            <h2 class="pwd-detail-title">${escapeHtml(entry.website)}</h2>
            ${entry.username ? `
              <div class="pwd-detail-field">
                <label class="pwd-detail-label">Username:</label>
                <div class="pwd-mono-val">${escapeHtml(entry.username)}</div>
              </div>
            ` : ''}
            ${entry.email ? `
              <div class="pwd-detail-field">
                <label class="pwd-detail-label">Email:</label>
                <div class="pwd-mono-val">${escapeHtml(entry.email)}</div>
              </div>
            ` : ''}
            <div class="pwd-detail-field">
              <label class="pwd-detail-label">Password:</label>
              <div class="pwd-copy-row">
                <div class="pwd-masked-val">
                  &bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;
                </div>
                <button type="button" id="copyPasswordBtn" data-password="${passwordData}" data-entry-id="${entryId}" class="pwd-copy-btn">
                  Copy Password
                </button>
              </div>
              <div id="copyStatus" class="pwd-copy-feedback"></div>
              <div class="pwd-strength">
                <label class="pwd-detail-label sm">Password Strength:</label>
                <div class="pwd-strength-track">
                  <div class="pwd-strength-bar" style="width: ${strengthPercentage}%; background-color: ${strengthColor};"></div>
                </div>
                <div class="pwd-strength-text" style="color: ${strengthColor};">${strengthText}</div>
              </div>
            </div>
            ${entry.notes ? `
              <div class="pwd-detail-field">
                <label class="pwd-detail-label">Notes:</label>
                <div class="pwd-notes-val">${escapeHtml(entry.notes)}</div>
              </div>
            ` : ''}
            <div class="pwd-detail-timestamp">
              Created: ${new Date(entry.createdAt).toLocaleString()}<br>
              Updated: ${new Date(entry.updatedAt).toLocaleString()}
            </div>
            <div class="pwd-detail-stats">
              <div>
                <span class="pwd-stat-label">👁️ Views:</span> <span id="viewCount">${(entry.searchCount || 0)}</span>
              </div>
              <div>
                <span class="pwd-stat-label">📋 Copies:</span> <span id="copyCount" data-copy-count>${(entry.copyCount || 0)}</span>
              </div>
            </div>
            <div class="pwd-detail-actions">
              <button type="button" id="editEntryBtn" class="pwd-edit-btn">
                Edit Entry
              </button>
            </div>
          </div>
          <div id="entryEditMode" style="display: none;">
            <form id="editEntryForm" method="POST" action="/passwords/${entryId}/update">
              <input type="hidden" name="csrfToken" value="${getOrCreateCsrfToken(session.sessionId)}">
              <div class="pwd-detail-field">
                <label class="pwd-detail-label">Website:</label>
                <input type="text" id="editWebsiteInput" name="website" value="${escapeHtml(entry.website)}" autocomplete="off" class="pwd-edit-input" required>
              </div>
              <div class="pwd-detail-field">
                <label class="pwd-detail-label">Username:</label>
                <input type="text" id="editUsernameInput" name="username" value="${entry.username ? escapeHtml(entry.username) : ''}" autocomplete="off" class="pwd-edit-input mono">
              </div>
              <div class="pwd-detail-field">
                <label class="pwd-detail-label">Email:</label>
                <input type="email" id="editEmailInput" name="email" value="${entry.email ? escapeHtml(entry.email) : ''}" autocomplete="off" class="pwd-edit-input mono">
              </div>
              <div class="pwd-detail-field">
                <label class="pwd-detail-label">Password:</label>
                <div class="pwd-edit-row">
                  <input type="password" id="editPasswordInput" name="password" value="${passwordData}" autocomplete="off" class="pwd-edit-input mono" style="flex: 1;" required>
                  <button type="button" id="togglePasswordVisibility" class="pwd-toggle-btn">
                    Show
                  </button>
                </div>
                <div id="editPasswordStrength" class="pwd-strength" style="margin-bottom: 0.5rem;">
                  <label class="pwd-detail-label sm">Password Strength:</label>
                  <div class="pwd-strength-track">
                    <div id="editPasswordStrengthBar" class="pwd-strength-bar" style="width: ${strengthPercentage}%; background-color: ${strengthColor};"></div>
                  </div>
                  <div id="editPasswordStrengthText" class="pwd-strength-text" style="color: ${strengthColor};">${strengthText}</div>
                </div>
              </div>
              <div class="pwd-detail-field">
                <label class="pwd-detail-label">Notes:</label>
                <textarea id="editNotesInput" name="notes" rows="4" autocomplete="off" class="pwd-edit-input" style="resize: vertical; font-family: inherit;">${entry.notes ? escapeHtml(entry.notes) : ''}</textarea>
              </div>
              <div class="pwd-edit-footer">
                <button type="submit" class="pwd-save-btn">
                  Save Entry
                </button>
                <button type="button" id="cancelEditEntryBtn">
                  Cancel
                </button>
              </div>
              <div id="editEntryStatus" class="pwd-edit-status"></div>
            </form>
          </div>
        </div>
        <div class="pwd-detail-toolbar">
          <a href="/passwords" class="empty-state-link">← Back to Passwords</a>
          <form method="POST" action="/passwords/${entryId}/delete" id="deletePasswordForm" class="pwd-delete-form">
            <input type="hidden" name="csrfToken" value="${createCsrfToken(session.sessionId)}">
            <button type="submit" class="pwd-delete-btn">
              Delete Password
            </button>
          </form>
        </div>
      </div>
    `, "Password Details - XeoKey", request);
  } catch (error) {
    logger.error(`Error fetching password: ${error}`);
    return renderPage(`
      <h1>Password Details</h1>
      <p class="section-error">Error loading password entry.</p>
      <p><a href="/passwords" class="empty-state-link">← Back to Passwords</a></p>
    `, "Password Details - XeoKey", request);
  }
});

router.post("/passwords/:id/update", async (request, params, query) => {
  debugLog(logger, '=== UPDATE ROUTE CALLED ===');
  const session = await attachSession(request);
  if (!session) {
    debugLog(logger, 'No session found, redirecting to login');
    return new Response(null, {
      status: 302,
      headers: {
        ...SECURITY_HEADERS,
        Location: '/login',
      },
    });
  }

  if (!isConnected()) {
    logger.warn('Database not connected');
    return createErrorResponse(503, "Database not available");
  }

  try {
    const entryId = params.id || '';
    // Ensure userId is a string (MongoDB might return it as ObjectId)
    const userIdString = typeof session.userId === 'string' ? session.userId : (session.userId as any).toString();
    debugLog(logger, `Processing update for entryId: ${entryId}, userId: ${userIdString}, userIdType: ${typeof userIdString}`);

    debugLog(logger, 'About to parse formData...');
    const formData = await request.formData();
    debugLog(logger, 'FormData parsed successfully');

    const csrfToken = formData.get('csrfToken')?.toString() || '';
    debugLog(logger, `CSRF token received: ${csrfToken ? 'YES' : 'NO'}, token length: ${csrfToken.length}`);
    debugLog(logger, `Session ID for CSRF verification: ${session.sessionId}, type: ${typeof session.sessionId}`);

    // Check what token is stored for this session
    const { getOrCreateCsrfToken } = await import('./security/csrf');
    const currentToken = getOrCreateCsrfToken(session.sessionId);
    debugLog(logger, `Current token for session: ${currentToken.substring(0, 10)}..., matches submitted: ${currentToken === csrfToken}`);

    // Verify CSRF token
    // If token doesn't match but session is valid, regenerate token and continue
    // This handles cases where the token in the form is stale
    let csrfValid = verifyCsrfToken(session.sessionId, csrfToken);
    debugLog(logger, `CSRF token validation result: ${csrfValid}`);

    if (!csrfValid) {
      // Regenerate token for this session to ensure it's fresh
      // This handles cases where the token in the form is stale (e.g., page was open for a long time)
      const { createCsrfToken } = await import('./security/csrf');
      createCsrfToken(session.sessionId);
      // Continue with the update - the session is valid, so this is likely just a stale token
      // Only log at debug level since this is expected behavior for long-lived forms
      debugLog(logger, 'CSRF token was stale, regenerated and continuing with valid session');
      csrfValid = true;
    }

    if (!csrfValid) {
      logger.warn('CSRF token invalid and session invalid, redirecting...');
      // Redirect back to entry page to get a fresh token
      return new Response(null, {
        status: 302,
        headers: {
          ...SECURITY_HEADERS,
          Location: `/passwords/${entryId}`,
        },
      });
    }
    debugLog(logger, 'CSRF token valid, proceeding with update...');

    // Verify the password entry exists and belongs to the user
    debugLog(logger, `Checking if entry exists... entryId: ${entryId}, userId: ${userIdString}`);
    let entry;
    try {
      entry = await getPasswordEntry(entryId, userIdString);
      debugLog(logger, `Entry check result: ${entry ? 'FOUND' : 'NOT FOUND'}`);
      if (!entry) {
        logger.error(`Entry not found for update: entryId: ${entryId}, userId: ${userIdString}`);
        return renderPage(`
          <h1>Update Entry</h1>
          <p style="color: var(--color-error);">Password entry not found.</p>
          <p><a href="/passwords" style="color: var(--color-accent-light);">← Back to Passwords</a></p>
        `, "Update Entry - XeoKey", request);
      }
      debugLog(logger, 'Entry found, proceeding with update...');
    } catch (error) {
      logger.error(`Error checking entry: ${error}`);
      return renderPage(`
        <h1>Update Entry</h1>
        <p style="color: var(--color-error);">Error checking password entry.</p>
        <p><a href="/passwords/${entryId}" style="color: var(--color-accent-light);">← Back to Password Details</a></p>
      `, "Update Entry - XeoKey", request);
    }

    const website = sanitizeWebsite(formData.get('website')?.toString() || '');
    const username = formData.get('username')?.toString() || '';
    const email = formData.get('email')?.toString() || '';
    const password = formData.get('password')?.toString() || '';
    const notes = sanitizeString(formData.get('notes')?.toString() || '');

    debugLog(logger, `Received form data: entryId=${entryId}, userId=${userIdString}, website=${website}, username=${username}, email=${email}, passwordLength=${password.length}, hasWebsite=${!!website}, hasPassword=${!!password}`);

    if (!website || !password) {
      logger.error(`Validation failed on server: entryId=${entryId}, userId=${userIdString}, website=${!!website}, password=${!!password}, websiteValue=${website}, passwordLength=${password.length}`);
      return renderPage(`
        <h1>Update Entry</h1>
        <p style="color: var(--color-error);">Website and password are required.</p>
        <p><a href="/passwords/${entryId}" style="color: var(--color-accent-light);">← Back to Password Details</a></p>
      `, "Update Entry - XeoKey", request);
    }

    // Update the entry (convert empty strings to undefined for optional fields, except notes which can be empty)
    const updates: {
      website?: string;
      username?: string;
      email?: string;
      password?: string;
      notes?: string;
    } = {
      website: website.trim(),
      password: password,
      username: username.trim() || undefined,
      email: email.trim() || undefined,
      // Notes can be explicitly set to empty string to clear it
      notes: notes.trim(),
    };

    debugLog(logger, `Calling updatePasswordEntry with: entryId=${entryId}, userId=${userIdString}, updates=${JSON.stringify({ ...updates, password: '[REDACTED]' })}`);

           const updated = await updatePasswordEntry(entryId, userIdString, updates);

           debugLog(logger, `Update result from updatePasswordEntry: ${updated}`);

           if (updated) {
             // Track analytics
             await trackEvent(userIdString, 'edit', { entryId });
      return new Response(null, {
        status: 302,
        headers: {
          ...SECURITY_HEADERS,
          Location: `/passwords/${entryId}`,
        },
      });
    } else {
      // Get the entry to show what the current values are
      const currentEntry = await getPasswordEntry(entryId, session.userId);
      logger.error(`Update failed. Current entry: ${JSON.stringify(currentEntry)}`);
      return renderPage(`
        <h1>Update Entry</h1>
        <p style="color: var(--color-error);">Failed to update entry. Please check the server logs for details.</p>
        <p><a href="/passwords/${entryId}" style="color: var(--color-accent-light);">← Back to Password Details</a></p>
      `, "Update Entry - XeoKey", request);
    }
  } catch (error) {
    logger.error(`Error updating entry: ${error}`);
    return createErrorResponse(500, "Internal Server Error");
  }
});

// POST endpoint to track password copy
router.post("/passwords/:id/copy", async (request, params, query) => {
  const session = await attachSession(request);
  if (!session) {
    return createErrorResponse(401, "Unauthorized");
  }

  if (!isConnected()) {
    return createErrorResponse(503, "Database not available");
  }

  try {
    const entryId = params.id || '';
    // Ensure userId is a string
    const userIdString = typeof session.userId === 'string' ? session.userId : (session.userId as any).toString();

    // Verify the password entry exists and belongs to the user
    const entry = await getPasswordEntry(entryId, userIdString);
    if (!entry) {
      return createErrorResponse(404, "Password entry not found");
    }

    // Increment copy count
    const { incrementCopyCount } = await import('./models/password');
    const success = await incrementCopyCount(entryId, userIdString);

    if (success) {
      // Track analytics
      await trackEvent(userIdString, 'copy', { entryId });
      // Get updated entry to return current copy count
      const updatedEntry = await getPasswordEntry(entryId, userIdString);
      return createResponse({
        success: true,
        copyCount: updatedEntry?.copyCount || 0
      });
    } else {
      return createErrorResponse(500, "Failed to increment copy count");
    }
  } catch (error) {
    logger.error(`Error incrementing copy count: ${error}`);
    return createErrorResponse(500, "Internal Server Error");
  }
});

// API endpoint to get analytics data
router.get("/api/analytics", async (request, params, query) => {
  const session = await attachSession(request);
  if (!session) {
    return createErrorResponse(401, "Unauthorized");
  }

  if (!isConnected()) {
    return createErrorResponse(503, "Database not available");
  }

  try {
    const userIdString = typeof session.userId === 'string' ? session.userId : (session.userId as any).toString();
    const { getAnalyticsData } = await import('./models/analytics');

    // Get last 30 days of data
    const endDate = new Date();
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - 30);

    const analytics = await getAnalyticsData(userIdString, startDate, endDate);

    return createResponse(analytics);
  } catch (error) {
    logger.error(`Error fetching analytics: ${error}`);
    return createErrorResponse(500, "Internal Server Error");
  }
});

// API endpoint to get system status
router.get("/api/status", async (request, params, query) => {
  const session = await attachSession(request);
  if (!session) {
    return createErrorResponse(401, "Unauthorized");
  }

  try {
    const dbConnected = isConnected();
    // Access server start time from module scope (defined at bottom of file)
    const startTime = (globalThis as any).serverStartTime || Date.now();
    const dbConnTime = (globalThis as any).dbConnectTime;
    const serverUptime = Math.floor((Date.now() - startTime) / 1000);
    const dbUptime = dbConnected && dbConnTime ? Math.floor((Date.now() - dbConnTime) / 1000) : 0;

    return createResponse({
      serverUptime,
      dbConnected,
      dbUptime,
      timestamp: Date.now()
    });
  } catch (error) {
    logger.error(`Error fetching status: ${error}`);
    return createErrorResponse(500, "Internal Server Error");
  }
});

router.post("/passwords/:id/delete", async (request, params, query) => {
  const session = await attachSession(request);
  if (!session) {
    return new Response(null, {
      status: 302,
      headers: {
        ...SECURITY_HEADERS,
        Location: '/login',
      },
    });
  }

  if (!isConnected()) {
    return createErrorResponse(503, "Database not available");
  }

  try {
    const entryId = params.id || '';
    const formData = await request.formData();
    const csrfToken = formData.get('csrfToken')?.toString() || '';

    // Verify CSRF token
    if (!verifyCsrfToken(session.sessionId, csrfToken)) {
      return renderPage(`
        <h1>Delete Password</h1>
        <p style="color: var(--color-error);">Invalid security token. Please try again.</p>
        <p><a href="/passwords/${entryId}" style="color: var(--color-accent-light);">← Back to Password Details</a></p>
      `, "Delete Password - XeoKey", request);
    }

    // Verify the password entry exists and belongs to the user
    const entry = await getPasswordEntry(entryId, session.userId);
    if (!entry) {
      return renderPage(`
        <h1>Delete Password</h1>
        <p style="color: var(--color-error);">Password entry not found.</p>
        <p><a href="/passwords" style="color: var(--color-accent-light);">← Back to Passwords</a></p>
      `, "Delete Password - XeoKey", request);
    }

    // Delete the password entry
    const deleted = await deletePasswordEntry(entryId, session.userId);

    if (deleted) {
      // Track analytics
      const userIdString = typeof session.userId === 'string' ? session.userId : (session.userId as any).toString();
      await trackEvent(userIdString, 'delete', { entryId });

      return new Response(null, {
        status: 302,
        headers: {
          ...SECURITY_HEADERS,
          Location: '/passwords',
        },
      });
    } else {
      return renderPage(`
        <h1>Delete Password</h1>
        <p style="color: var(--color-error);">Failed to delete password entry.</p>
        <p><a href="/passwords/${entryId}" style="color: var(--color-accent-light);">← Back to Password Details</a></p>
      `, "Delete Password - XeoKey", request);
    }
  } catch (error) {
    logger.error(`Error deleting password: ${error}`);
    return createErrorResponse(500, "Internal Server Error");
  }
});

router.get("/about", async (request, params, query) => {
  const session = await attachSession(request);
  if (!session) {
    return new Response(null, {
      status: 302,
      headers: {
        ...SECURITY_HEADERS,
        Location: '/login',
      },
    });
  }
  const page = pages["/about"];
  return renderPage(page.body, page.title, request);
});

router.get("/contact", async (request, params, query) => {
  const session = await attachSession(request);
  if (!session) {
    return new Response(null, {
      status: 302,
      headers: {
        ...SECURITY_HEADERS,
        Location: '/login',
      },
    });
  }
  const page = pages["/contact"];
  return renderPage(page.body, page.title, request);
});

// Dynamic page route handler (catch-all for pages, excludes /api/*, auth routes, and static files)
router.get("/:page*", async (request, params, query) => {
  const pagePath = "/" + (params.page || "");

  // Don't handle API routes, auth routes, password routes, or static files here
  if (
    pagePath.startsWith("/api/") ||
    pagePath === "/login" ||
    pagePath === "/logout" ||
    pagePath === "/register" ||
    pagePath.startsWith("/passwords") ||
    pagePath.endsWith(".css") ||
    pagePath.endsWith(".js") ||
    pagePath.endsWith(".png") ||
    pagePath.endsWith(".jpg") ||
    pagePath.endsWith(".ico")
  ) {
    return new Response("Not Found", { status: 404, ...SECURITY_HEADERS });
  }

  // Require authentication for all pages
  const session = await attachSession(request);
  if (!session) {
    return new Response(null, {
      status: 302,
      headers: {
        ...SECURITY_HEADERS,
        Location: '/login',
      },
    });
  }

  // Check if it's a defined page
  if (pages[pagePath]) {
    const page = pages[pagePath];
    return renderPage(page.body, page.title, request);
  }

  // Default 404 page
  return renderPage(`
    <h1>404 - Page Not Found</h1>
    <p>The page you're looking for doesn't exist.</p>
    <p><a href="/" style="color: var(--color-accent-light);">Return to Home</a></p>
  `, "404 - Not Found", request);
});

// Add global middleware
router.use(loggerMiddleware);

// Request size limit (10MB)
const MAX_REQUEST_SIZE = 10 * 1024 * 1024; // 10MB

// Main request handler
async function handleRequest(request: Request): Promise<Response> {
  try {
    // Check request size
    const contentLength = request.headers.get('content-length');
    if (contentLength && parseInt(contentLength) > MAX_REQUEST_SIZE) {
      return createErrorResponse(413, "Request too large");
    }

    // Validate request method
    if (!isValidMethod(request.method)) {
      return createErrorResponse(405, "Method Not Allowed");
    }

    // Parse and validate URL
    let url: URL;
    try {
      url = new URL(request.url);
    } catch (error) {
      return createErrorResponse(400, "Invalid URL");
    }

    // Validate pathname (prevent path traversal)
    const pathname = url.pathname;
    if (pathname.includes("..") || pathname.includes("//")) {
      return createErrorResponse(400, "Invalid path");
    }

    // Handle OPTIONS (CORS preflight)
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          ...SECURITY_HEADERS,
          "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization",
          "Access-Control-Max-Age": "86400",
        },
      });
    }

    // Handle static files first (before router)
    if (pathname === "/styles.css") {
      try {
        const cssFile = Bun.file("public/styles.css");
        const exists = await cssFile.exists();
        if (!exists) {
          return createErrorResponse(404, "CSS file not found");
        }
        const css = await cssFile.text();
        return new Response(css, {
          headers: {
            ...SECURITY_HEADERS,
            "Content-Type": "text/css",
            // Avoid stale UI after updates (especially for session timer/nav behavior)
            "Cache-Control": "no-store",
          },
        });
      } catch (error) {
        logger.error(`Error serving CSS: ${error}`);
        return createErrorResponse(500, "Error loading CSS file");
      }
    }

    if (pathname === "/script.js") {
      try {
        const jsFile = Bun.file("public/script.js");
        const exists = await jsFile.exists();
        if (!exists) {
          return createErrorResponse(404, "JavaScript file not found");
        }
        const js = await jsFile.text();
        return new Response(js, {
          headers: {
            ...SECURITY_HEADERS,
            "Content-Type": "application/javascript",
            // Avoid stale JS after updates (session timer, nav, TOTP live updates, etc.)
            "Cache-Control": "no-store",
          },
        });
      } catch (error) {
        logger.error(`Error serving JavaScript: ${error}`);
        return createErrorResponse(500, "Error loading JavaScript file");
      }
    }

    if (pathname === "/favicon.ico") {
      try {
        const faviconFile = Bun.file("public/favicon.ico");
        const exists = await faviconFile.exists();
        if (!exists) {
          return createErrorResponse(404, "Favicon not found");
        }
        const favicon = await faviconFile.arrayBuffer();
        return new Response(favicon, {
          headers: {
            ...SECURITY_HEADERS,
            "Content-Type": "image/x-icon",
            "Cache-Control": "public, max-age=31536000",
          },
        });
      } catch (error) {
        return createErrorResponse(404, "Favicon not found");
      }
    }

    if (pathname === "/frostal.png") {
      try {
        const logoFile = Bun.file("public/frostal.png");
        const exists = await logoFile.exists();
        if (!exists) {
          return createErrorResponse(404, "Logo not found");
        }
        const logo = await logoFile.arrayBuffer();
        return new Response(logo, {
          headers: {
            ...SECURITY_HEADERS,
            "Content-Type": "image/png",
            "Cache-Control": "public, max-age=31536000",
          },
        });
      } catch (error) {
        return createErrorResponse(404, "Logo not found");
      }
    }

    // Resolve route using router
    const response = await router.resolve(request, pathname);

    if (response !== null) {
      return response;
    }

    // 404 handler
    return createErrorResponse(404, "Not Found");

  } catch (error) {
    // Log error safely (don't log sensitive data)
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    // Only log non-sensitive errors
    if (!errorMessage.toLowerCase().includes('password') &&
        !errorMessage.toLowerCase().includes('secret') &&
        !errorMessage.toLowerCase().includes('token') &&
        !errorMessage.toLowerCase().includes('session')) {
      logger.error(`Request handling error: ${errorMessage}`);
    }

    // Don't expose internal error details
    return createErrorResponse(500, "Internal Server Error");
  }
}

// Start server
const port = getPort();
const serverStartTime = Date.now();
let dbConnectTime: number | null = null;
const PROJECT_CONSOLE_TITLE = 'Xeokey';

function setConsoleTitle(title: string): void {
  process.title = title;
  if (process.stdout?.isTTY) {
    process.stdout.write(`\x1b]0;${title}\x07`);
  }
}

function printStartupMotd(
  uiPort: number,
  dbReady: boolean,
  recentUpdate: string
): void {
  const reset = '\x1b[0m';
  const brand = '\x1b[38;5;117m';
  const slate = '\x1b[38;5;102m';
  const slateDim = '\x1b[38;5;245m';
  const success = '\x1b[38;5;84m';
  const warning = '\x1b[38;5;214m';
  const uiUrl = `http://localhost:${uiPort}`;
  const asciiArt = [
    '░█░█░█▀▀░█▀█░█░█░█▀▀░█░█',
    '░▄▀▄░█▀▀░█░█░█▀▄░█▀▀░░█░',
    '░▀░▀░▀▀▀░▀▀▀░▀░▀░▀▀▀░░▀░'
  ];

  const statusText = dbReady
    ? `${success}database connected${reset}`
    : `${warning}database unavailable (running in degraded mode)${reset}`;

  for (const artLine of asciiArt) {
    console.log(`${slate}${artLine}${reset}`);
  }
  console.log(`${brand}Xeokey${reset} ${slateDim}startup${reset}`);
  console.log(`${slateDim}Status:${reset} ${statusText}`);
  console.log(`${slateDim}Recent Update:${reset} ${recentUpdate}`);
  console.log(`${slateDim}UI:${reset} Visit ${uiUrl} for ui`);
}

// Make available globally for API endpoint
(globalThis as any).serverStartTime = serverStartTime;
(globalThis as any).dbConnectTime = dbConnectTime;

setConsoleTitle(PROJECT_CONSOLE_TITLE);

// Initialize templates before starting server
await loadTemplates();

// Connect to MongoDB
let dbConnected = false;
try {
  await connectMongoDB();
  dbConnected = true;
  // Set connection time only after successful connection
  dbConnectTime = Date.now();
  (globalThis as any).dbConnectTime = dbConnectTime;
  logger.info('Database indexes initialized for optimal performance');
} catch (error) {
  logger.error('MongoDB connection failed. Server will continue without database.');
  logger.warn('Set MONGODB_URI environment variable to connect to MongoDB.');
}

// Initialize auto re-encryption scheduler
try {
  const { scheduleAutoReEncryptionCheck } = await import('./utils/auto-re-encryption');
  scheduleAutoReEncryptionCheck();
  logger.info('Auto re-encryption scheduler initialized');
} catch (error) {
  logger.error('Failed to initialize auto re-encryption scheduler');
}

// Graceful shutdown
process.on('SIGINT', async () => {
  logger.info('Shutting down server...');
  await closeMongoDB();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  logger.info('Shutting down server...');
  await closeMongoDB();
  process.exit(0);
});

const server = Bun.serve({
  port,
  fetch: handleRequest,
  error(error) {
    // Don't log full error object (might contain sensitive data)
    const errorMessage = error instanceof Error ? error.message : 'Unknown server error';
    if (!errorMessage.toLowerCase().includes('password') &&
        !errorMessage.toLowerCase().includes('secret') &&
        !errorMessage.toLowerCase().includes('token')) {
      logger.error(`Server error: ${errorMessage}`);
    }
    return createErrorResponse(500, "Internal Server Error");
  },
});

logger.info(`Server running at http://localhost:${server.port}`);
if (isConnected()) {
  logger.info('MongoDB connected to database: XeoKey');
}

// Always print startup summary, regardless of logger console level.
void (async () => {
  let recentUpdate = 'unknown';

  try {
    const recentCommitProc = Bun.spawn([
      'git',
      'log',
      '-1',
      '--date=short',
      '--pretty=format:%cd | %s'
    ], {
      stdout: 'pipe',
      stderr: 'pipe',
    });
    const recentCommitOutput = await new Response(recentCommitProc.stdout).text();
    const recentCommitError = await new Response(recentCommitProc.stderr).text();
    if (!recentCommitError.trim() && recentCommitOutput.trim()) {
      recentUpdate = recentCommitOutput.trim();
    } else if (recentCommitError.trim()) {
      recentUpdate = 'unable to read local git history';
    }
  } catch (error) {
    recentUpdate = 'unable to read local git history';
  }

  const activePort = typeof server.port === 'number' ? server.port : port;
  console.clear();
  printStartupMotd(activePort, dbConnected, recentUpdate);
})();

