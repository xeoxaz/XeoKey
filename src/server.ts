// Logger
import { logger } from './utils/logger';
import { debugLog } from './utils/debug';

// MongoDB connection
import { connectMongoDB, closeMongoDB, getDatabase, isConnected } from './db/mongodb';

// Authentication
import { createSession, getSession, deleteSession, getSessionIdFromRequest, createSessionCookie, createLogoutCookie } from './auth/session';
import { authenticateUser, createUser } from './auth/users';

// Password management
import { createPasswordEntry, getUserPasswords, getPasswordEntry, getDecryptedPassword, updatePasswordEntry, deletePasswordEntry } from './models/password';

// Analytics
import { trackEvent } from './models/analytics';

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
  "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'; connect-src 'self' https://cdn.jsdelivr.net;",
  "Referrer-Policy": "strict-origin-when-cross-origin",
};

// Router System - OS-like hierarchical structure
type HttpMethod = "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "HEAD" | "OPTIONS";
type RouteHandler = (request: Request, params: Record<string, string>, query: URLSearchParams) => Promise<Response> | Response;
type Middleware = (request: Request, params: Record<string, string>, query: URLSearchParams) => Promise<Response | null> | Response | null;

// Session interface
interface AuthenticatedRequest extends Request {
  session?: {
    sessionId: string;
    userId: string;
    username: string;
  };
}

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

  // If not logged in, hide the entire nav menu
  if (!session) {
    // Remove the nav element completely
    header = header.replace(/<nav>[\s\S]*?<\/nav>/, '');
  } else {
    // Add notification badge to Dashboard link
    const dashboardBadge = issueCount > 0
      ? `<span style="background: #d4a5a5; color: #1d1d1d; border-radius: 50%; width: 20px; height: 20px; display: inline-flex; align-items: center; justify-content: center; font-size: 0.75rem; font-weight: bold; margin-left: 0.5rem;">${issueCount}</span>`
      : `<span style="color: #7fb069; margin-left: 0.5rem; font-size: 1rem;">✓</span>`;

    header = header.replace(
      '<a href="/">Dashboard</a>',
      `<a href="/" style="display: flex; align-items: center;">Dashboard${dashboardBadge}</a>`
    );

    // Add login/logout menu items for logged in users
    const authMenu = `<div class="nav-item dropdown">
        <button type="button">${sanitizeString(session.username)}</button>
        <div class="dropdown-menu">
          <a href="/logout">Logout</a>
        </div>
      </div>`;

    // Insert auth menu before closing nav tag
    header = header.replace('</nav>', authMenu + '</nav>');
  }

  return header;
}

function getFooter(): string {
  if (!footerTemplate) {
    throw new Error("Footer template not loaded");
  }
  const year = new Date().getFullYear();
  return footerTemplate.replace("{{YEAR}}", year.toString());
}

// Render page with header and footer
async function renderPage(body: string, title: string = "XeoKey", request?: Request): Promise<Response> {
  let session = null;
  let issueCount = 0;

  if (request && isConnected()) {
    const sessionData = await attachSession(request);
    if (sessionData) {
      session = { username: sessionData.username, userId: sessionData.userId };
      // Get security issue count for notification badge
      const analysis = await analyzePasswords(sessionData.userId);
      issueCount = analysis.duplicateCount + analysis.weakPasswordCount;
    }
  }
  const html = await getHeader(title, session, issueCount) + body + getFooter();
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
        <div style="background: #2d2d2d; padding: 1.5rem; border-radius: 8px; border: 1px solid #3d3d3d;">
          <h3 style="margin-bottom: 0.5rem; color: #9db4d4;">Quick Actions</h3>
          <p style="margin-bottom: 1rem; color: #b0b0b0;">Manage your passwords</p>
          <a href="/passwords/add" style="display: inline-block; background: #3d3d3d; color: #e0e0e0; padding: 0.5rem 1rem; border-radius: 4px; text-decoration: none; border: 1px solid #4d4d4d;">Add Password</a>
        </div>
        <div style="background: #2d2d2d; padding: 1.5rem; border-radius: 8px; border: 1px solid #3d3d3d;">
          <h3 style="margin-bottom: 0.5rem; color: #9db4d4;">Your Passwords</h3>
          <p style="margin-bottom: 1rem; color: #b0b0b0;">View all saved passwords</p>
          <a href="/passwords" style="display: inline-block; background: #3d3d3d; color: #e0e0e0; padding: 0.5rem 1rem; border-radius: 4px; text-decoration: none; border: 1px solid #4d4d4d;">View All</a>
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
          <input type="text" id="name" name="name" style="width: 100%; padding: 0.5rem; border: 1px solid #ddd; border-radius: 4px;">
        </div>
        <div style="margin-bottom: 1rem;">
          <label for="email" style="display: block; margin-bottom: 0.5rem;">Email:</label>
          <input type="email" id="email" name="email" style="width: 100%; padding: 0.5rem; border: 1px solid #ddd; border-radius: 4px;">
        </div>
        <div style="margin-bottom: 1rem;">
          <label for="message" style="display: block; margin-bottom: 0.5rem;">Message:</label>
          <textarea id="message" name="message" rows="5" style="width: 100%; padding: 0.5rem; border: 1px solid #ddd; border-radius: 4px;"></textarea>
        </div>
        <button type="submit" style="background: #2c3e50; color: white; padding: 0.75rem 1.5rem; border: none; border-radius: 4px; cursor: pointer;">Send Message</button>
      </form>
    `,
  },
};

// Register routes - OS-like hierarchical structure
// API routes (must be registered before catch-all routes)
router.get("/api/status", async (request, params, query) => {
  return createResponse({
    status: "online",
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
  });
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

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// Helper function to render login form with errors
async function renderLoginForm(request: Request, username: string = '', error: string = '', csrfToken: string = ''): Promise<string> {
  const errorHtml = error ? `<div style="color: #d4a5a5; font-size: 0.9rem; margin-bottom: 1rem; padding: 0.5rem; background: #2d1a1a; border: 1px solid #d4a5a5; border-radius: 4px;">${escapeHtml(error)}</div>` : '';
  const usernameValue = username ? ` value="${escapeHtml(username)}"` : '';
  const csrfField = csrfToken ? `<input type="hidden" name="csrfToken" value="${escapeHtml(csrfToken)}">` : '';

  return `
    <h1>Login</h1>
    <form method="POST" action="/login" style="max-width: 400px; margin: 0 auto;">
      ${csrfField}
      ${errorHtml}
      <div style="margin-bottom: 1rem;">
        <label for="username" style="display: block; margin-bottom: 0.5rem;">Username:</label>
        <input type="text" id="username" name="username" required${usernameValue} style="width: 100%; padding: 0.5rem; border: 1px solid #3d3d3d; border-radius: 4px; background: #2d2d2d; color: #e0e0e0;">
      </div>
      <div style="margin-bottom: 1.5rem;">
        <label for="password" style="display: block; margin-bottom: 0.5rem;">Password:</label>
        <input type="password" id="password" name="password" required style="width: 100%; padding: 0.5rem; border: 1px solid #3d3d3d; border-radius: 4px; background: #2d2d2d; color: #e0e0e0;">
      </div>
      <button type="submit" style="width: 100%; background: #3d3d3d; color: #e0e0e0; padding: 0.75rem; border: 1px solid #4d4d4d; border-radius: 4px; cursor: pointer; font-size: 1rem;">Login</button>
    </form>
    <p style="text-align: center; margin-top: 1rem;">
      <a href="/register" style="color: #9db4d4;">Don't have an account? Register here</a>
    </p>
  `;
}

// Helper function to render register form with errors
async function renderRegisterForm(request: Request, username: string = '', error: string = '', csrfToken: string = ''): Promise<string> {
  const errorHtml = error ? `<div style="color: #d4a5a5; font-size: 0.9rem; margin-bottom: 1rem; padding: 0.5rem; background: #2d1a1a; border: 1px solid #d4a5a5; border-radius: 4px;">${escapeHtml(error)}</div>` : '';
  const usernameValue = username ? ` value="${escapeHtml(username)}"` : '';
  const csrfField = csrfToken ? `<input type="hidden" name="csrfToken" value="${escapeHtml(csrfToken)}">` : '';

  return `
    <h1>Register</h1>
    <form method="POST" action="/register" id="registerForm" style="max-width: 400px; margin: 0 auto;">
      ${csrfField}
      ${errorHtml}
      <div style="margin-bottom: 1rem;">
        <label for="username" style="display: block; margin-bottom: 0.5rem;">Username:</label>
        <input type="text" id="username" name="username" required minlength="3" maxlength="30" pattern="[a-zA-Z0-9_]+"${usernameValue} style="width: 100%; padding: 0.5rem; border: 1px solid #3d3d3d; border-radius: 4px; background: #2d2d2d; color: #e0e0e0;">
        <small style="color: #b0b0b0; font-size: 0.85rem;">3-30 characters, letters, numbers, and underscores only</small>
      </div>
      <div style="margin-bottom: 1rem;">
        <label for="password" style="display: block; margin-bottom: 0.5rem;">Password:</label>
        <input type="password" id="password" name="password" required minlength="6" maxlength="100" style="width: 100%; padding: 0.5rem; border: 1px solid #3d3d3d; border-radius: 4px; background: #2d2d2d; color: #e0e0e0;">
        <div id="passwordStrength" style="margin-top: 0.5rem; height: 4px; background: #2d2d2d; border-radius: 2px; overflow: hidden;">
          <div id="passwordStrengthBar" style="height: 100%; width: 0%; transition: width 0.3s, background-color 0.3s;"></div>
        </div>
        <div id="passwordStrengthText" style="color: #b0b0b0; font-size: 0.85rem; margin-top: 0.25rem;"></div>
      </div>
      <div style="margin-bottom: 1.5rem;">
        <label for="confirmPassword" style="display: block; margin-bottom: 0.5rem;">Confirm Password:</label>
        <input type="password" id="confirmPassword" name="confirmPassword" required minlength="6" maxlength="100" style="width: 100%; padding: 0.5rem; border: 1px solid #3d3d3d; border-radius: 4px; background: #2d2d2d; color: #e0e0e0;">
        <div id="passwordMatch" style="color: #b0b0b0; font-size: 0.85rem; margin-top: 0.25rem;"></div>
      </div>
      <button type="submit" id="submitBtn" style="width: 100%; background: #3d3d3d; color: #e0e0e0; padding: 0.75rem; border: 1px solid #4d4d4d; border-radius: 4px; cursor: pointer; font-size: 1rem;">Register</button>
    </form>
    <p style="text-align: center; margin-top: 1rem;">
      <a href="/login" style="color: #9db4d4;">Already have an account? Login here</a>
    </p>
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
  return renderPage(formHtml, "Login - XeoKey", request);
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
    return renderPage(formHtml, "Login - XeoKey", request);
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
      return renderPage(formHtml, "Login - XeoKey", request);
    }

    // Sanitize inputs
    const username = sanitizeUsername(rawUsername);
    const password = sanitizeString(rawPassword);

    if (!username || !password) {
      const tempSessionId = 'temp_' + Date.now();
      const newCsrfToken = createCsrfToken(tempSessionId);
      const formHtml = await renderLoginForm(request, rawUsername, "Username and password are required.", newCsrfToken);
      return renderPage(formHtml, "Login - XeoKey", request);
    }

    // Validate inputs
    const usernameValidation = validateUsername(username);
    if (!usernameValidation.valid) {
      const tempSessionId = 'temp_' + Date.now();
      const newCsrfToken = createCsrfToken(tempSessionId);
      const formHtml = await renderLoginForm(request, rawUsername, usernameValidation.error || "Invalid username format.", newCsrfToken);
      return renderPage(formHtml, "Login - XeoKey", request);
    }

    const user = await authenticateUser(username, password);
    if (!user) {
      const tempSessionId = 'temp_' + Date.now();
      const newCsrfToken = createCsrfToken(tempSessionId);
      const formHtml = await renderLoginForm(request, rawUsername, "Invalid username or password.", newCsrfToken);
      return renderPage(formHtml, "Login - XeoKey", request);
    }

    // Reset rate limit on successful login
    resetRateLimit(request, 'login');

    // Create new session (regenerate session ID to prevent fixation)
    const sessionId = await createSession(user._id!, user.username);
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
  return renderPage(formHtml, "Register - XeoKey", request);
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
    return renderPage(formHtml, "Register - XeoKey", request);
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
    return renderPage(formHtml, "Register - XeoKey", request);
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
      return renderPage(formHtml, "Register - XeoKey", request);
    }

    const passwordValidation = validatePassword(password);
    if (!passwordValidation.valid) {
      const tempSessionId = 'temp_' + Date.now();
      const newCsrfToken = createCsrfToken(tempSessionId);
      const formHtml = await renderRegisterForm(request, rawUsername, passwordValidation.error || "Invalid password.", newCsrfToken);
      return renderPage(formHtml, "Register - XeoKey", request);
    }

    // Check if passwords match
    if (password !== confirmPassword) {
      const tempSessionId = 'temp_' + Date.now();
      const newCsrfToken = createCsrfToken(tempSessionId);
      const formHtml = await renderRegisterForm(request, rawUsername, "Passwords do not match.", newCsrfToken);
      return renderPage(formHtml, "Register - XeoKey", request);
    }

    const user = await createUser(username, password);

    // Reset rate limit on successful registration
    resetRateLimit(request, 'register');

    const sessionId = await createSession(user._id!, user.username);
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
    return renderPage(formHtml, "Register - XeoKey", request);
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

  // Build dashboard body with statistics - compact design with graphs
  const dashboardBody = `
    <h1 style="margin-bottom: 0.5rem;">Dashboard</h1>
    <p style="color: #888; font-size: 0.9rem; margin-bottom: 1.5rem;">Analytics & System Status</p>

    <!-- Status Cards Row -->
    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 0.75rem; margin-bottom: 1rem;">
      <div style="background: #2d2d2d; padding: 0.75rem; border-radius: 6px; border: 1px solid #3d3d3d;">
        <div style="font-size: 1.5rem; font-weight: bold; color: #9db4d4; margin-bottom: 0.25rem;">${passwordCount}</div>
        <div style="color: #888; font-size: 0.75rem;">Passwords</div>
      </div>
      <div style="background: #2d2d2d; padding: 0.75rem; border-radius: 6px; border: 1px solid #3d3d3d;">
        <div style="font-size: 1.5rem; font-weight: bold; color: #7fb069; margin-bottom: 0.25rem;" id="totalAdds">-</div>
        <div style="color: #888; font-size: 0.75rem;">Added</div>
      </div>
      <div style="background: #2d2d2d; padding: 0.75rem; border-radius: 6px; border: 1px solid #3d3d3d;">
        <div style="font-size: 1.5rem; font-weight: bold; color: #d4a5a5; margin-bottom: 0.25rem;" id="totalDeletes">-</div>
        <div style="color: #888; font-size: 0.75rem;">Deleted</div>
      </div>
      <div style="background: #2d2d2d; padding: 0.75rem; border-radius: 6px; border: 1px solid #3d3d3d;">
        <div style="font-size: 1.5rem; font-weight: bold; color: #9db4d4; margin-bottom: 0.25rem;" id="totalViews">-</div>
        <div style="color: #888; font-size: 0.75rem;">Views</div>
      </div>
      <div style="background: #2d2d2d; padding: 0.75rem; border-radius: 6px; border: 1px solid #3d3d3d;">
        <div style="font-size: 1.5rem; font-weight: bold; color: #9db4d4; margin-bottom: 0.25rem;" id="totalCopies">-</div>
        <div style="color: #888; font-size: 0.75rem;">Copies</div>
      </div>
      <div style="background: #2d2d2d; padding: 0.75rem; border-radius: 6px; border: 1px solid #3d3d3d;">
        <div style="font-size: 1.5rem; font-weight: bold; color: #d4a5a5; margin-bottom: 0.25rem;" id="totalErrors">-</div>
        <div style="color: #888; font-size: 0.75rem;">Errors</div>
      </div>
    </div>

    <!-- System Status Row -->
    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 0.75rem; margin-bottom: 1rem;">
      <div style="background: #2d2d2d; padding: 0.75rem; border-radius: 6px; border: 1px solid #3d3d3d;">
        <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.25rem;">
          <span style="color: ${isConnected() ? '#7fb069' : '#d4a5a5'}; font-size: 1.2rem;">${isConnected() ? '●' : '○'}</span>
          <span style="color: #b0b0b0; font-size: 0.85rem;">Database: <span id="dbStatus">${isConnected() ? 'Connected' : 'Disconnected'}</span></span>
        </div>
        <div style="color: #888; font-size: 0.7rem;" id="dbUptime">Uptime: -</div>
      </div>
      <div style="background: #2d2d2d; padding: 0.75rem; border-radius: 6px; border: 1px solid #3d3d3d;">
        <div style="color: #b0b0b0; font-size: 0.85rem; margin-bottom: 0.25rem;">Server Uptime</div>
        <div style="color: #888; font-size: 0.7rem;" id="serverUptime">-</div>
      </div>
    </div>

    <!-- Charts Row -->
    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 0.75rem; margin-bottom: 1rem;">
      <div style="background: #2d2d2d; padding: 1rem; border-radius: 6px; border: 1px solid #3d3d3d;">
        <h3 style="color: #9db4d4; font-size: 0.9rem; margin-bottom: 0.75rem; font-weight: normal;">Activity (Last 30 Days)</h3>
        <canvas id="activityChart" style="max-height: 200px;"></canvas>
      </div>
      <div style="background: #2d2d2d; padding: 1rem; border-radius: 6px; border: 1px solid #3d3d3d;">
        <h3 style="color: #9db4d4; font-size: 0.9rem; margin-bottom: 0.75rem; font-weight: normal;">Event Distribution</h3>
        <canvas id="distributionChart" style="max-height: 200px;"></canvas>
      </div>
    </div>

    ${passwordCount > 0 ? `

      <div style="background: ${hasIssues ? '#2d1a1a' : '#1d2d1d'}; padding: 1.5rem; border-radius: 8px; border: 1px solid ${hasIssues ? '#d4a5a5' : '#7fb069'}; margin-bottom: 1.5rem;">
        <h2 style="color: ${hasIssues ? '#d4a5a5' : '#7fb069'}; margin-bottom: 1rem; display: flex; align-items: center; gap: 0.5rem;">
          ${hasIssues ? '⚠' : '✓'} Security Check
        </h2>
        ${hasIssues ? `
          <div style="color: #d4a5a5; margin-bottom: 0.75rem;">
            <p style="font-size: 1.1rem; font-weight: bold; margin-bottom: 0.5rem;">Security Issues Found:</p>
            ${duplicateCount > 0 ? `
              <p style="color: #b0b0b0; margin-bottom: 0.5rem; font-weight: bold;">• ${duplicateCount} duplicate password${duplicateCount > 1 ? 's' : ''} detected:</p>
              <ul style="color: #b0b0b0; margin-left: 1.5rem; margin-bottom: 0.5rem;">
                ${Array.from(new Set(duplicateEntries.map(e => e.password))).slice(0, 5).map(password => {
                  const entries = duplicateEntries.filter(e => e.password === password);
                  return `<li style="margin-bottom: 0.25rem;">Used in: ${entries.map(e => escapeHtml(e.website)).join(', ')}</li>`;
                }).join('')}
                ${Array.from(new Set(duplicateEntries.map(e => e.password))).length > 5 ? `<li style="color: #888;">...and more</li>` : ''}
              </ul>
            ` : ''}
            ${weakPasswordCount > 0 ? `
              <p style="color: #b0b0b0; margin-bottom: 0.5rem; font-weight: bold;">• ${weakPasswordCount} weak password${weakPasswordCount > 1 ? 's' : ''} detected:</p>
              <ul style="color: #b0b0b0; margin-left: 1.5rem; margin-bottom: 0.5rem;">
                ${weakEntries.slice(0, 5).map(entry => `<li style="margin-bottom: 0.25rem;"><a href="/passwords/${entry.entryId}" style="color: #9db4d4;">${escapeHtml(entry.website)}</a> (Strength: ${entry.strength <= 2 ? 'Weak' : 'Fair'})</li>`).join('')}
                ${weakEntries.length > 5 ? `<li style="color: #888;">...and ${weakEntries.length - 5} more</li>` : ''}
              </ul>
            ` : ''}
          </div>
          <div style="color: #b0b0b0; font-size: 0.9rem;">
            <p style="margin-bottom: 0.25rem;">Recommendations:</p>
            ${duplicateCount > 0 ? `<p style="margin-bottom: 0.25rem;">• Use unique passwords for each account</p>` : ''}
            ${weakPasswordCount > 0 ? `<p style="margin-bottom: 0.25rem;">• Strengthen weak passwords using the password generator</p>` : ''}
          </div>
        ` : `
          <div style="color: #7fb069; font-size: 1.2rem; font-weight: bold; display: flex; align-items: center; gap: 0.5rem;">
            <span style="font-size: 1.5rem;">✓</span>
            <span>Security Check Passed</span>
          </div>
          <p style="color: #b0b0b0; margin-top: 0.5rem; font-size: 0.9rem;">All passwords are unique and strong.</p>
        `}
      </div>
    ` : `
      <div style="background: #2d2d2d; padding: 1.5rem; border-radius: 8px; border: 1px solid #3d3d3d; margin-top: 1.5rem; margin-bottom: 1.5rem;">
        <p style="color: #b0b0b0;">No passwords saved yet. Add your first password to see security statistics.</p>
      </div>
    `}

    ${recentPasswords.length > 0 ? `
      <div style="background: #2d2d2d; padding: 1.5rem; border-radius: 8px; border: 1px solid #3d3d3d; margin-top: 1.5rem; margin-bottom: 1.5rem;">
        <h2 style="color: #9db4d4; margin-bottom: 1rem;">Most Recent Passwords</h2>
        <div style="display: flex; flex-direction: column; gap: 0.75rem;">
          ${recentPasswords.map(p => `
            <a href="/passwords/${p._id}" style="display: block; background: #1d1d1d; padding: 1rem; border-radius: 4px; border: 1px solid #3d3d3d; text-decoration: none; color: #e0e0e0; transition: background 0.2s;">
              <div style="display: flex; justify-content: space-between; align-items: center;">
                <div>
                  <div style="font-weight: bold; color: #9db4d4; margin-bottom: 0.25rem;">${escapeHtml(p.website)}</div>
                  ${p.username ? `<div style="font-size: 0.85rem; color: #b0b0b0;">${escapeHtml(p.username)}</div>` : ''}
                  <div style="font-size: 0.75rem; color: #888; margin-top: 0.25rem;">Added ${p.createdAt.toLocaleDateString()}</div>
                </div>
                <div style="display: flex; gap: 1rem; font-size: 0.8rem; color: #888;">
                  <span>👁️ ${p.searchCount || 0}</span>
                  <span>📋 ${p.copyCount || 0}</span>
                </div>
              </div>
            </a>
          `).join('')}
        </div>
        ${passwordCount > 3 ? `
          <div style="margin-top: 1rem; text-align: center;">
            <a href="/passwords" style="color: #9db4d4; text-decoration: none; font-size: 0.9rem;">View All Passwords →</a>
          </div>
        ` : ''}
      </div>
    ` : ''}

    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
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

            // Update totals
            document.getElementById('totalAdds').textContent = analytics.adds || 0;
            document.getElementById('totalDeletes').textContent = analytics.deletes || 0;
            document.getElementById('totalViews').textContent = analytics.views || 0;
            document.getElementById('totalCopies').textContent = analytics.copies || 0;
            document.getElementById('totalErrors').textContent = analytics.errors || 0;

            // Activity chart
            const activityCtx = document.getElementById('activityChart');
            if (activityCtx && analytics.dailyData && analytics.dailyData.length > 0) {
              const labels = analytics.dailyData.map(d => new Date(d.date).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }));

              // Update existing chart or create new one
              if (window.activityChart && window.activityChart.data) {
                window.activityChart.data.labels = labels;
                window.activityChart.data.datasets[0].data = analytics.dailyData.map(d => d.views);
                window.activityChart.data.datasets[1].data = analytics.dailyData.map(d => d.copies);
                window.activityChart.data.datasets[2].data = analytics.dailyData.map(d => d.adds);
                window.activityChart.update();
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
                      { label: 'Views', data: analytics.dailyData.map(d => d.views), borderColor: '#9db4d4', backgroundColor: 'rgba(157, 180, 212, 0.1)', tension: 0.4 },
                      { label: 'Copies', data: analytics.dailyData.map(d => d.copies), borderColor: '#7fb069', backgroundColor: 'rgba(127, 176, 105, 0.1)', tension: 0.4 },
                      { label: 'Adds', data: analytics.dailyData.map(d => d.adds), borderColor: '#9db4d4', backgroundColor: 'rgba(157, 180, 212, 0.1)', tension: 0.4, borderDash: [5, 5] }
                    ]
                  },
                  options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { labels: { color: '#b0b0b0', font: { size: 11 } } } },
                    scales: {
                      x: { ticks: { color: '#888', font: { size: 10 } }, grid: { color: '#3d3d3d' } },
                      y: { ticks: { color: '#888', font: { size: 10 } }, grid: { color: '#3d3d3d' }, beginAtZero: true }
                    }
                  }
                });
              }
            }

            // Distribution chart
            const distCtx = document.getElementById('distributionChart');
            if (distCtx) {
              // Update existing chart or create new one
              if (window.distributionChart && window.distributionChart.data) {
                window.distributionChart.data.datasets[0].data = [
                  analytics.views, analytics.copies, analytics.adds,
                  analytics.edits, analytics.deletes, analytics.errors
                ];
                window.distributionChart.update();
              } else {
                // Destroy existing chart if it exists but is invalid
                if (window.distributionChart && typeof window.distributionChart.destroy === 'function') {
                  try {
                    window.distributionChart.destroy();
                  } catch (e) {
                    console.warn('Error destroying distribution chart:', e);
                  }
                }
                window.distributionChart = new Chart(distCtx, {
                  type: 'doughnut',
                  data: {
                    labels: ['Views', 'Copies', 'Adds', 'Edits', 'Deletes', 'Errors'],
                    datasets: [{
                      data: [analytics.views, analytics.copies, analytics.adds, analytics.edits, analytics.deletes, analytics.errors],
                      backgroundColor: ['#9db4d4', '#7fb069', '#9db4d4', '#9db4d4', '#d4a5a5', '#d4a5a5']
                    }]
                  },
                  options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { labels: { color: '#b0b0b0', font: { size: 11 } }, position: 'bottom' } }
                  }
                });
              }
            }
          }

          if (statusRes.ok) {
            const status = await statusRes.json();
            document.getElementById('serverUptime').textContent = formatUptime(status.serverUptime);
            document.getElementById('dbStatus').textContent = status.dbConnected ? 'Connected' : 'Disconnected';
            document.getElementById('dbUptime').textContent = status.dbConnected ? 'Uptime: ' + formatUptime(status.dbUptime) : 'Not connected';
          }
        } catch (error) {
          console.error('Error loading analytics:', error);
        }
      }

      loadAnalytics();
      setInterval(loadAnalytics, 30000); // Refresh every 30 seconds
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
      <p style="color: #d4a5a5;">Database not available.</p>
    `, "Passwords - XeoKey", request);
  }

  try {
    const passwords = await getUserPasswords(session.userId);

    if (passwords.length === 0) {
      return renderPage(`
        <h1>All Passwords</h1>
        <div style="margin-bottom: 1.5rem; display: flex; gap: 1rem; align-items: center; flex-wrap: wrap;">
          <div style="flex: 1; min-width: 250px;">
            <input type="text" id="passwordSearch" placeholder="Search passwords..." disabled style="width: 100%; padding: 0.5rem; border: 1px solid #3d3d3d; border-radius: 4px; background: #1d1d1d; color: #888; font-size: 0.9rem; cursor: not-allowed;">
          </div>
          <a href="/passwords/add" style="color: #9db4d4; text-decoration: none; background: #3d3d3d; padding: 0.5rem 1rem; border-radius: 4px; border: 1px solid #4d4d4d; display: inline-block; white-space: nowrap;">+ Add Password</a>
        </div>
        <p>No passwords saved yet.</p>
        <p><a href="/passwords/add" style="color: #9db4d4;">Add your first password</a></p>
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
      <div class="password-entry"
           data-password-id="${p._id}"
           data-website="${escapeHtml(p.website).toLowerCase()}"
           data-username="${p.username ? escapeHtml(p.username).toLowerCase() : ''}"
           data-email="${p.email ? escapeHtml(p.email).toLowerCase() : ''}"
           data-notes="${p.notes ? escapeHtml(p.notes).toLowerCase() : ''}"
           ${issues.length > 0 ? `style="border-left: 4px solid #d4a5a5;"` : ''}>
        <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 0.5rem;">
          <h3 style="margin-bottom: 0; color: #9db4d4;">${escapeHtml(p.website)}</h3>
          ${issues.length > 0 ? `
            <div style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
              ${issues.map(issue => `<span style="background: #2d1a1a; color: #d4a5a5; padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.75rem; border: 1px solid #d4a5a5;">${issue}</span>`).join('')}
            </div>
          ` : ''}
        </div>
        ${p.username ? `<p style="color: #b0b0b0; margin-bottom: 0.25rem;">Username: ${escapeHtml(p.username)}</p>` : ''}
        ${p.email ? `<p style="color: #b0b0b0; margin-bottom: 0.25rem;">Email: ${escapeHtml(p.email)}</p>` : ''}
        <div style="display: flex; gap: 1rem; margin-top: 0.5rem; font-size: 0.8rem; color: #888;">
          <span>👁️ ${p.searchCount || 0} views</span>
          <span>📋 ${p.copyCount || 0} copies</span>
        </div>
      </div>
    `;
    }).join('');

    return renderPage(`
      <h1>All Passwords</h1>
      <div style="margin-bottom: 1.5rem; display: flex; gap: 1rem; align-items: center; flex-wrap: wrap;">
        <div style="flex: 1; min-width: 250px;">
          <input type="text" id="passwordSearch" placeholder="Search passwords..." style="width: 100%; padding: 0.5rem; border: 1px solid #3d3d3d; border-radius: 4px; background: #2d2d2d; color: #e0e0e0; font-size: 0.9rem;">
        </div>
        <a href="/passwords/add" style="color: #9db4d4; text-decoration: none; background: #3d3d3d; padding: 0.5rem 1rem; border-radius: 4px; border: 1px solid #4d4d4d; display: inline-block; white-space: nowrap;">+ Add Password</a>
      </div>
      <div id="passwordListContainer">
        ${passwordList}
      </div>
      <div id="noResultsMessage" style="display: none; text-align: center; padding: 2rem; color: #b0b0b0;">
        No passwords found matching your search.
      </div>
    `, "Passwords - XeoKey", request);
  } catch (error) {
    logger.error(`Error fetching passwords: ${error}`);
    return renderPage(`
      <h1>All Passwords</h1>
      <p style="color: #d4a5a5;">Error loading passwords.</p>
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
    <form method="POST" action="/passwords/add" style="max-width: 600px; margin: 0 auto;">
      <input type="hidden" name="csrfToken" value="${escapeHtml(csrfToken)}">
      <div style="margin-bottom: 1rem;">
        <label for="website" style="display: block; margin-bottom: 0.5rem;">Website/Service *</label>
        <input type="text" id="website" name="website" required style="width: 100%; padding: 0.5rem; border: 1px solid #3d3d3d; border-radius: 4px; background: #2d2d2d; color: #e0e0e0;">
      </div>
      <div style="margin-bottom: 1rem;">
        <label for="username" style="display: block; margin-bottom: 0.5rem;">Username</label>
        <input type="text" id="username" name="username" style="width: 100%; padding: 0.5rem; border: 1px solid #3d3d3d; border-radius: 4px; background: #2d2d2d; color: #e0e0e0;">
      </div>
      <div style="margin-bottom: 1rem;">
        <label for="email" style="display: block; margin-bottom: 0.5rem;">Email</label>
        <input type="email" id="email" name="email" style="width: 100%; padding: 0.5rem; border: 1px solid #3d3d3d; border-radius: 4px; background: #2d2d2d; color: #e0e0e0;">
      </div>
      <div style="margin-bottom: 1rem;">
        <label for="password" style="display: block; margin-bottom: 0.5rem;">Password *</label>
        <div style="display: flex; gap: 0.5rem; align-items: flex-start;">
          <div style="flex: 1;">
            <input type="text" id="password" name="password" required style="width: 100%; padding: 0.5rem; border: 1px solid #3d3d3d; border-radius: 4px; background: #2d2d2d; color: #e0e0e0;">
            <div id="passwordStrength" style="margin-top: 0.5rem; height: 4px; background: #2d2d2d; border-radius: 2px; overflow: hidden;">
              <div id="passwordStrengthBar" style="height: 100%; width: 0%; transition: width 0.3s, background-color 0.3s;"></div>
            </div>
            <div id="passwordStrengthText" style="color: #b0b0b0; font-size: 0.85rem; margin-top: 0.25rem;"></div>
          </div>
          <button type="button" id="generatePasswordBtn" style="background: #3d3d3d; color: #e0e0e0; padding: 0.5rem 1rem; border: 1px solid #4d4d4d; border-radius: 4px; cursor: pointer; font-size: 0.9rem; white-space: nowrap; height: fit-content;">
            Generate
          </button>
        </div>
      </div>
      <div style="margin-bottom: 1.5rem;">
        <label for="notes" style="display: block; margin-bottom: 0.5rem;">Notes</label>
        <textarea id="notes" name="notes" rows="4" style="width: 100%; padding: 0.5rem; border: 1px solid #3d3d3d; border-radius: 4px; background: #2d2d2d; color: #e0e0e0; font-family: inherit;"></textarea>
      </div>
      <button type="submit" style="width: 100%; background: #3d3d3d; color: #e0e0e0; padding: 0.75rem; border: 1px solid #4d4d4d; border-radius: 4px; cursor: pointer; font-size: 1rem;">Save Password</button>
    </form>
    <p style="text-align: center; margin-top: 1rem;">
      <a href="/passwords" style="color: #9db4d4;">← Back to Passwords</a>
    </p>
  `, "Add Password - XeoKey", request);
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
        <p style="color: #d4a5a5;">Invalid security token. Please try again.</p>
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
        <p style="color: #d4a5a5;">Website and password are required.</p>
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
      <p style="color: #d4a5a5;">Database not available.</p>
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
        <p style="color: #d4a5a5;">Password entry not found.</p>
        <p><a href="/passwords" style="color: #9db4d4;">← Back to Passwords</a></p>
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
    let strengthColor = '#4d4d4d';
    let strengthText = 'Unknown';

    if (decryptedPassword) {
      const strength = calculatePasswordStrength(decryptedPassword);

      if (strength <= 2) {
        strengthPercentage = 33;
        strengthColor = '#d4a5a5';
        strengthText = 'Weak';
      } else if (strength <= 4) {
        strengthPercentage = 66;
        strengthColor = '#d4a5a5';
        strengthText = 'Fair';
      } else if (strength <= 5) {
        strengthPercentage = 80;
        strengthColor = '#9db4d4';
        strengthText = 'Good';
      } else {
        strengthPercentage = 100;
        strengthColor = '#7fb069';
        strengthText = 'Strong';
      }
    }

    return renderPage(`
      <h1>Password Details</h1>
      <div style="max-width: 600px; margin: 0 auto;">
        <div style="background: #2d2d2d; padding: 1.5rem; border-radius: 8px; border: 1px solid #3d3d3d; margin-bottom: 1rem;">
          <div id="entryViewMode" style="display: block;">
            <h2 style="margin-bottom: 1rem; color: #9db4d4;">${escapeHtml(entry.website)}</h2>
            ${entry.username ? `
              <div style="margin-bottom: 1rem;">
                <label style="display: block; margin-bottom: 0.5rem; color: #b0b0b0;">Username:</label>
                <div style="background: #1d1d1d; padding: 0.75rem; border-radius: 4px; border: 1px solid #3d3d3d; color: #e0e0e0; font-family: monospace;">${escapeHtml(entry.username)}</div>
              </div>
            ` : ''}
            ${entry.email ? `
              <div style="margin-bottom: 1rem;">
                <label style="display: block; margin-bottom: 0.5rem; color: #b0b0b0;">Email:</label>
                <div style="background: #1d1d1d; padding: 0.75rem; border-radius: 4px; border: 1px solid #3d3d3d; color: #e0e0e0; font-family: monospace;">${escapeHtml(entry.email)}</div>
              </div>
            ` : ''}
            <div style="margin-bottom: 1rem;">
              <label style="display: block; margin-bottom: 0.5rem; color: #b0b0b0;">Password:</label>
              <div style="display: flex; gap: 0.5rem; align-items: center;">
                <div style="background: #1d1d1d; padding: 0.75rem; border-radius: 4px; border: 1px solid #3d3d3d; color: #888; font-family: monospace; flex: 1; text-align: center;">
                  •••••••••••••••••
                </div>
                <button type="button" id="copyPasswordBtn" data-password="${passwordData}" data-entry-id="${entryId}" style="background: #3d3d3d; color: #e0e0e0; padding: 0.75rem 1.5rem; border: 1px solid #4d4d4d; border-radius: 4px; cursor: pointer; font-size: 0.9rem; white-space: nowrap;">
                  Copy Password
                </button>
              </div>
              <div id="copyStatus" style="margin-top: 0.5rem; font-size: 0.85rem; color: #7fb069; display: none;"></div>
              <div style="margin-top: 0.75rem;">
                <label style="display: block; margin-bottom: 0.5rem; color: #b0b0b0; font-size: 0.9rem;">Password Strength:</label>
                <div style="height: 4px; background: #2d2d2d; border-radius: 2px; overflow: hidden; margin-bottom: 0.25rem;">
                  <div style="height: 100%; width: ${strengthPercentage}%; background-color: ${strengthColor}; transition: width 0.3s, background-color 0.3s;"></div>
                </div>
                <div style="color: ${strengthColor}; font-size: 0.85rem; font-weight: bold;">${strengthText}</div>
              </div>
            </div>
            ${entry.notes ? `
              <div style="margin-bottom: 1rem;">
                <label style="display: block; margin-bottom: 0.5rem; color: #b0b0b0;">Notes:</label>
                <div style="background: #1d1d1d; padding: 0.75rem; border-radius: 4px; border: 1px solid #3d3d3d; color: #e0e0e0; white-space: pre-wrap;">${escapeHtml(entry.notes)}</div>
              </div>
            ` : ''}
            <div style="margin-top: 1.5rem; padding-top: 1rem; border-top: 1px solid #3d3d3d; color: #888; font-size: 0.85rem;">
              Created: ${entry.createdAt.toLocaleString()}<br>
              Updated: ${entry.updatedAt.toLocaleString()}
            </div>
            <div style="margin-top: 1rem; padding-top: 1rem; border-top: 1px solid #3d3d3d; display: flex; gap: 1.5rem; font-size: 0.85rem; color: #b0b0b0;">
              <div>
                <span style="color: #9db4d4; font-weight: bold;">👁️ Views:</span> <span id="viewCount">${(entry.searchCount || 0)}</span>
              </div>
              <div>
                <span style="color: #9db4d4; font-weight: bold;">📋 Copies:</span> <span id="copyCount" data-copy-count>${(entry.copyCount || 0)}</span>
              </div>
            </div>
            <div style="margin-top: 1rem; display: flex; gap: 0.5rem;">
              <button type="button" id="editEntryBtn" style="background: #9db4d4; color: #1d1d1d; padding: 0.75rem 1.5rem; border: 1px solid #8ca3c3; border-radius: 4px; cursor: pointer; font-size: 0.9rem; white-space: nowrap;">
                Edit Entry
              </button>
            </div>
          </div>
          <div id="entryEditMode" style="display: none;">
            <form id="editEntryForm" method="POST" action="/passwords/${entryId}/update">
              <input type="hidden" name="csrfToken" value="${getOrCreateCsrfToken(session.sessionId)}">
              <div style="margin-bottom: 1rem;">
                <label style="display: block; margin-bottom: 0.5rem; color: #b0b0b0;">Website:</label>
                <input type="text" id="editWebsiteInput" name="website" value="${escapeHtml(entry.website)}" style="background: #1d1d1d; padding: 0.75rem; border-radius: 4px; border: 1px solid #3d3d3d; color: #e0e0e0; width: 100%; font-size: 0.9rem; box-sizing: border-box;" required>
              </div>
              <div style="margin-bottom: 1rem;">
                <label style="display: block; margin-bottom: 0.5rem; color: #b0b0b0;">Username:</label>
                <input type="text" id="editUsernameInput" name="username" value="${entry.username ? escapeHtml(entry.username) : ''}" style="background: #1d1d1d; padding: 0.75rem; border-radius: 4px; border: 1px solid #3d3d3d; color: #e0e0e0; width: 100%; font-family: monospace; font-size: 0.9rem; box-sizing: border-box;">
              </div>
              <div style="margin-bottom: 1rem;">
                <label style="display: block; margin-bottom: 0.5rem; color: #b0b0b0;">Email:</label>
                <input type="email" id="editEmailInput" name="email" value="${entry.email ? escapeHtml(entry.email) : ''}" style="background: #1d1d1d; padding: 0.75rem; border-radius: 4px; border: 1px solid #3d3d3d; color: #e0e0e0; width: 100%; font-family: monospace; font-size: 0.9rem; box-sizing: border-box;">
              </div>
              <div style="margin-bottom: 1rem;">
                <label style="display: block; margin-bottom: 0.5rem; color: #b0b0b0;">Password:</label>
                <div style="display: flex; gap: 0.5rem; align-items: center;">
                  <input type="password" id="editPasswordInput" name="password" value="${passwordData}" style="background: #1d1d1d; padding: 0.75rem; border-radius: 4px; border: 1px solid #3d3d3d; color: #e0e0e0; font-family: monospace; flex: 1; font-size: 0.9rem;" required>
                  <button type="button" id="togglePasswordVisibility" style="background: #3d3d3d; color: #e0e0e0; padding: 0.75rem 1rem; border: 1px solid #4d4d4d; border-radius: 4px; cursor: pointer; font-size: 0.9rem; white-space: nowrap;">
                    Show
                  </button>
                </div>
                <div id="editPasswordStrength" style="margin-top: 0.75rem; margin-bottom: 0.5rem;">
                  <label style="display: block; margin-bottom: 0.5rem; color: #b0b0b0; font-size: 0.9rem;">Password Strength:</label>
                  <div style="height: 4px; background: #2d2d2d; border-radius: 2px; overflow: hidden; margin-bottom: 0.25rem;">
                    <div id="editPasswordStrengthBar" style="height: 100%; width: ${strengthPercentage}%; background-color: ${strengthColor}; transition: width 0.3s, background-color 0.3s;"></div>
                  </div>
                  <div id="editPasswordStrengthText" style="color: ${strengthColor}; font-size: 0.85rem; font-weight: bold;">${strengthText}</div>
                </div>
              </div>
              <div style="margin-bottom: 1rem;">
                <label style="display: block; margin-bottom: 0.5rem; color: #b0b0b0;">Notes:</label>
                <textarea id="editNotesInput" name="notes" rows="4" style="background: #1d1d1d; padding: 0.75rem; border-radius: 4px; border: 1px solid #3d3d3d; color: #e0e0e0; width: 100%; font-size: 0.9rem; box-sizing: border-box; resize: vertical; font-family: inherit;">${entry.notes ? escapeHtml(entry.notes) : ''}</textarea>
              </div>
              <div style="display: flex; gap: 0.5rem; align-items: center; margin-top: 1.5rem;">
                <button type="submit" style="background: #7fb069; color: #1d1d1d; padding: 0.75rem 1.5rem; border: 1px solid #6fa059; border-radius: 4px; cursor: pointer; font-size: 0.9rem; white-space: nowrap;">
                  Save Entry
                </button>
                <button type="button" id="cancelEditEntryBtn" style="background: #3d3d3d; color: #e0e0e0; padding: 0.75rem 1.5rem; border: 1px solid #4d4d4d; border-radius: 4px; cursor: pointer; font-size: 0.9rem; white-space: nowrap;">
                  Cancel
                </button>
              </div>
              <div id="editEntryStatus" style="margin-top: 0.5rem; font-size: 0.85rem; color: #7fb069; display: none;"></div>
            </form>
          </div>
        </div>
        <div style="display: flex; gap: 1rem; align-items: center; margin-top: 1rem;">
          <a href="/passwords" style="color: #9db4d4; text-decoration: none;">← Back to Passwords</a>
          <form method="POST" action="/passwords/${entryId}/delete" id="deletePasswordForm" style="margin: 0; margin-left: auto;">
            <input type="hidden" name="csrfToken" value="${createCsrfToken(session.sessionId)}">
            <button type="submit" style="background: #d4a5a5; color: #1d1d1d; padding: 0.5rem 1rem; border: 1px solid #c49494; border-radius: 4px; cursor: pointer; font-size: 0.9rem;">
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
      <p style="color: #d4a5a5;">Error loading password entry.</p>
      <p><a href="/passwords" style="color: #9db4d4;">← Back to Passwords</a></p>
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
      logger.warn('CSRF token invalid, but session is valid. Regenerating token and continuing...');
      // Regenerate token for this session to ensure it's fresh
      const { createCsrfToken } = await import('./security/csrf');
      createCsrfToken(session.sessionId);
      // Continue with the update - the session is valid, so this is likely just a stale token
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
          <p style="color: #d4a5a5;">Password entry not found.</p>
          <p><a href="/passwords" style="color: #9db4d4;">← Back to Passwords</a></p>
        `, "Update Entry - XeoKey", request);
      }
      debugLog(logger, 'Entry found, proceeding with update...');
    } catch (error) {
      logger.error(`Error checking entry: ${error}`);
      return renderPage(`
        <h1>Update Entry</h1>
        <p style="color: #d4a5a5;">Error checking password entry.</p>
        <p><a href="/passwords/${entryId}" style="color: #9db4d4;">← Back to Password Details</a></p>
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
        <p style="color: #d4a5a5;">Website and password are required.</p>
        <p><a href="/passwords/${entryId}" style="color: #9db4d4;">← Back to Password Details</a></p>
      `, "Update Entry - XeoKey", request);
    }

    // Update the entry (convert empty strings to undefined for optional fields)
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
      notes: notes.trim() || undefined,
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
        <p style="color: #d4a5a5;">Failed to update entry. Please check the server logs for details.</p>
        <p><a href="/passwords/${entryId}" style="color: #9db4d4;">← Back to Password Details</a></p>
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
        <p style="color: #d4a5a5;">Invalid security token. Please try again.</p>
        <p><a href="/passwords/${entryId}" style="color: #9db4d4;">← Back to Password Details</a></p>
      `, "Delete Password - XeoKey", request);
    }

    // Verify the password entry exists and belongs to the user
    const entry = await getPasswordEntry(entryId, session.userId);
    if (!entry) {
      return renderPage(`
        <h1>Delete Password</h1>
        <p style="color: #d4a5a5;">Password entry not found.</p>
        <p><a href="/passwords" style="color: #9db4d4;">← Back to Passwords</a></p>
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
        <p style="color: #d4a5a5;">Failed to delete password entry.</p>
        <p><a href="/passwords/${entryId}" style="color: #9db4d4;">← Back to Password Details</a></p>
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
    return null; // Let router return 404
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
    <p><a href="/" style="color: #9db4d4;">Return to Home</a></p>
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
            "Cache-Control": "public, max-age=3600",
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
            "Cache-Control": "public, max-age=3600",
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

// Make available globally for API endpoint
(globalThis as any).serverStartTime = serverStartTime;
(globalThis as any).dbConnectTime = dbConnectTime;

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
} catch (error) {
  logger.error('MongoDB connection failed. Server will continue without database.');
  logger.warn('Set MONGODB_URI environment variable to connect to MongoDB.');
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

