/**
 * @file index.js
 * @description Authentication and authorization library: JWT, API keys,
 *   rate limiting, RBAC, password hashing, and session management.
 * @module auth-fortress
 * @author idirdev
 */

'use strict';

const crypto = require('crypto');

// ─── JWT ──────────────────────────────────────────────────────────────────────

const JWT_DEFAULT_EXPIRY = 3600; // seconds

/**
 * Encodes data as Base64URL.
 * @param {string|Buffer} data
 * @returns {string}
 */
function _b64u(data) {
  const buf = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8');
  return buf.toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

/**
 * Decodes a Base64URL string.
 * @param {string} str
 * @returns {string}
 */
function _b64d(str) {
  const padded = str + '='.repeat((4 - (str.length % 4)) % 4);
  return Buffer.from(padded.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
}

// ─── AuthFortress class ───────────────────────────────────────────────────────

/**
 * AuthFortress — a comprehensive authentication/authorization toolkit.
 *
 * @example
 * const auth = new AuthFortress({ jwtSecret: 'mySecret' });
 * const token = auth.generateToken({ userId: 1 });
 * const payload = auth.verifyToken(token);
 */
class AuthFortress {
  /**
   * Creates a new AuthFortress instance.
   * @param {Object} [opts={}] - Configuration options.
   * @param {string} [opts.jwtSecret='default-secret-change-me'] - JWT signing secret.
   * @param {number} [opts.jwtExpiresIn=3600] - Default JWT expiry in seconds.
   */
  constructor(opts = {}) {
    this._jwtSecret = opts.jwtSecret || 'default-secret-change-me';
    this._jwtExpiresIn = opts.jwtExpiresIn || JWT_DEFAULT_EXPIRY;
    this._roles = new Map();
    this._sessions = new Map();
    this._rateBuckets = new Map();
  }

  // ── JWT ────────────────────────────────────────────────────────────────────

  /**
   * Generates a signed HS256 JWT token.
   * @param {Object} payload - Claims to embed in the token.
   * @param {Object} [opts={}] - Override options.
   * @param {number} [opts.expiresIn] - Token lifetime in seconds.
   * @returns {string} Signed JWT.
   */
  generateToken(payload, opts = {}) {
    const now = Math.floor(Date.now() / 1000);
    const exp = now + (opts.expiresIn !== undefined ? opts.expiresIn : this._jwtExpiresIn);
    const claims = Object.assign({}, payload, { iat: now, exp });
    const header = _b64u(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
    const body = _b64u(JSON.stringify(claims));
    const sig = crypto.createHmac('sha256', this._jwtSecret)
      .update(`${header}.${body}`)
      .digest('base64')
      .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    return `${header}.${body}.${sig}`;
  }

  /**
   * Verifies a JWT token and returns its payload.
   * @param {string} token - The JWT string.
   * @returns {Object} Decoded payload.
   * @throws {Error} On invalid signature or expiration.
   */
  verifyToken(token) {
    const parts = token.split('.');
    if (parts.length !== 3) throw new Error('Invalid token format');
    const signingInput = `${parts[0]}.${parts[1]}`;
    const expected = crypto.createHmac('sha256', this._jwtSecret)
      .update(signingInput)
      .digest('base64')
      .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    if (expected !== parts[2]) throw new Error('Invalid token signature');
    let payload;
    try { payload = JSON.parse(_b64d(parts[1])); } catch { throw new Error('Malformed token payload'); }
    if (payload.exp !== undefined && Math.floor(Date.now() / 1000) >= payload.exp) {
      throw new Error('Token has expired');
    }
    return payload;
  }

  /**
   * Issues a new token from an existing (possibly expired) token's payload.
   * @param {string} token - The original JWT.
   * @param {Object} [opts={}] - Override options for the new token.
   * @returns {string} Refreshed JWT.
   */
  refreshToken(token, opts = {}) {
    const parts = token.split('.');
    if (parts.length !== 3) throw new Error('Invalid token format');
    let payload;
    try { payload = JSON.parse(_b64d(parts[1])); } catch { throw new Error('Malformed token'); }
    const { iat, exp, ...claims } = payload; // eslint-disable-line no-unused-vars
    return this.generateToken(claims, opts);
  }

  // ── API Keys ───────────────────────────────────────────────────────────────

  /**
   * Generates a cryptographically random API key.
   * @param {string} [prefix='ak'] - Key prefix for identification.
   * @returns {string} API key string in the form `prefix_<hex>`.
   */
  generateApiKey(prefix = 'ak') {
    const raw = crypto.randomBytes(32).toString('hex');
    return `${prefix}_${raw}`;
  }

  /**
   * Validates an API key against a key store.
   * @param {string} key - The API key to validate.
   * @param {Set|Map|string[]} store - Collection of valid keys.
   * @returns {boolean} True if key is present in the store.
   */
  validateApiKey(key, store) {
    if (store instanceof Set) return store.has(key);
    if (store instanceof Map) return store.has(key);
    if (Array.isArray(store)) return store.includes(key);
    return false;
  }

  // ── Rate Limiter ───────────────────────────────────────────────────────────

  /**
   * Creates a new rate limiter configuration.
   * @param {Object} [opts={}] - Limiter settings.
   * @param {number} [opts.windowMs=60000] - Time window in milliseconds.
   * @param {number} [opts.maxRequests=100] - Maximum allowed requests per window.
   * @returns {{ check: function(string): {allowed: boolean, remaining: number, resetTime: number} }}
   */
  createRateLimiter(opts = {}) {
    const windowMs = opts.windowMs || 60000;
    const maxRequests = opts.maxRequests || 100;
    const buckets = new Map();

    return {
      /**
       * Checks whether the given key is within rate limits.
       * @param {string} key - Identifier (e.g. IP, userId).
       * @returns {{ allowed: boolean, remaining: number, resetTime: number }}
       */
      check(key) {
        const now = Date.now();
        let bucket = buckets.get(key);
        if (!bucket || now >= bucket.resetTime) {
          bucket = { count: 0, resetTime: now + windowMs };
          buckets.set(key, bucket);
        }
        bucket.count++;
        const allowed = bucket.count <= maxRequests;
        const remaining = Math.max(0, maxRequests - bucket.count);
        return { allowed, remaining, resetTime: bucket.resetTime };
      },
    };
  }

  // ── RBAC ───────────────────────────────────────────────────────────────────

  /**
   * Defines a named role with a list of permissions.
   * @param {string} name - Role name.
   * @param {string[]} permissions - Array of permission strings.
   */
  defineRole(name, permissions) {
    this._roles.set(name, new Set(permissions));
  }

  /**
   * Checks whether a role has a specific permission.
   * @param {string} role - Role name.
   * @param {string} permission - Permission to check.
   * @returns {boolean} True if the role grants that permission.
   */
  hasPermission(role, permission) {
    const perms = this._roles.get(role);
    if (!perms) return false;
    return perms.has(permission) || perms.has('*');
  }

  /**
   * Asserts that a role has the required permission.
   * @param {string} role - Role name.
   * @param {string} requiredPermission - Permission required.
   * @throws {Error} If the role lacks the permission.
   */
  authorize(role, requiredPermission) {
    if (!this.hasPermission(role, requiredPermission)) {
      throw new Error(`Role "${role}" lacks permission "${requiredPermission}"`);
    }
  }

  // ── Password Hasher ────────────────────────────────────────────────────────

  /**
   * Hashes a password using scrypt with a random salt.
   * @param {string} password - Plain-text password.
   * @returns {Promise<string>} Colon-separated "salt:hash" string.
   */
  hashPassword(password) {
    return new Promise((resolve, reject) => {
      const salt = crypto.randomBytes(16).toString('hex');
      crypto.scrypt(password, salt, 64, (err, derived) => {
        if (err) return reject(err);
        resolve(`${salt}:${derived.toString('hex')}`);
      });
    });
  }

  /**
   * Verifies a plain-text password against a stored hash.
   * @param {string} password - Plain-text password to check.
   * @param {string} storedHash - The "salt:hash" string from hashPassword.
   * @returns {Promise<boolean>} True if the password matches.
   */
  verifyPassword(password, storedHash) {
    return new Promise((resolve, reject) => {
      const [salt, hash] = storedHash.split(':');
      crypto.scrypt(password, salt, 64, (err, derived) => {
        if (err) return reject(err);
        const candidate = Buffer.from(derived.toString('hex'));
        const stored = Buffer.from(hash);
        try {
          resolve(candidate.length === stored.length && crypto.timingSafeEqual(candidate, stored));
        } catch {
          resolve(false);
        }
      });
    });
  }

  // ── Session Manager ────────────────────────────────────────────────────────

  /**
   * Creates a new session for a user.
   * @param {string|number} userId - The user identifier.
   * @param {Object} [data={}] - Additional session data.
   * @param {number} [ttlMs=1800000] - Session TTL in milliseconds (default 30 min).
   * @returns {{ id: string, userId: string|number, data: Object, expiresAt: number }}
   */
  createSession(userId, data = {}, ttlMs = 1800000) {
    const id = crypto.randomBytes(24).toString('hex');
    const session = { id, userId, data, expiresAt: Date.now() + ttlMs };
    this._sessions.set(id, session);
    return session;
  }

  /**
   * Retrieves a session by ID if it has not expired.
   * @param {string} id - Session ID.
   * @returns {Object|null} Session object or null.
   */
  getSession(id) {
    const session = this._sessions.get(id);
    if (!session) return null;
    if (Date.now() > session.expiresAt) {
      this._sessions.delete(id);
      return null;
    }
    return session;
  }

  /**
   * Destroys a session by ID.
   * @param {string} id - Session ID.
   * @returns {boolean} True if the session existed and was removed.
   */
  destroySession(id) {
    return this._sessions.delete(id);
  }

  /**
   * Removes all expired sessions.
   * @returns {number} Number of sessions removed.
   */
  cleanExpired() {
    const now = Date.now();
    let count = 0;
    for (const [id, session] of this._sessions) {
      if (now > session.expiresAt) {
        this._sessions.delete(id);
        count++;
      }
    }
    return count;
  }

  // ── Express Middleware ────────────────────────────────────────────────────

  /**
   * Returns an Express-compatible JWT authentication middleware.
   * Attaches the decoded payload to req.user on success.
   * @returns {function(req, res, next): void}
   */
  middleware() {
    return (req, res, next) => {
      const authHeader = req.headers && req.headers['authorization'];
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Missing or invalid Authorization header' });
      }
      const token = authHeader.slice(7);
      try {
        req.user = this.verifyToken(token);
        next();
      } catch (e) {
        return res.status(401).json({ error: e.message });
      }
    };
  }
}

module.exports = { AuthFortress };
