'use strict';
const crypto = require('crypto');

class SessionManager {
  constructor(opts = {}) {
    this.store = new Map();
    this.cookieName = opts.cookieName || 'sid';
    this.maxAge = opts.maxAge || 86400000;
    this.secure = opts.secure !== false;
    this.httpOnly = opts.httpOnly !== false;
    this.sameSite = opts.sameSite || 'Strict';
    this._cleanup = setInterval(() => this._gc(), 60000);
    if (this._cleanup.unref) this._cleanup.unref();
  }

  create(userData) {
    const sid = crypto.randomBytes(32).toString('hex');
    this.store.set(sid, { data: userData, createdAt: Date.now(), expiresAt: Date.now() + this.maxAge });
    const cookie = this.cookieName + '=' + sid + '; Path=/; Max-Age=' + Math.floor(this.maxAge / 1000) + (this.httpOnly ? '; HttpOnly' : '') + (this.secure ? '; Secure' : '') + '; SameSite=' + this.sameSite;
    return { sid, cookie };
  }

  get(sid) {
    const s = this.store.get(sid);
    if (!s) return null;
    if (Date.now() > s.expiresAt) { this.store.delete(sid); return null; }
    return s.data;
  }

  destroy(sid) { this.store.delete(sid); }
  count() { return this.store.size; }
  _gc() { const now = Date.now(); for (const [sid, s] of this.store) if (now > s.expiresAt) this.store.delete(sid); }
  close() { clearInterval(this._cleanup); }
}
module.exports = { SessionManager };
