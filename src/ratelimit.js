'use strict';
class RateLimiter {
  constructor(opts = {}) {
    this.max = opts.max || 100;
    this.windowMs = opts.windowMs || 60000;
    this.windowSec = Math.ceil(this.windowMs / 1000);
    this.store = new Map();
    this.strategy = opts.strategy || 'sliding-window';
    this._cleanup = setInterval(() => this._gc(), this.windowMs);
    if (this._cleanup.unref) this._cleanup.unref();
  }

  check(key) {
    const now = Date.now();
    let entry = this.store.get(key);
    if (this.strategy === 'fixed-window') {
      if (!entry || now > entry.resetAt) { entry = { count: 0, resetAt: now + this.windowMs }; this.store.set(key, entry); }
      if (entry.count >= this.max) return false;
      entry.count++; return true;
    }
    if (!entry) { entry = { hits: [] }; this.store.set(key, entry); }
    entry.hits = entry.hits.filter(t => now - t < this.windowMs);
    if (entry.hits.length >= this.max) return false;
    entry.hits.push(now); return true;
  }

  remaining(key) {
    const e = this.store.get(key);
    if (!e) return this.max;
    if (e.hits) return Math.max(0, this.max - e.hits.filter(t => Date.now() - t < this.windowMs).length);
    if (Date.now() > e.resetAt) return this.max;
    return Math.max(0, this.max - e.count);
  }

  reset(key) { this.store.delete(key); }
  _gc() { const now = Date.now(); for (const [k, e] of this.store) { if (e.hits) { e.hits = e.hits.filter(t => now - t < this.windowMs); if (!e.hits.length) this.store.delete(k); } else if (now > e.resetAt) this.store.delete(k); } }
  destroy() { clearInterval(this._cleanup); }
}
module.exports = { RateLimiter };
