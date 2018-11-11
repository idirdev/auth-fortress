'use strict';
const crypto = require('crypto');

class ApiKeyAuth {
  constructor(opts = {}) {
    this.keys = new Map();
    this.prefix = opts.prefix || 'ak_';
    if (opts.keys) for (const [k, m] of Object.entries(opts.keys)) this.register(k, m);
  }

  generate(meta = {}) {
    const raw = this.prefix + crypto.randomBytes(24).toString('hex');
    const hash = this._hash(raw);
    this.keys.set(hash, { ...meta, createdAt: new Date().toISOString(), lastUsed: null, usageCount: 0, active: true });
    return { key: raw, hash };
  }

  register(key, meta = {}) { const h = this._hash(key); this.keys.set(h, { ...meta, active: true, usageCount: 0, lastUsed: null }); return h; }

  validate(key) {
    const h = this._hash(key), m = this.keys.get(h);
    if (!m || !m.active) return null;
    m.lastUsed = new Date().toISOString(); m.usageCount++;
    return { ...m, apiKey: h };
  }

  revoke(hash) { const m = this.keys.get(hash); if (m) m.active = false; }
  list() { return [...this.keys.entries()].map(([h, m]) => ({ hash: h.slice(0, 12) + '...', ...m })); }
  _hash(k) { return crypto.createHash('sha256').update(k).digest('hex'); }
}
module.exports = { ApiKeyAuth };
