'use strict';
const crypto = require('crypto');

class JwtAuth {
  constructor(opts = {}) {
    this.secret = opts.secret || crypto.randomBytes(32).toString('hex');
    this.expiresIn = opts.expiresIn || 3600;
    this.issuer = opts.issuer || undefined;
    this.audience = opts.audience || undefined;
    this.clockTolerance = opts.clockTolerance || 0;
    this.blacklist = new Set();
  }

  sign(payload, options = {}) {
    const header = { alg: 'HS256', typ: 'JWT' };
    const now = Math.floor(Date.now() / 1000);
    const claims = { ...payload, iat: now, exp: now + (options.expiresIn || this.expiresIn), jti: crypto.randomUUID() };
    if (this.issuer) claims.iss = this.issuer;
    if (this.audience) claims.aud = this.audience;
    const hB64 = b64url(JSON.stringify(header));
    const pB64 = b64url(JSON.stringify(claims));
    const sig = this._hmac(hB64 + '.' + pB64);
    return hB64 + '.' + pB64 + '.' + sig;
  }

  verify(token) {
    const parts = token.split('.');
    if (parts.length !== 3) throw tokenErr('INVALID_TOKEN', 'Malformed token');
    const sig = this._hmac(parts[0] + '.' + parts[1]);
    if (!tsEqual(sig, parts[2])) throw tokenErr('INVALID_TOKEN', 'Invalid signature');
    let payload;
    try { payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString()); }
    catch { throw tokenErr('INVALID_TOKEN', 'Invalid payload'); }
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp && now > payload.exp + this.clockTolerance) throw tokenErr('TOKEN_EXPIRED', 'Token expired');
    if (payload.nbf && now < payload.nbf - this.clockTolerance) throw tokenErr('INVALID_TOKEN', 'Token not yet valid');
    if (this.issuer && payload.iss !== this.issuer) throw tokenErr('INVALID_TOKEN', 'Invalid issuer');
    if (this.audience) {
      const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
      const exp = Array.isArray(this.audience) ? this.audience : [this.audience];
      if (!exp.some(a => aud.includes(a))) throw tokenErr('INVALID_TOKEN', 'Invalid audience');
    }
    if (payload.jti && this.blacklist.has(payload.jti)) throw tokenErr('INVALID_TOKEN', 'Token revoked');
    return payload;
  }

  revoke(token) {
    try { const p = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString()); if (p.jti) this.blacklist.add(p.jti); } catch {}
  }

  refresh(token, opts = {}) {
    const p = this.verify(token);
    this.revoke(token);
    const { iat, exp, jti, ...rest } = p;
    return this.sign(rest, opts);
  }

  _hmac(data) { return b64url(crypto.createHmac('sha256', this.secret).update(data).digest()); }
}

function b64url(input) { return (typeof input === 'string' ? Buffer.from(input) : input).toString('base64url'); }
function tsEqual(a, b) { const bA = Buffer.from(a), bB = Buffer.from(b); return bA.length === bB.length && crypto.timingSafeEqual(bA, bB); }
function tokenErr(code, msg) { const e = new Error(msg); e.code = code; return e; }
module.exports = { JwtAuth };
