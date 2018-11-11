'use strict';
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { JwtAuth } = require('../src/jwt');
const { ApiKeyAuth } = require('../src/apikey');
const { RateLimiter } = require('../src/ratelimit');
const { RBAC } = require('../src/rbac');
const { SessionManager } = require('../src/session');

describe('JwtAuth', () => {
  const jwt = new JwtAuth({ secret: 'test-secret' });
  it('sign and verify', () => { const t = jwt.sign({ sub: 'u1' }); const p = jwt.verify(t); assert.equal(p.sub, 'u1'); });
  it('reject tampered', () => { const t = jwt.sign({ sub: 'u1' }); assert.throws(() => jwt.verify(t.slice(0,-3)+'XXX'), {code:'INVALID_TOKEN'}); });
  it('reject expired', () => { const j2 = new JwtAuth({ secret: 'x', expiresIn: -1 }); assert.throws(() => j2.verify(j2.sign({sub:'u1'})), {code:'TOKEN_EXPIRED'}); });
  it('revoke', () => { const t = jwt.sign({ sub: 'u1' }); jwt.revoke(t); assert.throws(() => jwt.verify(t), {code:'INVALID_TOKEN'}); });
  it('refresh', () => { const t = jwt.sign({ sub: 'u1', role: 'admin' }); const n = jwt.refresh(t); assert.equal(jwt.verify(n).role, 'admin'); });
});

describe('ApiKeyAuth', () => {
  const ak = new ApiKeyAuth();
  it('generate and validate', () => { const { key } = ak.generate({ name: 'test' }); const m = ak.validate(key); assert.ok(m); assert.equal(m.name, 'test'); });
  it('reject unknown', () => { assert.equal(ak.validate('ak_unknown'), null); });
  it('revoke', () => { const { key, hash } = ak.generate({}); ak.revoke(hash); assert.equal(ak.validate(key), null); });
});

describe('RateLimiter', () => {
  it('allow within limit', () => { const l = new RateLimiter({ max: 3, windowMs: 1000 }); assert.ok(l.check('a')); assert.ok(l.check('a')); assert.ok(l.check('a')); l.destroy(); });
  it('block over limit', () => { const l = new RateLimiter({ max: 2, windowMs: 1000 }); l.check('b'); l.check('b'); assert.equal(l.check('b'), false); l.destroy(); });
  it('remaining', () => { const l = new RateLimiter({ max: 5, windowMs: 1000 }); assert.equal(l.remaining('c'), 5); l.check('c'); assert.equal(l.remaining('c'), 4); l.destroy(); });
});

describe('RBAC', () => {
  const rbac = new RBAC({ admin: { permissions: ['*'] }, editor: { permissions: ['read','write'], inherits: ['viewer'] }, viewer: { permissions: ['read'] } });
  it('admin wildcard', () => { assert.ok(rbac.can('admin', 'anything')); });
  it('direct perms', () => { assert.ok(rbac.can('editor', 'write')); });
  it('deny missing', () => { assert.equal(rbac.can('viewer', 'write'), false); });
  it('inherit', () => { assert.ok(rbac.can('editor', 'read')); });
});

describe('SessionManager', () => {
  const sm = new SessionManager({ maxAge: 5000 });
  it('create and get', () => { const { sid } = sm.create({ id: 1 }); assert.deepEqual(sm.get(sid), { id: 1 }); });
  it('destroy', () => { const { sid } = sm.create({ id: 2 }); sm.destroy(sid); assert.equal(sm.get(sid), null); });
  sm.close();
});
