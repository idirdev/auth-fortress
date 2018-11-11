/**
 * @file test.js
 * @description Tests for auth-fortress: JWT, API keys, rate limiter, RBAC,
 *   password hashing, and session management.
 * @author idirdev
 */

'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { AuthFortress } = require('../src/index.js');

describe('JWT', () => {
  it('generateToken and verifyToken round-trip', () => {
    const auth = new AuthFortress({ jwtSecret: 'test-secret' });
    const token = auth.generateToken({ userId: 42, role: 'admin' });
    const payload = auth.verifyToken(token);
    assert.equal(payload.userId, 42);
    assert.equal(payload.role, 'admin');
  });

  it('verifyToken throws on tampered token', () => {
    const auth = new AuthFortress({ jwtSecret: 'test-secret' });
    const token = auth.generateToken({ userId: 1 });
    const tampered = token.slice(0, -3) + 'xxx';
    assert.throws(() => auth.verifyToken(tampered), /signature|Invalid/i);
  });

  it('verifyToken throws on expired token', () => {
    const auth = new AuthFortress({ jwtSecret: 'test-secret' });
    const token = auth.generateToken({ userId: 1 }, { expiresIn: -1 });
    assert.throws(() => auth.verifyToken(token), /expired/i);
  });

  it('refreshToken produces a new valid token', () => {
    const auth = new AuthFortress({ jwtSecret: 'test-secret' });
    const original = auth.generateToken({ userId: 99 }, { expiresIn: -1 });
    const refreshed = auth.refreshToken(original, { expiresIn: 3600 });
    const payload = auth.verifyToken(refreshed);
    assert.equal(payload.userId, 99);
  });
});

describe('API Keys', () => {
  it('generateApiKey uses given prefix', () => {
    const auth = new AuthFortress();
    const key = auth.generateApiKey('myapp');
    assert.ok(key.startsWith('myapp_'));
  });

  it('validateApiKey returns true for a key in a Set', () => {
    const auth = new AuthFortress();
    const key = auth.generateApiKey('svc');
    const store = new Set([key]);
    assert.equal(auth.validateApiKey(key, store), true);
  });

  it('validateApiKey returns false for unknown key', () => {
    const auth = new AuthFortress();
    const store = new Set(['other_key']);
    assert.equal(auth.validateApiKey('svc_fake', store), false);
  });

  it('validateApiKey works with arrays', () => {
    const auth = new AuthFortress();
    const key = auth.generateApiKey('k');
    assert.equal(auth.validateApiKey(key, [key, 'other']), true);
    assert.equal(auth.validateApiKey('nothere', [key]), false);
  });
});

describe('Rate Limiter', () => {
  it('allows requests within the limit', () => {
    const auth = new AuthFortress();
    const limiter = auth.createRateLimiter({ windowMs: 60000, maxRequests: 3 });
    assert.equal(limiter.check('user1').allowed, true);
    assert.equal(limiter.check('user1').allowed, true);
  });

  it('blocks requests over the limit', () => {
    const auth = new AuthFortress();
    const limiter = auth.createRateLimiter({ windowMs: 60000, maxRequests: 2 });
    limiter.check('u');
    limiter.check('u');
    const result = limiter.check('u');
    assert.equal(result.allowed, false);
    assert.equal(result.remaining, 0);
  });

  it('returns a future resetTime', () => {
    const auth = new AuthFortress();
    const limiter = auth.createRateLimiter({ windowMs: 5000, maxRequests: 10 });
    const { resetTime } = limiter.check('user2');
    assert.ok(resetTime > Date.now());
  });
});

describe('RBAC', () => {
  it('hasPermission returns true for granted permission', () => {
    const auth = new AuthFortress();
    auth.defineRole('editor', ['read', 'write']);
    assert.equal(auth.hasPermission('editor', 'read'), true);
    assert.equal(auth.hasPermission('editor', 'write'), true);
  });

  it('hasPermission returns false for ungrant permission', () => {
    const auth = new AuthFortress();
    auth.defineRole('viewer', ['read']);
    assert.equal(auth.hasPermission('viewer', 'delete'), false);
  });

  it('authorize throws when permission is missing', () => {
    const auth = new AuthFortress();
    auth.defineRole('guest', ['read']);
    assert.throws(() => auth.authorize('guest', 'delete'), /lacks permission/);
  });

  it('authorize does not throw when permission is present', () => {
    const auth = new AuthFortress();
    auth.defineRole('admin', ['read', 'write', 'delete']);
    assert.doesNotThrow(() => auth.authorize('admin', 'delete'));
  });
});

describe('Password Hashing', () => {
  it('hashPassword and verifyPassword round-trip', async () => {
    const auth = new AuthFortress();
    const hash = await auth.hashPassword('secret123');
    const valid = await auth.verifyPassword('secret123', hash);
    assert.equal(valid, true);
  });

  it('verifyPassword returns false for wrong password', async () => {
    const auth = new AuthFortress();
    const hash = await auth.hashPassword('correctPassword');
    const valid = await auth.verifyPassword('wrongPassword', hash);
    assert.equal(valid, false);
  });

  it('hashPassword produces a salt:hash formatted string', async () => {
    const auth = new AuthFortress();
    const hash = await auth.hashPassword('pass');
    assert.ok(hash.includes(':'));
    const parts = hash.split(':');
    assert.equal(parts.length, 2);
    assert.ok(parts[0].length > 0);
    assert.ok(parts[1].length > 0);
  });
});

describe('Session Manager', () => {
  it('createSession and getSession round-trip', () => {
    const auth = new AuthFortress();
    const session = auth.createSession('user-1', { theme: 'dark' });
    const retrieved = auth.getSession(session.id);
    assert.ok(retrieved !== null);
    assert.equal(retrieved.userId, 'user-1');
    assert.equal(retrieved.data.theme, 'dark');
  });

  it('destroySession removes the session', () => {
    const auth = new AuthFortress();
    const session = auth.createSession('user-2');
    assert.equal(auth.destroySession(session.id), true);
    assert.equal(auth.getSession(session.id), null);
  });

  it('getSession returns null for expired session', () => {
    const auth = new AuthFortress();
    const session = auth.createSession('user-3', {}, -1);
    assert.equal(auth.getSession(session.id), null);
  });

  it('cleanExpired removes only expired sessions', () => {
    const auth = new AuthFortress();
    auth.createSession('user-a', {}, -1);
    auth.createSession('user-b', {}, -1);
    const live = auth.createSession('user-c', {}, 60000);
    const removed = auth.cleanExpired();
    assert.equal(removed, 2);
    assert.ok(auth.getSession(live.id) !== null);
  });
});
