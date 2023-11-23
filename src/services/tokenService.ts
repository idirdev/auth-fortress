import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import { config } from '../config';
import { TokenPayload, TokenPair, StoredRefreshToken } from '../types';

// ── In-memory stores (replace with Redis / DB in production) ───────────
const refreshTokenStore: Map<string, StoredRefreshToken> = new Map();
const accessTokenBlacklist: Set<string> = new Set();

// ── Access Token ───────────────────────────────────────────────────────

/**
 * Generate a short-lived access token (default 15 min).
 */
export function generateAccessToken(payload: TokenPayload): string {
  return jwt.sign(payload, config.jwt.secret, {
    expiresIn: config.jwt.accessExpiry,
    jwtid: uuidv4(),
  });
}

// ── Refresh Token ──────────────────────────────────────────────────────

/**
 * Generate a long-lived refresh token (default 7 days).
 * The token's jti is stored so it can be validated and rotated later.
 */
export function generateRefreshToken(payload: TokenPayload): string {
  const jti = uuidv4();

  const token = jwt.sign(
    { ...payload, jti },
    config.jwt.secret,
    { expiresIn: config.jwt.refreshExpiry },
  );

  // Persist metadata
  refreshTokenStore.set(jti, {
    jti,
    userId: payload.sub,
    expiresAt: new Date(Date.now() + parseDuration(config.jwt.refreshExpiry)),
    createdAt: new Date(),
    revoked: false,
  });

  return token;
}

// ── Token Pair (convenience) ───────────────────────────────────────────

export function generateTokenPair(payload: TokenPayload): TokenPair {
  return {
    accessToken: generateAccessToken(payload),
    refreshToken: generateRefreshToken(payload),
  };
}

// ── Verification ───────────────────────────────────────────────────────

/**
 * Verify and decode any token (access or refresh).
 * Throws if the token is invalid, expired, or blacklisted.
 */
export function verifyToken(token: string): TokenPayload & { jti?: string } {
  const decoded = jwt.verify(token, config.jwt.secret) as TokenPayload & {
    jti?: string;
  };

  // Check access token blacklist
  if (decoded.jti && accessTokenBlacklist.has(decoded.jti)) {
    throw new Error('Token has been revoked');
  }

  return decoded;
}

// ── Rotation ───────────────────────────────────────────────────────────

/**
 * Rotate a refresh token: revoke the old one and issue a new pair.
 * Implements refresh-token rotation to limit replay attacks.
 */
export function rotateRefreshToken(oldToken: string): TokenPair {
  const decoded = verifyToken(oldToken);

  if (!decoded.jti) {
    throw new Error('Token missing jti claim');
  }

  const stored = refreshTokenStore.get(decoded.jti);

  if (!stored) {
    throw new Error('Refresh token not recognised');
  }

  if (stored.revoked) {
    // Possible token reuse attack — revoke the entire family
    revokeAllUserTokens(stored.userId);
    throw new Error('Refresh token reuse detected — all tokens revoked');
  }

  // Revoke old token
  stored.revoked = true;

  // Issue new pair
  const payload: TokenPayload = {
    sub: decoded.sub,
    email: decoded.email,
    role: decoded.role,
  };

  const newPair = generateTokenPair(payload);

  // Link old token to new one (audit trail)
  const newDecoded = jwt.decode(newPair.refreshToken) as TokenPayload & {
    jti: string;
  };
  stored.replacedBy = newDecoded.jti;

  return newPair;
}

// ── Blacklisting ───────────────────────────────────────────────────────

/**
 * Blacklist a specific access token by its jti.
 */
export function blacklistAccessToken(token: string): void {
  try {
    const decoded = jwt.decode(token) as TokenPayload & { jti?: string } | null;
    if (decoded?.jti) {
      accessTokenBlacklist.add(decoded.jti);
    }
  } catch {
    // Silently ignore decode failures — token may already be invalid
  }
}

/**
 * Revoke all refresh tokens belonging to a user.
 */
export function revokeAllUserTokens(userId: string): void {
  for (const [, stored] of refreshTokenStore) {
    if (stored.userId === userId) {
      stored.revoked = true;
    }
  }
}

/**
 * Revoke a single refresh token by its raw JWT string.
 */
export function revokeRefreshToken(token: string): void {
  try {
    const decoded = jwt.decode(token) as TokenPayload & { jti?: string } | null;
    if (decoded?.jti) {
      const stored = refreshTokenStore.get(decoded.jti);
      if (stored) {
        stored.revoked = true;
      }
    }
  } catch {
    // Ignore
  }
}

// ── Helpers ────────────────────────────────────────────────────────────

/**
 * Parse a duration string like "15m" or "7d" into milliseconds.
 */
function parseDuration(dur: string): number {
  const match = dur.match(/^(\d+)(s|m|h|d)$/);
  if (!match) return 15 * 60 * 1000; // fallback 15 min

  const value = parseInt(match[1], 10);
  const unit = match[2];

  switch (unit) {
    case 's': return value * 1000;
    case 'm': return value * 60 * 1000;
    case 'h': return value * 60 * 60 * 1000;
    case 'd': return value * 24 * 60 * 60 * 1000;
    default:  return 15 * 60 * 1000;
  }
}
