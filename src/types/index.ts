import { Request } from 'express';

// ── Roles ──────────────────────────────────────────────────────────────
export type Role = 'user' | 'admin' | 'moderator';

// ── Token Payload (embedded in JWT) ────────────────────────────────────
export interface TokenPayload {
  sub: string;       // user id
  email: string;
  role: Role;
  jti?: string;      // unique token id (for refresh tokens)
}

// ── Extended Express Request with authenticated user ───────────────────
export interface AuthRequest extends Request {
  user?: TokenPayload;
}

// ── DTOs (validated by Zod at the route level) ─────────────────────────
export interface RegisterDTO {
  email: string;
  password: string;
  name: string;
  role?: Role;
}

export interface LoginDTO {
  email: string;
  password: string;
}

// ── Token pair returned to the client ──────────────────────────────────
export interface TokenPair {
  accessToken: string;
  refreshToken: string;
}

// ── Stored refresh token metadata ──────────────────────────────────────
export interface StoredRefreshToken {
  jti: string;
  userId: string;
  expiresAt: Date;
  createdAt: Date;
  revoked: boolean;
  replacedBy?: string; // jti of the new token after rotation
}
