import { Request, Response } from 'express';
import { z } from 'zod';
import { AuthRequest, TokenPayload } from '../types';
import { createUser, verifyCredentials, findUserById } from '../services/userService';
import {
  generateTokenPair,
  rotateRefreshToken,
  blacklistAccessToken,
  revokeRefreshToken,
  revokeAllUserTokens,
} from '../services/tokenService';

// ── Zod Schemas ────────────────────────────────────────────────────────

const registerSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: z
    .string()
    .min(8, 'Password must be at least 8 characters')
    .max(128, 'Password must not exceed 128 characters'),
  name: z
    .string()
    .min(1, 'Name is required')
    .max(100, 'Name must not exceed 100 characters'),
});

const loginSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: z.string().min(1, 'Password is required'),
});

const refreshSchema = z.object({
  refreshToken: z.string().min(1, 'Refresh token is required'),
});

// ── Register ───────────────────────────────────────────────────────────

export async function register(req: Request, res: Response): Promise<void> {
  try {
    const parsed = registerSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({
        error: 'Validation failed',
        details: parsed.error.flatten().fieldErrors,
      });
      return;
    }

    const user = await createUser(parsed.data);

    const payload: TokenPayload = {
      sub: user.id,
      email: user.email,
      role: user.role,
    };

    const tokens = generateTokenPair(payload);

    res.status(201).json({
      message: 'Registration successful',
      user,
      ...tokens,
    });
  } catch (err: any) {
    if (err.message === 'Email already registered') {
      res.status(409).json({ error: 'Conflict', message: err.message });
      return;
    }
    res.status(500).json({ error: 'Internal server error' });
  }
}

// ── Login ──────────────────────────────────────────────────────────────

export async function login(req: Request, res: Response): Promise<void> {
  try {
    const parsed = loginSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({
        error: 'Validation failed',
        details: parsed.error.flatten().fieldErrors,
      });
      return;
    }

    const user = await verifyCredentials(parsed.data.email, parsed.data.password);

    if (!user) {
      res.status(401).json({
        error: 'Unauthorized',
        message: 'Invalid email or password',
      });
      return;
    }

    const payload: TokenPayload = {
      sub: user.id,
      email: user.email,
      role: user.role,
    };

    const tokens = generateTokenPair(payload);

    res.json({
      message: 'Login successful',
      user,
      ...tokens,
    });
  } catch {
    res.status(500).json({ error: 'Internal server error' });
  }
}

// ── Refresh ────────────────────────────────────────────────────────────

export function refresh(req: Request, res: Response): void {
  try {
    const parsed = refreshSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({
        error: 'Validation failed',
        details: parsed.error.flatten().fieldErrors,
      });
      return;
    }

    const tokens = rotateRefreshToken(parsed.data.refreshToken);

    res.json({
      message: 'Tokens refreshed',
      ...tokens,
    });
  } catch (err: any) {
    res.status(401).json({
      error: 'Unauthorized',
      message: err.message || 'Invalid refresh token',
    });
  }
}

// ── Logout ─────────────────────────────────────────────────────────────

export function logout(req: AuthRequest, res: Response): void {
  try {
    // Blacklist the current access token
    const authHeader = req.headers.authorization;
    if (authHeader?.startsWith('Bearer ')) {
      blacklistAccessToken(authHeader.slice(7));
    }

    // Revoke the refresh token if provided in body
    const { refreshToken } = req.body || {};
    if (refreshToken) {
      revokeRefreshToken(refreshToken);
    }

    // Optionally revoke ALL tokens for this user
    if (req.user) {
      revokeAllUserTokens(req.user.sub);
    }

    res.json({ message: 'Logged out successfully' });
  } catch {
    res.status(500).json({ error: 'Internal server error' });
  }
}

// ── Me (current user profile) ──────────────────────────────────────────

export function me(req: AuthRequest, res: Response): void {
  if (!req.user) {
    res.status(401).json({
      error: 'Unauthorized',
      message: 'Not authenticated',
    });
    return;
  }

  const user = findUserById(req.user.sub);

  if (!user) {
    res.status(404).json({
      error: 'Not found',
      message: 'User no longer exists',
    });
    return;
  }

  res.json({ user });
}
