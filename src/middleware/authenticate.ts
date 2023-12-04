import { Response, NextFunction } from 'express';
import { AuthRequest } from '../types';
import { verifyToken } from '../services/tokenService';

/**
 * JWT authentication middleware.
 *
 * Extracts the Bearer token from the Authorization header,
 * verifies it, and attaches the decoded payload to `req.user`.
 */
export function authenticate(
  req: AuthRequest,
  res: Response,
  next: NextFunction,
): void {
  const header = req.headers.authorization;

  if (!header || !header.startsWith('Bearer ')) {
    res.status(401).json({
      error: 'Authentication required',
      message: 'Missing or malformed Authorization header',
    });
    return;
  }

  const token = header.slice(7); // strip "Bearer "

  try {
    const payload = verifyToken(token);
    req.user = {
      sub: payload.sub,
      email: payload.email,
      role: payload.role,
    };
    next();
  } catch (err: any) {
    const message =
      err.name === 'TokenExpiredError'
        ? 'Access token expired'
        : 'Invalid access token';

    res.status(401).json({ error: 'Unauthorized', message });
  }
}
