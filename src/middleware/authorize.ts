import { Response, NextFunction } from 'express';
import { AuthRequest, Role } from '../types';

/**
 * Role-based access control middleware factory.
 *
 * Usage:
 *   router.get('/admin', authenticate, authorize('admin'), handler);
 *   router.get('/staff', authenticate, authorize('admin', 'moderator'), handler);
 *
 * Must be placed AFTER the `authenticate` middleware so that
 * `req.user` is guaranteed to be populated.
 */
export function authorize(...allowedRoles: Role[]) {
  return (req: AuthRequest, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({
        error: 'Authentication required',
        message: 'You must be logged in to access this resource',
      });
      return;
    }

    if (!allowedRoles.includes(req.user.role)) {
      res.status(403).json({
        error: 'Forbidden',
        message: `This resource requires one of the following roles: ${allowedRoles.join(', ')}`,
      });
      return;
    }

    next();
  };
}
