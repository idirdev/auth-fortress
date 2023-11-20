import { Role } from '../types';

export interface User {
  id: string;
  email: string;
  name: string;
  passwordHash: string;
  role: Role;
  createdAt: Date;
  updatedAt: Date;
}

/**
 * Safe user projection — everything except the password hash.
 */
export type SafeUser = Omit<User, 'passwordHash'>;

/**
 * In-memory user store.
 * Swap this out for a real database adapter (PostgreSQL, MongoDB, etc.)
 * when moving to production.
 */
export const users: Map<string, User> = new Map();
