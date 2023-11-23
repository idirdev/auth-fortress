import { v4 as uuidv4 } from 'uuid';
import { User, SafeUser, users } from '../models/User';
import { RegisterDTO, Role } from '../types';
import { hashPassword, comparePassword } from '../utils/password';

// ── Helpers ────────────────────────────────────────────────────────────

function toSafeUser(user: User): SafeUser {
  const { passwordHash: _, ...safe } = user;
  return safe;
}

// ── CRUD ───────────────────────────────────────────────────────────────

/**
 * Create a new user. Throws if the email is already taken.
 */
export async function createUser(dto: RegisterDTO): Promise<SafeUser> {
  // Check uniqueness
  for (const [, u] of users) {
    if (u.email === dto.email) {
      throw new Error('Email already registered');
    }
  }

  const now = new Date();

  const user: User = {
    id: uuidv4(),
    email: dto.email.toLowerCase().trim(),
    name: dto.name.trim(),
    passwordHash: await hashPassword(dto.password),
    role: dto.role || 'user',
    createdAt: now,
    updatedAt: now,
  };

  users.set(user.id, user);
  return toSafeUser(user);
}

/**
 * Find a user by ID. Returns null if not found.
 */
export function findUserById(id: string): SafeUser | null {
  const user = users.get(id);
  return user ? toSafeUser(user) : null;
}

/**
 * Find a user by email (case-insensitive). Returns the full user
 * (including password hash) so the caller can verify credentials.
 */
export function findUserByEmail(email: string): User | null {
  const normalised = email.toLowerCase().trim();
  for (const [, user] of users) {
    if (user.email === normalised) {
      return user;
    }
  }
  return null;
}

/**
 * Verify a user's credentials. Returns the safe user on success, null on failure.
 */
export async function verifyCredentials(
  email: string,
  password: string,
): Promise<SafeUser | null> {
  const user = findUserByEmail(email);
  if (!user) return null;

  const valid = await comparePassword(password, user.passwordHash);
  if (!valid) return null;

  return toSafeUser(user);
}

/**
 * Update a user's role. Returns the updated safe user or null if not found.
 */
export function updateUserRole(id: string, role: Role): SafeUser | null {
  const user = users.get(id);
  if (!user) return null;

  user.role = role;
  user.updatedAt = new Date();
  return toSafeUser(user);
}

/**
 * Delete a user by ID. Returns true if the user existed and was removed.
 */
export function deleteUser(id: string): boolean {
  return users.delete(id);
}

/**
 * List all users (safe projection).
 */
export function listUsers(): SafeUser[] {
  return Array.from(users.values()).map(toSafeUser);
}
