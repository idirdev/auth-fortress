import { describe, it, expect, beforeEach } from 'vitest';
import { hashPassword, comparePassword } from '../src/utils/password';
import {
  createUser,
  findUserById,
  findUserByEmail,
  verifyCredentials,
  updateUserRole,
  deleteUser,
  listUsers,
} from '../src/services/userService';
import { users } from '../src/models/User';

describe('password utilities', () => {
  it('hashes a password and produces a bcrypt hash', async () => {
    const hash = await hashPassword('my-secret-pass');
    expect(hash).toBeTruthy();
    expect(hash).not.toBe('my-secret-pass');
    // bcrypt hashes start with $2a$ or $2b$
    expect(hash).toMatch(/^\$2[ab]\$/);
  });

  it('comparePassword returns true for matching password', async () => {
    const hash = await hashPassword('correcthorse');
    const match = await comparePassword('correcthorse', hash);
    expect(match).toBe(true);
  });

  it('comparePassword returns false for wrong password', async () => {
    const hash = await hashPassword('correcthorse');
    const match = await comparePassword('wrongpassword', hash);
    expect(match).toBe(false);
  });
});

describe('userService', () => {
  beforeEach(() => {
    users.clear();
  });

  it('createUser creates a new user and returns a SafeUser without passwordHash', async () => {
    const safe = await createUser({
      email: 'alice@example.com',
      password: 'password123',
      name: 'Alice',
    });

    expect(safe.id).toBeTruthy();
    expect(safe.email).toBe('alice@example.com');
    expect(safe.name).toBe('Alice');
    expect(safe.role).toBe('user');
    expect((safe as any).passwordHash).toBeUndefined();
  });

  it('createUser normalizes email to lowercase', async () => {
    const safe = await createUser({
      email: 'Bob@EXAMPLE.com',
      password: 'password123',
      name: 'Bob',
    });
    expect(safe.email).toBe('bob@example.com');
  });

  it('createUser throws on duplicate email', async () => {
    await createUser({
      email: 'dup@example.com',
      password: 'pass1',
      name: 'First',
    });
    await expect(
      createUser({
        email: 'dup@example.com',
        password: 'pass2',
        name: 'Second',
      })
    ).rejects.toThrow('Email already registered');
  });

  it('createUser assigns a custom role when provided', async () => {
    const safe = await createUser({
      email: 'admin@example.com',
      password: 'adminpass',
      name: 'Admin',
      role: 'admin',
    });
    expect(safe.role).toBe('admin');
  });

  it('findUserById returns the user or null', async () => {
    const created = await createUser({
      email: 'find@example.com',
      password: 'pass',
      name: 'Findable',
    });

    const found = findUserById(created.id);
    expect(found).not.toBeNull();
    expect(found!.email).toBe('find@example.com');

    expect(findUserById('nonexistent-id')).toBeNull();
  });

  it('findUserByEmail returns the full user including passwordHash', async () => {
    await createUser({
      email: 'fulluser@example.com',
      password: 'secret',
      name: 'Full',
    });

    const user = findUserByEmail('fulluser@example.com');
    expect(user).not.toBeNull();
    expect(user!.passwordHash).toBeTruthy();
  });

  it('findUserByEmail is case-insensitive', async () => {
    await createUser({
      email: 'case@example.com',
      password: 'pass',
      name: 'Case',
    });

    const user = findUserByEmail('CASE@EXAMPLE.COM');
    expect(user).not.toBeNull();
    expect(user!.email).toBe('case@example.com');
  });

  it('verifyCredentials returns SafeUser on valid credentials', async () => {
    await createUser({
      email: 'verify@example.com',
      password: 'validpass',
      name: 'Verifiable',
    });

    const result = await verifyCredentials('verify@example.com', 'validpass');
    expect(result).not.toBeNull();
    expect(result!.email).toBe('verify@example.com');
    expect((result as any).passwordHash).toBeUndefined();
  });

  it('verifyCredentials returns null on wrong password', async () => {
    await createUser({
      email: 'wrongpass@example.com',
      password: 'correctpass',
      name: 'Wrong',
    });

    const result = await verifyCredentials('wrongpass@example.com', 'badpass');
    expect(result).toBeNull();
  });

  it('verifyCredentials returns null for nonexistent email', async () => {
    const result = await verifyCredentials('ghost@example.com', 'pass');
    expect(result).toBeNull();
  });

  it('updateUserRole changes the role', async () => {
    const created = await createUser({
      email: 'rolechange@example.com',
      password: 'pass',
      name: 'RoleChange',
    });

    const updated = updateUserRole(created.id, 'admin');
    expect(updated).not.toBeNull();
    expect(updated!.role).toBe('admin');
  });

  it('updateUserRole returns null for unknown id', () => {
    expect(updateUserRole('fake-id', 'moderator')).toBeNull();
  });

  it('deleteUser removes the user', async () => {
    const created = await createUser({
      email: 'delete@example.com',
      password: 'pass',
      name: 'Deletable',
    });

    expect(deleteUser(created.id)).toBe(true);
    expect(findUserById(created.id)).toBeNull();
  });

  it('deleteUser returns false for unknown id', () => {
    expect(deleteUser('fake-id')).toBe(false);
  });

  it('listUsers returns all created users', async () => {
    await createUser({ email: 'u1@example.com', password: 'p', name: 'U1' });
    await createUser({ email: 'u2@example.com', password: 'p', name: 'U2' });
    await createUser({ email: 'u3@example.com', password: 'p', name: 'U3' });

    const all = listUsers();
    expect(all).toHaveLength(3);
    expect(all.map((u) => u.name).sort()).toEqual(['U1', 'U2', 'U3']);
  });
});
