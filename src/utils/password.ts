import bcrypt from 'bcryptjs';
import { config } from '../config';

/**
 * Hash a plaintext password using bcrypt.
 */
export async function hashPassword(plain: string): Promise<string> {
  const salt = await bcrypt.genSalt(config.bcrypt.rounds);
  return bcrypt.hash(plain, salt);
}

/**
 * Compare a plaintext password against a bcrypt hash.
 */
export async function comparePassword(
  plain: string,
  hash: string,
): Promise<boolean> {
  return bcrypt.compare(plain, hash);
}
