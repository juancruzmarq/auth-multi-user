import * as bcrypt from 'bcrypt';
import { createHmac } from 'crypto';

// Número de rondas para el salt de bcrypt
const SALT_ROUNDS = 12;

export async function hashPassword(plain: string) {
  const salt = await bcrypt.genSalt(SALT_ROUNDS);
  return bcrypt.hash(plain, salt);
}

export async function verifyPassword(hash: string, plain: string) {
  return bcrypt.compare(plain, hash);
}

export function hashTokenStable(token: string, pepper: string) {
  return createHmac('sha256', pepper).update(token).digest('hex');
}
