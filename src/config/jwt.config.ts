// src/config/jwt.config.ts
import * as fs from 'fs';
import * as path from 'path';

/**
 * IJwtConfig — Interface for JWT configuration.
 *
 * SOLID — D (Dependency Inversion):
 * Other modules depend on this interface, not on a concrete implementation.
 * This allows swapping config sources (env, vault, k8s secrets) without
 * changing any consumer code.
 */
export interface IJwtConfig {
  privateKey: string;
  publicKey: string;
  accessExpiry: string;
  refreshExpiry: string;
  issuer: string;
  audience: string;
}

/**
 * Reads RS256 key files from disk and builds the JWT configuration object.
 *
 * Keys are read once at startup — not on every request.
 * Throws immediately if files are missing — fail fast at boot, not at runtime.
 */
export function buildJwtConfig(): IJwtConfig {
  const privateKeyPath = path.resolve(
    process.env.JWT_PRIVATE_KEY_PATH || 'keys/private.pem',
  );

  const publicKeyPath = path.resolve(
    process.env.JWT_PUBLIC_KEY_PATH || 'keys/public.pem',
  );

  // Fail fast — if keys don't exist, crash immediately at startup
  // Better to fail at boot than to silently issue unsigned tokens
  if (!fs.existsSync(privateKeyPath)) {
    throw new Error(`Private key not found at: ${privateKeyPath}`);
  }

  if (!fs.existsSync(publicKeyPath)) {
    throw new Error(`Public key not found at: ${publicKeyPath}`);
  }

  return {
    privateKey: fs.readFileSync(privateKeyPath, 'utf8'),
    publicKey: fs.readFileSync(publicKeyPath, 'utf8'),
    accessExpiry: process.env.JWT_ACCESS_EXPIRY || '15m',
    refreshExpiry: process.env.JWT_REFRESH_EXPIRY || '7d',
    issuer: process.env.JWT_ISSUER || 'auth-service',
    audience: process.env.JWT_AUDIENCE || 'api',
  };
}