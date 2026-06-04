// src/modules/redis/redis.service.ts
import {
  Injectable,
  OnModuleInit,
  OnModuleDestroy,
  Logger,
} from '@nestjs/common';
import Redis from 'ioredis';
import { buildRedisConfig } from '../../config/redis.config';

/**
 * ITokenBlacklistService — Interface for token blacklisting operations.
 *
 * SOLID — D (Dependency Inversion):
 * Guards and services depend on this interface, not on RedisService directly.
 * If we switch from Redis to Memcached tomorrow — zero changes in consumers.
 *
 * SOLID — I (Interface Segregation):
 * Only exposes the 4 methods relevant to blacklisting.
 * Does not expose raw Redis operations to consumers.
 */
export interface ITokenBlacklistService {
  blacklistToken(jti: string, exp: number): Promise<void>;
  isTokenBlacklisted(jti: string): Promise<boolean>;
  blacklistAllUserTokens(userId: string): Promise<void>;
  areAllUserTokensRevoked(userId: string): Promise<boolean>;
}

/**
 * RedisService — Manages Redis connection and token blacklist operations.
 *
 * SOLID — S (Single Responsibility):
 * Only responsible for Redis connection management and blacklist operations.
 * Does not know about JWT structure, users, or business rules.
 *
 * Key naming convention:
 *   blacklist:{jti}       → specific token revoked (logout)
 *   blacklist:user:{id}   → all tokens for user revoked (password change)
 */
@Injectable()
export class RedisService
  implements ITokenBlacklistService, OnModuleInit, OnModuleDestroy
{
  private client: Redis;
  private readonly logger = new Logger(RedisService.name);
  // Timestamp (ms) of last logged Redis error — used to rate-limit logs
  private lastErrorLogAt = 0;

  onModuleInit(): void {
    const config = buildRedisConfig();

    this.client = new Redis({
      host: config.host,
      port: config.port,
    });

    this.client.on('connect', () => {
      this.logger.log('Redis connected');
    });

    this.client.on('error', (err: Error) => {
      const now = Date.now();
      // Log at most once per minute to avoid flooding logs when Redis is down
      if (now - this.lastErrorLogAt > 60_000) {
        this.lastErrorLogAt = now;
        this.logger.error('Redis connection error: ' + err.message);
      }
    });
  }

  async onModuleDestroy(): Promise<void> {
    // Gracefully close Redis connection on app shutdown (if initialized)
    if (this.client) {
      try {
        await this.client.quit();
        this.logger.log('Redis disconnected');
      } catch (err) {
        this.logger.warn('Error while disconnecting Redis: ' + (err as Error).message);
      }
    }
  }

  /**
   * Blacklists a specific token by its jti.
   * Called on logout — kills this one token only.
   *
   * TTL is set to the token's remaining lifetime.
   * When the token expires naturally, Redis auto-deletes the entry.
   * This keeps Redis lean — no manual cleanup ever needed.
   *
   * @param jti - Unique token ID from JWT payload
   * @param exp - Token expiry timestamp (unix seconds)
   */
  async blacklistToken(jti: string, exp: number): Promise<void> {
    const now = Math.floor(Date.now() / 1000);
    const ttl = exp - now; // remaining seconds until token expires

    // Token already expired — no point blacklisting
    if (ttl <= 0) return;

    // SETEX key seconds value — sets key with automatic TTL
    await this.client.setex(`blacklist:${jti}`, ttl, '1');

    this.logger.log(`Token blacklisted: ${jti}, TTL: ${ttl}s`);
  }

  /**
   * Checks if a specific token has been blacklisted.
   * Called on every authenticated request — must be fast.
   * Redis GET is O(1) — sub-millisecond.
   *
   * @param jti - Unique token ID to check
   * @returns true if blacklisted, false if clean
   */
  async isTokenBlacklisted(jti: string): Promise<boolean> {
    const result = await this.client.get(`blacklist:${jti}`);
    return result !== null;
  }

  /**
   * Blacklists ALL tokens for a user.
   * Called on password change or account suspension.
   * Any token with this userId will be rejected — regardless of jti.
   *
   * TTL set to 7 days — maximum possible refresh token lifetime.
   * All tokens issued before this moment will expire within 7 days anyway.
   *
   * @param userId - User whose all tokens should be revoked
   */
  async blacklistAllUserTokens(userId: string): Promise<void> {
    const TTL_7_DAYS = 7 * 24 * 60 * 60; // 604800 seconds
    await this.client.setex(`blacklist:user:${userId}`, TTL_7_DAYS, '1');

    this.logger.log(`All tokens revoked for user: ${userId}`);
  }

  /**
   * Checks if all tokens for a user have been revoked.
   * Called on every authenticated request after jti check.
   *
   * @param userId - User to check
   * @returns true if all tokens revoked, false if clean
   */
  async areAllUserTokensRevoked(userId: string): Promise<boolean> {
    const result = await this.client.get(`blacklist:user:${userId}`);
    return result !== null;
  }
}