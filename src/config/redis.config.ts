// src/config/redis.config.ts

/**
 * IRedisConfig — Interface for Redis configuration.
 *
 * SOLID — D (Dependency Inversion):
 * RedisService depends on this interface.
 * Config source can change without touching RedisService.
 */
export interface IRedisConfig {
  host: string;
  port: number;
}

/**
 * Builds Redis configuration from environment variables.
 */
export function buildRedisConfig(): IRedisConfig {
  return {
    host: process.env.REDIS_HOST || 'localhost',
    port: parseInt(process.env.REDIS_PORT || '6379', 10),
  };
}