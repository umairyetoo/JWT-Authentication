// src/modules/redis/redis.module.ts
import { Global, Module } from '@nestjs/common';
import { RedisService } from './redis.service';

/**
 * RedisModule — Global module so RedisService is available everywhere.
 * Guards and services can inject it without importing RedisModule each time.
 */
@Global()
@Module({
  providers: [RedisService],
  exports: [RedisService],
})
export class RedisModule {}