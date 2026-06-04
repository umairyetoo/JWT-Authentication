// src/app.module.ts
import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { PrismaModule } from './prisma/prisma.module';
import { RedisModule } from './modules/redis/redis.module';
import { AuthModule } from './modules/auth/auth.module';

@Module({
  imports: [
    // Load .env variables first — other modules depend on process.env
    ConfigModule.forRoot({ isGlobal: true }),
    PrismaModule,  // global — PrismaService available everywhere
    RedisModule,   // global — RedisService available everywhere
    AuthModule,
  ],
})
export class AppModule {}