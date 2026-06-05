// src/app.module.ts
import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { PrismaModule } from './prisma/prisma.module';
import { RedisModule } from './modules/redis/redis.module';
import { AuthModule } from './modules/auth/auth.module';

import { ServeStaticModule } from '@nestjs/serve-static';
import { join } from 'path';

@Module({
  imports: [
    // Load .env variables first — other modules depend on process.env
    ConfigModule.forRoot({ isGlobal: true }),
    
    // Serve the public folder so we can access index.html directly from Nest
    ServeStaticModule.forRoot({
      rootPath: join(__dirname, '..', 'public'),
      exclude: ['/api/(.*)', '/auth/(.*)'],
    }),
    
    PrismaModule,  // global — PrismaService available everywhere
    RedisModule,   // global — RedisService available everywhere
    AuthModule,
  ],
})
export class AppModule {}