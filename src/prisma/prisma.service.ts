// src/prisma/prisma.service.ts
import { Injectable, OnModuleInit, OnModuleDestroy, Logger } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';

/**
 * PrismaService — Wraps PrismaClient for NestJS lifecycle management.
 *
 * SOLID — S (Single Responsibility):
 * Only responsible for managing the Prisma DB connection lifecycle.
 * Does not contain any business logic or query building.
 *
 * Implements OnModuleInit and OnModuleDestroy to connect/disconnect
 * cleanly with the NestJS application lifecycle.
 */
@Injectable()
export class PrismaService
  extends PrismaClient
  implements OnModuleInit, OnModuleDestroy
{
  private readonly logger = new Logger(PrismaService.name);

  async onModuleInit(): Promise<void> {
    // Connect to DB when the NestJS module initializes
    await this.$connect();
    this.logger.log('Database connected');
  }

  async onModuleDestroy(): Promise<void> {
    // Gracefully disconnect when app shuts down
    await this.$disconnect();
    this.logger.log('Database disconnected');
  }
}