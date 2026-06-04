// src/modules/user/user.service.ts
import {
  Injectable,
  ConflictException,
  NotFoundException,
  Logger,
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { PrismaService } from '../../prisma/prisma.service';
import {
  IUser,
  IUserWithPassword,
} from './../token/interfaces/user.interface';

/**
 * IUserService — Interface for user data operations.
 *
 * SOLID — D (Dependency Inversion):
 * AuthService depends on this interface, not UserService directly.
 * Enables mocking in tests and swapping implementations without
 * touching AuthService.
 *
 * SOLID — I (Interface Segregation):
 * Only exposes methods that callers actually need.
 * Internal helpers stay private in the implementation.
 */
export interface IUserService {
  createUser(email: string, password: string): Promise<IUser>;
  findByEmail(email: string): Promise<IUserWithPassword | null>;
  findById(id: string): Promise<IUser | null>;
  updatePassword(userId: string, hashedPassword: string): Promise<void>;
  validatePassword(plain: string, hashed: string): Promise<boolean>;
}

/**
 * UserService — Handles all user-related database operations.
 *
 * SOLID — S (Single Responsibility):
 * Only responsible for user CRUD and password operations.
 * Does not know about JWT, Redis, or auth flow.
 * One reason to change: user data structure changes.
 */
@Injectable()
export class UserService implements IUserService {
  private readonly logger = new Logger(UserService.name);
  private readonly SALT_ROUNDS = 12; // bcrypt cost factor

  constructor(private readonly prisma: PrismaService) {}

  /**
   * Creates a new user after checking for duplicate email.
   * Hashes the password with bcrypt before storing.
   *
   * @param email - User's email address
   * @param password - Plain text password (will be hashed)
   * @throws ConflictException if email already registered
   */
  async createUser(email: string, password: string): Promise<IUser> {
    // Check duplicate before attempting insert
    // Cheaper than catching a unique constraint error from DB
    const existing = await this.prisma.user.findUnique({
      where: { email },
    });

    if (existing) {
      throw new ConflictException('Email already registered');
    }

    // Hash password — bcrypt with 12 rounds
    // Higher rounds = slower brute force — 12 is production standard
    const hashedPassword = await bcrypt.hash(password, this.SALT_ROUNDS);

    const user = await this.prisma.user.create({
      data: {
        email,
        password: hashedPassword,
      },
    });

    this.logger.log(`User created: ${user.id}`);

    // Return IUser — never return the hashed password outside this service
    return this.toIUser(user);
  }

  /**
   * Finds a user by email — includes password for login verification.
   * Only used by AuthService during login — never exposed via API.
   *
   * @param email - Email to look up
   * @returns User with password or null if not found
   */
  async findByEmail(email: string): Promise<IUserWithPassword | null> {
    const user = await this.prisma.user.findUnique({
      where: { email },
    });

    if (!user) return null;

    return {
      id: user.id,
      email: user.email,
      role: user.role,
      isActive: user.isActive,
      password: user.password, // included here — only place password leaves DB
    };
  }

  /**
   * Finds a user by ID — excludes password.
   * Used for profile lookups and guard population.
   *
   * @param id - User UUID
   * @returns User without password or null
   */
  async findById(id: string): Promise<IUser | null> {
    const user = await this.prisma.user.findUnique({
      where: { id },
    });

    if (!user) return null;

    return this.toIUser(user);
  }

  /**
   * Updates a user's password in the DB.
   * Expects already-hashed password — hashing done in AuthService.
   *
   * @param userId - User to update
   * @param hashedPassword - New bcrypt hashed password
   * @throws NotFoundException if user doesn't exist
   */
  async updatePassword(userId: string, hashedPassword: string): Promise<void> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    await this.prisma.user.update({
      where: { id: userId },
      data: { password: hashedPassword },
    });

    this.logger.log(`Password updated for user: ${userId}`);
  }

  /**
   * Compares plain text password against bcrypt hash.
   * Timing-safe — bcrypt.compare prevents timing attacks.
   *
   * @param plain - Password the user submitted
   * @param hashed - Stored bcrypt hash
   * @returns true if match, false otherwise
   */
  async validatePassword(plain: string, hashed: string): Promise<boolean> {
    return bcrypt.compare(plain, hashed);
  }

  /**
   * Maps Prisma User model to IUser interface.
   * Ensures password is never accidentally returned.
   * Private — internal mapping only.
   */
  private toIUser(user: {
    id: string;
    email: string;
    role: string;
    isActive: boolean;
  }): IUser {
    return {
      id: user.id,
      email: user.email,
      role: user.role,
      isActive: user.isActive,
    };
  }
}