// src/modules/token/token.service.ts
import {
  Injectable,
  UnauthorizedException,
  Logger,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { v4 as uuidv4 } from 'uuid';
import { PrismaService } from '../../prisma/prisma.service';
import { RedisService } from '../redis/redis.service';
import { buildJwtConfig } from '../../config/jwt.config';
import { ITokenPayload } from './interfaces/token-payload.interface';
import { ITokenPair } from './interfaces/token-pair.interface';

/**
 * ITokenService — Interface for token operations.
 *
 * SOLID — D (Dependency Inversion):
 * AuthService depends on this abstraction.
 * Swapping JWT library or signing strategy doesn't touch AuthService.
 *
 * SOLID — I (Interface Segregation):
 * Only the 4 operations callers need — nothing internal exposed.
 */
export interface ITokenService {
  generateTokenPair(userId: string, email: string, role: string): Promise<ITokenPair>;
  rotateRefreshToken(refreshToken: string): Promise<ITokenPair>;
  revokeAccessToken(accessToken: string): Promise<void>;
  revokeAllUserTokens(userId: string): Promise<void>;
}

/**
 * TokenService — Handles all JWT token operations.
 *
 * SOLID — S (Single Responsibility):
 * Only responsible for token generation, validation, rotation, revocation.
 * Does not know about user passwords, HTTP requests, or business rules.
 * One reason to change: token strategy changes.
 *
 * SOLID — O (Open/Closed):
 * New token types can be added (e.g. email verification token)
 * without modifying existing methods.
 */
@Injectable()
export class TokenService implements ITokenService {
  private readonly logger = new Logger(TokenService.name);
  private readonly jwtConfig = buildJwtConfig();

  constructor(
    private readonly jwtService: JwtService,
    private readonly prisma: PrismaService,
    private readonly redisService: RedisService,
  ) {}

  /**
   * Generates a new access + refresh token pair for a user.
   *
   * Access Token:
   *   - Short lived (15 min)
   *   - Contains user info for authorization decisions
   *   - Sent with every API request
   *
   * Refresh Token:
   *   - Long lived (7 days)
   *   - Minimal payload — just userId and jti
   *   - Only sent to /auth/refresh endpoint
   *   - Stored in DB to enable rotation and theft detection
   *
   * @param userId  - User's UUID
   * @param email   - User's email
   * @param role    - User's role
   */
  async generateTokenPair(
    userId: string,
    email: string,
    role: string,
  ): Promise<ITokenPair> {
    // Generate unique IDs for each token
    // These are stored/blacklisted for revocation
    const accessJti = uuidv4();
    const refreshJti = uuidv4();

    // Build access token payload
    const accessPayload: ITokenPayload = {
      sub: userId,
      email,
      role,
      jti: accessJti,
      type: 'access',
    };

    // Build refresh token payload — minimal, no sensitive data
    const refreshPayload: ITokenPayload = {
      sub: userId,
      email,  // included to avoid extra DB lookup on rotation
      role,
      jti: refreshJti,
      type: 'refresh', // type field prevents refresh token being used as access token
    };

    // Sign both tokens with RS256 private key
    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(accessPayload, {
        algorithm: 'RS256',
        expiresIn: this.jwtConfig.accessExpiry,
        issuer: this.jwtConfig.issuer,
        audience: this.jwtConfig.audience,
        privateKey: this.jwtConfig.privateKey,
      }),
      this.jwtService.signAsync(refreshPayload, {
        algorithm: 'RS256',
        expiresIn: this.jwtConfig.refreshExpiry,
        issuer: this.jwtConfig.issuer,
        audience: this.jwtConfig.audience,
        privateKey: this.jwtConfig.privateKey,
      }),
    ]);

    // Store refresh token in DB
    // This is what enables rotation detection —
    // if a used/deleted jti is presented again, it's a theft signal
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7);

    await this.prisma.refreshToken.create({
      data: {
        jti: refreshJti,
        userId,
        expiresAt,
      },
    });

    this.logger.log(`Token pair generated for user: ${userId}`);

    return { accessToken, refreshToken };
  }

  /**
   * Rotates a refresh token — issues a new pair and invalidates the old one.
   *
   * Rotation flow:
   * 1. Verify refresh token cryptographically
   * 2. Confirm it's a refresh token (not access)
   * 3. Look up jti in DB — must exist
   * 4. If NOT in DB → reuse detected → revoke all user tokens → throw
   * 5. If IN DB → delete it → issue new pair
   *
   * This implements "Refresh Token Family" invalidation.
   * Stolen token reuse is detected and kills all sessions.
   *
   * @param refreshToken - The refresh token from client
   * @throws UnauthorizedException on any validation failure
   */
  async rotateRefreshToken(refreshToken: string): Promise<ITokenPair> {
    // Step 1 — Verify signature and expiry
    let payload: ITokenPayload;

    try {
      payload = await this.jwtService.verifyAsync<ITokenPayload>(refreshToken, {
        algorithms: ['RS256'],
        issuer: this.jwtConfig.issuer,
        audience: this.jwtConfig.audience,
        publicKey: this.jwtConfig.publicKey,
      });
    } catch {
      throw new UnauthorizedException('Invalid or expired refresh token');
    }

    // Step 2 — Must be a refresh token — prevents access tokens being used here
    if (payload.type !== 'refresh') {
      throw new UnauthorizedException('Invalid token type');
    }

    // Step 3 — Look up in DB
    const stored = await this.prisma.refreshToken.findUnique({
      where: { jti: payload.jti },
    });

    // Step 4 — Not in DB = already used = THEFT DETECTED
    if (!stored) {
      // This refresh token was already rotated — someone is reusing it
      // Revoke ALL tokens for this user — force re-login on all devices
      await this.redisService.blacklistAllUserTokens(payload.sub);

      this.logger.warn(
        `Refresh token reuse detected for user: ${payload.sub}. All sessions revoked.`,
      );

      throw new UnauthorizedException(
        'Security violation detected. Please login again.',
      );
    }

    // Step 5 — Delete old refresh token (it's now consumed)
    await this.prisma.refreshToken.delete({
      where: { jti: payload.jti },
    });

    // Step 6 — Issue brand new pair
    return this.generateTokenPair(payload.sub, payload.email, payload.role);
  }

  /**
   * Blacklists a specific access token in Redis.
   * Called on logout — kills this token until it naturally expires.
   *
   * Uses jti from payload as the blacklist key.
   * TTL = remaining token lifetime — Redis auto-deletes when token expires anyway.
   *
   * @param accessToken - Raw JWT string to revoke
   */
  async revokeAccessToken(accessToken: string): Promise<void> {
    // Decode without verifying — we just need the payload
    // We already verified it in the guard before reaching logout
    const payload = this.jwtService.decode(accessToken) as ITokenPayload;

    if (!payload?.jti || !payload?.exp) {
      this.logger.warn('Attempted to revoke token with missing jti or exp');
      return;
    }

    await this.redisService.blacklistToken(payload.jti, payload.exp);
  }

  /**
   * Revokes ALL tokens for a user.
   * Called on password change or account suspension.
   *
   * Two-step revocation:
   * 1. Redis user-level blacklist — kills all access tokens immediately
   * 2. DB cleanup — removes all refresh tokens so rotation fails
   *
   * @param userId - User whose all sessions should be killed
   */
  async revokeAllUserTokens(userId: string): Promise<void> {
    // Kill all access tokens via Redis user-level ban
    await this.redisService.blacklistAllUserTokens(userId);

    // Remove all refresh tokens from DB
    // Rotation attempts will fail — no matching jti found
    await this.prisma.refreshToken.deleteMany({
      where: { userId },
    });

    this.logger.log(`All sessions revoked for user: ${userId}`);
  }
}