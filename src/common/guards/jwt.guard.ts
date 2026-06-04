// src/common/guards/jwt.guard.ts
import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
  Logger,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { RedisService } from '../../modules/redis/redis.service';
import { ITokenPayload } from '../../modules/token/interfaces/token-payload.interface';
import { IRequestWithUser } from '../interfaces/request-with-user.interface';
import { buildJwtConfig } from '../../config/jwt.config';

/**
 * JwtAuthGuard — Protects routes by validating JWT access tokens.
 *
 * SOLID — S (Single Responsibility):
 * Only responsible for authentication — verifying the token is valid.
 * Authorization (checking roles/permissions) is a separate concern
 * handled by a separate RolesGuard.
 *
 * SOLID — O (Open/Closed):
 * New validation steps can be added without modifying existing logic.
 * Guards can be composed — JwtAuthGuard + RolesGuard stacked.
 *
 * Validation order (fail fast — cheapest checks first):
 * 1. Token present in header
 * 2. Cryptographic verification (CPU only — no I/O)
 * 3. Token type check (access, not refresh)
 * 4. Redis blacklist check — jti level (single token revoked)
 * 5. Redis blacklist check — user level (all tokens revoked)
 */
@Injectable()
export class JwtAuthGuard implements CanActivate {
  private readonly logger = new Logger(JwtAuthGuard.name);
  private readonly jwtConfig = buildJwtConfig();

  constructor(
    private readonly jwtService: JwtService,
    private readonly redisService: RedisService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context
      .switchToHttp()
      .getRequest<IRequestWithUser>();

    // Step 1 — Extract Bearer token from Authorization header
    const token = this.extractBearerToken(request);

    if (!token) {
      throw new UnauthorizedException('Authorization token not provided');
    }

    // Step 2 — Verify RS256 signature + expiry + issuer + audience
    // If any check fails, jwt.verify throws — we catch and translate to 401
    let payload: ITokenPayload;

    try {
      payload = await this.jwtService.verifyAsync<ITokenPayload>(token, {
        algorithms: ['RS256'],
        publicKey: this.jwtConfig.publicKey,
        issuer: this.jwtConfig.issuer,
        audience: this.jwtConfig.audience,
      });
    } catch (err) {
      // Distinguish between expired and invalid for better client messaging
      const message =
        err.name === 'TokenExpiredError'
          ? 'Token has expired'
          : 'Invalid token';

      this.logger.warn(`Token verification failed: ${err.name}`);
      throw new UnauthorizedException(message);
    }

    // Step 3 — Reject refresh tokens used as access tokens
    // Prevents a client from using their refresh token to access APIs directly
    if (payload.type !== 'access') {
      throw new UnauthorizedException('Invalid token type');
    }

    // Step 4 — Check if THIS specific token is blacklisted
    // Covers: user logged out from this device
    const isTokenBlacklisted = await this.redisService.isTokenBlacklisted(
      payload.jti,
    );

    if (isTokenBlacklisted) {
      throw new UnauthorizedException('Token has been revoked');
    }

    // Step 5 — Check if ALL tokens for this user are revoked
    // Covers: password changed, account suspended
    const allRevoked = await this.redisService.areAllUserTokensRevoked(
      payload.sub,
    );

    if (allRevoked) {
      throw new UnauthorizedException(
        'Session invalidated. Please login again.',
      );
    }

    // Step 6 — Attach verified payload to request
    // Controllers access this via @CurrentUser() decorator
    request.user = payload;

    return true;
  }

  /**
   * Extracts the raw JWT from the Authorization: Bearer <token> header.
   * Returns null if header is missing or malformed.
   */
  private extractBearerToken(request: IRequestWithUser): string | null {
    const authHeader = request.headers?.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return null;
    }

    // "Bearer <token>" → split on space → take second part
    const token = authHeader.split(' ')[1];
    return token || null;
  }
}