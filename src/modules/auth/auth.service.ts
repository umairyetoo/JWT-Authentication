// src/modules/auth/auth.service.ts
import {
  Injectable,
  UnauthorizedException,
  ForbiddenException,
  Logger,
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { UserService } from '../user/user.service';
import { TokenService } from '../token/token.service';
import { IAuthResponse } from './interfaces/auth-response.interface';
import { ITokenPair } from '../token/interfaces/token-pair.interface';

/**
 * AuthService — Orchestrates the authentication flow.
 *
 * SOLID — S (Single Responsibility):
 * Only responsible for auth business logic — register, login, logout,
 * refresh, change password.
 * Delegates user DB operations to UserService.
 * Delegates token operations to TokenService.
 * One reason to change: auth business rules change.
 *
 * SOLID — D (Dependency Inversion):
 * Depends on IUserService and ITokenService interfaces.
 * Not coupled to UserService or TokenService implementations.
 * In tests — mock implementations can be injected transparently.
 *
 * AuthService knows the FLOW.
 * UserService knows the DATA.
 * TokenService knows the TOKENS.
 * Each stays in its lane.
 */
@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private readonly userService: UserService,
    private readonly tokenService: TokenService,
  ) {}

  /**
   * Registers a new user and returns token pair.
   * User is immediately logged in after registration.
   *
   * Flow:
   * 1. Create user (UserService handles duplicate check + password hashing)
   * 2. Generate token pair
   * 3. Return user + tokens
   *
   * @param email    - User's email
   * @param password - Plain text password
   */
  async register(email: string, password: string): Promise<IAuthResponse> {
    // UserService.createUser throws ConflictException if email taken
    const user = await this.userService.createUser(email, password);

    // Issue tokens immediately — no need to login separately after register
    const tokens = await this.tokenService.generateTokenPair(
      user.id,
      user.email,
      user.role,
    );

    this.logger.log(`New user registered: ${user.id}`);

    return { user, ...tokens };
  }

  /**
   * Authenticates a user with email and password.
   *
   * Flow:
   * 1. Find user by email
   * 2. Check account is active
   * 3. Verify password
   * 4. Issue token pair
   *
   * Security note:
   * Same error message for "user not found" and "wrong password".
   * Prevents user enumeration — attacker can't tell if email is registered.
   *
   * @param email    - User's email
   * @param password - Plain text password to verify
   */
  async login(email: string, password: string): Promise<IAuthResponse> {
    // Find user — includes password hash for verification
    const user = await this.userService.findByEmail(email);

    // Intentionally same error for not found vs wrong password
    // Prevents email enumeration attacks
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Check account is not suspended
    if (!user.isActive) {
      throw new ForbiddenException('Account has been suspended');
    }

    // Verify password — bcrypt.compare is timing-safe
    const passwordValid = await this.userService.validatePassword(
      password,
      user.password,
    );

    if (!passwordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Issue tokens
    const tokens = await this.tokenService.generateTokenPair(
      user.id,
      user.email,
      user.role,
    );

    this.logger.log(`User logged in: ${user.id}`);

    // Return user without password — toIUser mapping in UserService handles this
    const { password: _removed, ...safeUser } = user;
    return { user: safeUser, ...tokens };
  }

  /**
   * Logs out a user by revoking their current access token.
   * Also deletes all refresh tokens — cleans up DB.
   *
   * @param accessToken - Raw JWT string from Authorization header
   * @param userId      - Authenticated user's ID (from JWT payload)
   */
  async logout(accessToken: string, userId: string): Promise<{ message: string }> {
    // Blacklist this specific access token in Redis
    await this.tokenService.revokeAccessToken(accessToken);

    // Delete all refresh tokens for this user
    // If they want to re-login on other devices, they'll need to authenticate again
    // Adjust this if you want "logout from this device only" behavior
    await this.tokenService.revokeAllUserTokens(userId);

    this.logger.log(`User logged out: ${userId}`);

    return { message: 'Logged out successfully' };
  }

  /**
   * Issues a new token pair by rotating the refresh token.
   * Delegates entirely to TokenService — no business logic here.
   *
   * @param refreshToken - Current refresh token
   */
  async refresh(refreshToken: string): Promise<ITokenPair> {
    return this.tokenService.rotateRefreshToken(refreshToken);
  }

  /**
   * Changes a user's password and revokes ALL their active sessions.
   *
   * Flow:
   * 1. Verify current password is correct
   * 2. Hash new password
   * 3. Update in DB
   * 4. Revoke all tokens — forces re-login everywhere
   *
   * @param userId          - Authenticated user's ID
   * @param currentPassword - Must match stored hash
   * @param newPassword     - New plain text password
   */
  async changePassword(
    userId: string,
    currentPassword: string,
    newPassword: string,
  ): Promise<{ message: string }> {
    // Fetch user with password for verification
    const user = await this.userService.findById(userId);

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    // Need the hashed password — findById excludes it
    // So we find by the stored hash from a dedicated method
    const userWithPassword = await this.userService.findByEmail(user.email);

    // Verify current password before allowing change
    const valid = await this.userService.validatePassword(
      currentPassword,
      userWithPassword!.password,
    );

    if (!valid) {
      throw new UnauthorizedException('Current password is incorrect');
    }

    // Hash new password
    const hashed = await bcrypt.hash(newPassword, 12);

    // Update in DB
    await this.userService.updatePassword(userId, hashed);

    // Revoke ALL tokens — Redis user-level ban + DB refresh token cleanup
    // Forces re-login on ALL devices immediately
    await this.tokenService.revokeAllUserTokens(userId);

    this.logger.log(`Password changed for user: ${userId}`);

    return { message: 'Password changed. Please login again.' };
  }
}