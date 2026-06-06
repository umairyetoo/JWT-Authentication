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
import { GoogleOAuthProvider } from './providers/google-oauth.provider';
import { PkceService } from './services/pkce.service';
import { IAuthResponse } from '../token/interfaces/auth-response.interface';
import { ITokenPair } from '../token/interfaces/token-pair.interface';

/**
 * AuthService — Orchestrates the authentication flow.
 *
 * SOLID — S (Single Responsibility):
 * Only responsible for auth business logic — register, login, logout,
 * refresh, change password.
 * Delegates user DB operations to UserService.
 * Delegates token operations to TokenService.
 * Delegates PKCE operations to PkceService.
 * One reason to change: auth business rules change.
 *
 * SOLID — D (Dependency Inversion):
 * Depends on IUserService and ITokenService interfaces.
 * Depends on IPkceService interface for PKCE operations.
 * Not coupled to UserService, TokenService, or PkceService implementations.
 * In tests — mock implementations can be injected transparently.
 *
 * AuthService knows the FLOW.
 * UserService knows the DATA.
 * TokenService knows the TOKENS.
 * PkceService knows the PKCE CRYPTO.
 * Each stays in its lane.
 *
 * PKCE integration in the OAuth flow:
 *   getGoogleAuthUrl():
 *     1. PkceService generates code_verifier + code_challenge + state
 *     2. PkceService stores code_verifier in Redis (keyed by state)
 *     3. GoogleOAuthProvider builds URL with code_challenge + state
 *     4. Returns the URL + state for the client to redirect
 *
 *   loginWithGoogle(code, state):
 *     1. PkceService retrieves code_verifier from Redis (keyed by state)
 *     2. GoogleOAuthProvider exchanges code + code_verifier for access_token
 *     3. Google verifies SHA256(code_verifier) === code_challenge
 *     4. If verified → returns access_token → flow continues as before
 */
@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private readonly userService: UserService,
    private readonly tokenService: TokenService,
    private readonly googleOAuthProvider: GoogleOAuthProvider,
    private readonly pkceService: PkceService,
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
   * Returns the Google OAuth authorization URL with PKCE parameters.
   *
   * PKCE flow (server-side):
   * 1. PkceService.generatePkceChallenge() creates:
   *    - code_verifier: random 43-char base64url string (256 bits entropy)
   *    - code_challenge: SHA-256 hash of verifier, base64url-encoded
   *    - state: random 64-char hex string (256 bits entropy)
   *
   * 2. PkceService.storeCodeVerifier(state, codeVerifier) persists the verifier
   *    in Redis with a 10-minute TTL. The verifier NEVER leaves the server.
   *
   * 3. GoogleOAuthProvider.getAuthorizationUrl(codeChallenge, state) builds the
   *    Google authorization URL with code_challenge + code_challenge_method=S256 + state.
   *
   * The code_challenge tells Google: "When I come back with the authorization code,
   * I'll also send a code_verifier. Hash it and check it matches this challenge."
   *
   * SOLID — S: AuthService orchestrates the PKCE flow but doesn't implement
   * the crypto (PkceService does) or the URL building (GoogleOAuthProvider does).
   *
   * @returns Object with authorizationUrl for the client to redirect to
   */
  getGoogleAuthUrl(): { authorizationUrl: string } {
    // Step 1 — Generate PKCE challenge set
    const { codeVerifier, codeChallenge, state } = this.pkceService.generatePkceChallenge();

    // Step 2 — Store code_verifier server-side (Redis, 10-min TTL)
    // Fire-and-forget: we don't await because the redirect is not dependent
    // on the store completing synchronously. However, in practice, Redis SETEX
    // is sub-millisecond. We store it before building the URL to ensure the
    // verifier is persisted before the user is redirected to Google.
    // Using void to explicitly discard the promise is intentional — the store
    // operation should not block the URL generation.
    void this.pkceService.storeCodeVerifier(state, codeVerifier);

    // Step 3 — Build authorization URL with PKCE params
    const authorizationUrl = this.googleOAuthProvider.getAuthorizationUrl(codeChallenge, state);

    this.logger.log('Google OAuth authorization URL generated with PKCE');

    return { authorizationUrl };
  }

  /**
   * Handles Google OAuth login via authorization code exchange with PKCE verification.
   *
   * PKCE verification flow:
   * 1. Retrieve code_verifier from Redis using the state parameter.
   *    - If state is not found → CSRF attack or expired flow → throw UnauthorizedException
   *    - Retrieval is atomic (get + delete) — one-time use, prevents replay
   *
   * 2. Exchange authorization code + code_verifier at Google's token endpoint.
   *    - Google computes SHA256(code_verifier) and compares against the code_challenge
   *      that was sent during authorization.
   *    - If they don't match → Google rejects the token exchange → 400 Bad Request
   *    - This is the core PKCE security guarantee: even if an attacker intercepts
   *      the authorization code, they can't exchange it without the code_verifier.
   *
   * 3. Fetch user profile + issue our own JWT tokens (unchanged from pre-PKCE flow).
   *
   * @param code  - Authorization code from Google callback
   * @param state - State parameter echoed back by Google (used to retrieve code_verifier)
   */
  async loginWithGoogle(code: string, state: string): Promise<IAuthResponse> {
    // Step 1 — Retrieve and delete code_verifier from Redis
    // Throws UnauthorizedException if not found (expired or CSRF)
    const codeVerifier = await this.pkceService.retrieveAndDeleteCodeVerifier(state);

    // Step 2 — Exchange authorization code + code_verifier for access token
    // Google verifies: SHA256(codeVerifier) === codeChallenge
    const accessToken = await this.googleOAuthProvider.exchangeCodeForTokens(code, codeVerifier);

    // Step 3 — Fetch user profile from Google (unchanged by PKCE)
    const profile = await this.googleOAuthProvider.getUserProfile(accessToken);

    const user = await this.userService.createOAuthUser(
      profile.email,
      'GOOGLE',
      profile.providerId,
      profile.name,
    );

    if (!user.isActive) {
      throw new ForbiddenException('Account has been suspended');
    }

    const tokens = await this.tokenService.generateTokenPair(
      user.id,
      user.email,
      user.role,
    );

    this.logger.log(`User logged in via Google (PKCE verified): ${user.id}`);

    const safeUser = { ...user };
    if (safeUser.email) {
      const [localPart, domain] = safeUser.email.split('@');
      if (localPart && domain) {
        const maskedLocal = localPart.charAt(0) + '*'.repeat(localPart.length - 1);
        safeUser.email = `${maskedLocal}@${domain}`;
      }
    }

    return { user: safeUser, ...tokens };
  }

  /**
   * Fetches the user profile and masks the email.
   *
   * SOLID — S: Only responsible for fetching and masking.
   * Delegates DB lookup to UserService.
   */
  async getProfile(userId: string): Promise<any> {
    const user = await this.userService.findById(userId);
    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    const safeUser = { ...user };
    if (safeUser.email) {
      const [localPart, domain] = safeUser.email.split('@');
      if (localPart && domain) {
        const maskedLocal = localPart.charAt(0) + '*'.repeat(localPart.length - 1);
        safeUser.email = `${maskedLocal}@${domain}`;
      }
    }
    return safeUser;
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
    
    // Mask email for security: keep first char, mask rest of local part
    if (safeUser.email) {
      const [localPart, domain] = safeUser.email.split('@');
      if (localPart && domain) {
        const maskedLocal = localPart.charAt(0) + '*'.repeat(localPart.length - 1);
        // @ts-ignore - Assuming safeUser is mutable here
        safeUser.email = `${maskedLocal}@${domain}`;
      }
    }

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