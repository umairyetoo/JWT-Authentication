// src/modules/auth/auth.controller.ts
import {
  Controller,
  Post,
  Body,
  UseGuards,
  HttpCode,
  HttpStatus,
  Req,
  Get,
  Query,
  Res,
  UnauthorizedException,
} from '@nestjs/common';
import { ApiTags, ApiBearerAuth, ApiOperation, ApiBody } from '@nestjs/swagger';
import { AuthService } from './auth.service';
import { JwtAuthGuard } from '../../common/guards/jwt.guard';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { ChangePasswordDto } from './dto/change-password.dto';
import { ITokenPayload } from '../token/interfaces/token-payload.interface';
import { IRequestWithUser } from '../../common/interfaces/request-with-user.interface';

/**
 * AuthController — HTTP entry point for authentication operations.
 *
 * SOLID — S (Single Responsibility):
 * Only responsible for HTTP concerns:
 *   - Extracting request data (body, query params, headers)
 *   - Validating required parameters (state, code)
 *   - Calling AuthService
 *   - Returning responses
 * Zero business logic lives here.
 * Zero PKCE logic lives here — AuthService orchestrates the flow.
 *
 * SOLID — D (Dependency Inversion):
 * Depends on AuthService — not on UserService, TokenService, or PkceService directly.
 * Controller only knows about the auth flow, not its internals.
 *
 * PKCE impact on controller:
 *   GET /auth/google:
 *     - Changed from redirect to JSON response.
 *     - Returns { authorizationUrl } — the client redirects to it.
 *     - This is necessary because the backend generates PKCE params (code_challenge,
 *       state) server-side and embeds them in the URL. A direct redirect would
 *       work, but returning JSON gives the frontend more control (e.g., opening
 *       in a popup, showing a loading state).
 *
 *   GET /auth/google/callback:
 *     - Now extracts both `code` and `state` from query params.
 *     - Validates that both are present before calling AuthService.
 *     - Passes `state` to AuthService so it can retrieve the code_verifier.
 */
@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  /**
   * POST /auth/register
   * Public endpoint — no guard required.
   * Creates new user and returns token pair.
   */
  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Register a new user' })
  async register(@Body() dto: RegisterDto) {
    return this.authService.register(dto.email, dto.password);
  }

  /**
   * POST /auth/login
   * Public endpoint — no guard required.
   * Returns token pair on valid credentials.
   * 200 not 201 — no resource created, just authenticating.
   */
  @Post('login')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Login with email and password' })
  async login(@Body() dto: LoginDto) {
    return this.authService.login(dto.email, dto.password);
  }

  /**
   * GET /auth/google
   * Returns the Google OAuth 2.0 authorization URL with PKCE parameters.
   *
   * Why JSON response instead of redirect?
   * The backend generates PKCE params (code_challenge, state) server-side and
   * embeds them in the authorization URL. Returning JSON allows the frontend to:
   *   1. Fetch the URL via API call
   *   2. Redirect the user to Google's consent screen
   *   3. Maintain control over the UX (loading states, error handling)
   *
   * The response contains:
   *   - authorizationUrl: Full Google OAuth URL with client_id, redirect_uri,
   *     scope, code_challenge, code_challenge_method=S256, and state.
   *
   * The code_verifier is stored server-side in Redis (keyed by state).
   * It NEVER appears in the response — only the derived code_challenge is
   * sent to Google via the authorization URL.
   */
  @Get('google')
  @ApiOperation({ summary: 'Returns Google OAuth authorization URL with PKCE' })
  googleAuth() {
    return this.authService.getGoogleAuthUrl();
  }

  /**
   * GET /auth/google/callback
   * Handles the Google OAuth callback with PKCE verification.
   *
   * Query parameters:
   *   - code:  Authorization code from Google (used to get access token)
   *   - state: Random string echoed back by Google (used to retrieve code_verifier)
   *
   * PKCE verification happens inside AuthService.loginWithGoogle():
   *   1. Retrieves code_verifier from Redis using state
   *   2. Sends code + code_verifier to Google's token endpoint
   *   3. Google verifies SHA256(code_verifier) === code_challenge
   *
   * Security validations at this layer:
   *   - Both code and state must be present → if missing, reject immediately
   *   - This prevents processing requests that can't possibly succeed
   *   - Detailed PKCE/CSRF validation happens in PkceService
   */
  @Get('google/callback')
  @ApiOperation({ summary: 'Handles Google OAuth callback with PKCE verification' })
  async googleAuthCallback(
    @Query('code') code: string,
    @Query('state') state: string,
    @Res() res: any,
  ) {
    // Validate required query parameters
    // Both are mandatory when PKCE is enabled:
    //   - code:  without it, there's nothing to exchange
    //   - state: without it, we can't retrieve the code_verifier from Redis
    if (!code || !state) {
      throw new UnauthorizedException(
        'Missing required OAuth callback parameters (code and state)',
      );
    }

    const authResponse = await this.authService.loginWithGoogle(code, state);
    
    // Redirect to frontend with tokens in URL
    // Since NestJS is serving public/, we can just redirect to localhost:3001 by default
    const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:3001';
    res.redirect(`${frontendUrl}?accessToken=${authResponse.accessToken}&refreshToken=${authResponse.refreshToken}`);
  }

  /**
   * GET /auth/me
   * Protected — returns current user profile with masked email.
   */
  @Get('me')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth('access-token')
  @ApiOperation({ summary: 'Get current user profile' })
  async getProfile(@CurrentUser() user: ITokenPayload) {
    return this.authService.getProfile(user.sub);
  }

  /**
   * POST /auth/logout
   * Protected — requires valid access token.
   * Revokes current token and all refresh tokens.
   *
   * @CurrentUser() extracts payload from request (set by JwtAuthGuard)
   * @Req() needed to extract raw token string for blacklisting
   */
  @Post('logout')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth('access-token')
  @ApiOperation({ summary: 'Logout and revoke current tokens' })
  async logout(
    @CurrentUser() user: ITokenPayload,
    @Req() req: IRequestWithUser,
  ) {
    // Extract raw token string — needed for blacklisting by jti
    const rawToken = req.headers.authorization!.split(' ')[1];
    return this.authService.logout(rawToken, user.sub);
  }

  /**
   * POST /auth/refresh
   * Public — no access token required (it's expired, that's why we're refreshing)
   * Body: { refreshToken: string }
   */
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Refresh tokens using a refresh token' })
  @ApiBody({ schema: { properties: { refreshToken: { type: 'string' } } } })
  async refresh(@Body('refreshToken') refreshToken: string) {
    return this.authService.refresh(refreshToken);
  }

  /**
   * POST /auth/change-password
   * Protected — must be authenticated to change password.
   */
  @Post('change-password')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth('access-token')
  @ApiOperation({ summary: "Change authenticated user's password" })
  async changePassword(
    @CurrentUser() user: ITokenPayload,
    @Body() dto: ChangePasswordDto,
  ) {
    return this.authService.changePassword(
      user.sub,
      dto.currentPassword,
      dto.newPassword,
    );
  }
}