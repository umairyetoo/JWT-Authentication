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
 *   - Extracting request data
 *   - Calling AuthService
 *   - Returning responses
 * Zero business logic lives here.
 *
 * SOLID — D (Dependency Inversion):
 * Depends on AuthService — not on UserService or TokenService directly.
 * Controller only knows about the auth flow, not its internals.
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
   * Redirects the user to Google's OAuth 2.0 consent screen.
   */
  @Get('google')
  @ApiOperation({ summary: 'Redirects to Google OAuth consent screen' })
  googleAuth(@Res() res: any) {
    const url = this.authService.getGoogleAuthUrl();
    res.redirect(url);
  }

  /**
   * GET /auth/google/callback
   * Handles the Authorization Code exchange and logs the user in.
   */
  @Get('google/callback')
  @ApiOperation({ summary: 'Handles Google OAuth callback' })
  async googleAuthCallback(@Query('code') code: string, @Res() res: any) {
    const authResponse = await this.authService.loginWithGoogle(code);
    
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