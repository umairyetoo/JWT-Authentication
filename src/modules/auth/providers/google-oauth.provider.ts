// src/modules/auth/providers/google-oauth.provider.ts
import { Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import axios from 'axios';
import { IOAuthProvider, IOAuthProfile } from '../interfaces/oauth-provider.interface';

/**
 * GoogleOAuthProvider — Handles Google-specific OAuth 2.0 Authorization Code Grant.
 *
 * SOLID — S (Single Responsibility):
 * Only responsible for Google-specific OAuth mechanics:
 *   1. Building the Google authorization URL (with optional PKCE params)
 *   2. Exchanging authorization codes at Google's token endpoint (with optional code_verifier)
 *   3. Fetching user profile from Google's userinfo endpoint
 * Does NOT generate PKCE values — receives them as parameters from the caller.
 * Does NOT handle user creation, token issuance, or business logic.
 * One reason to change: Google's OAuth API changes.
 *
 * SOLID — O (Open/Closed):
 * PKCE support was added WITHOUT modifying the existing authorization/token logic.
 * PKCE parameters are optional — if not provided, the flow works exactly as before.
 * If Google adds new OAuth features (e.g., DPoP), they can be added the same way.
 *
 * SOLID — L (Liskov Substitution):
 * Implements IOAuthProvider — can be swapped with any other IOAuthProvider
 * (GitHubOAuthProvider, MicrosoftOAuthProvider) without affecting AuthService.
 *
 * SOLID — D (Dependency Inversion):
 * Depends on ConfigService abstraction for configuration.
 * Does not depend on PkceService — receives PKCE values as plain parameters.
 * The caller (AuthService) decides whether to use PKCE; this class just passes values through.
 *
 * PKCE flow from this provider's perspective:
 *   Authorization: Appends code_challenge + code_challenge_method + state to the URL
 *   Token exchange: Includes code_verifier in the POST body
 *   Google verifies: SHA256(code_verifier) === code_challenge
 */
@Injectable()
export class GoogleOAuthProvider implements IOAuthProvider {
  private readonly logger = new Logger(GoogleOAuthProvider.name);

  constructor(private readonly configService: ConfigService) {}

  /**
   * Builds the Google OAuth 2.0 authorization URL.
   *
   * Base parameters (always included):
   *   - client_id:     Identifies our application to Google
   *   - redirect_uri:  Where Google sends the user after consent
   *   - response_type: 'code' — we want an authorization code, not a token
   *   - scope:         'openid email profile' — what data we're requesting
   *   - access_type:   'offline' — request a refresh token from Google
   *   - prompt:        'consent' — force consent screen every time (ensures refresh token)
   *
   * PKCE parameters (included when codeChallenge and state are provided):
   *   - code_challenge:        SHA-256 hash of code_verifier, base64url-encoded
   *   - code_challenge_method: 'S256' — tells Google we used SHA-256 (not plain)
   *   - state:                 Random string echoed back in callback for CSRF protection
   *
   * @param codeChallenge - Optional PKCE code_challenge
   * @param state         - Optional state for CSRF protection + verifier lookup
   * @returns             Complete authorization URL
   */
  getAuthorizationUrl(codeChallenge?: string, state?: string): string {
    const clientId = this.configService.get<string>('GOOGLE_CLIENT_ID');
    const redirectUri = this.configService.get<string>('GOOGLE_REDIRECT_URI') || 'http://localhost:3001/auth/google/callback';
    
    if (!clientId) {
      this.logger.error('GOOGLE_CLIENT_ID is not configured');
      throw new Error('Google OAuth is not configured properly');
    }

    const scope = 'openid email profile';
    const responseType = 'code';
    const accessType = 'offline';
    const prompt = 'consent';

    // Build base URL with required params
    let url = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${clientId}&redirect_uri=${redirectUri}&response_type=${responseType}&scope=${scope}&access_type=${accessType}&prompt=${prompt}`;

    // Append PKCE parameters if provided
    // These are optional to satisfy Open/Closed principle — the method works
    // with or without PKCE. If a caller doesn't pass these, the flow degrades
    // gracefully to a standard (non-PKCE) authorization code grant.
    if (codeChallenge && state) {
      url += `&code_challenge=${codeChallenge}`;
      url += `&code_challenge_method=S256`;
      url += `&state=${state}`;

      this.logger.debug('Authorization URL built with PKCE parameters');
    }

    return url;
  }

  /**
   * Exchanges an authorization code for an access token at Google's token endpoint.
   *
   * Standard parameters (always sent):
   *   - client_id:     Our application identifier
   *   - client_secret: Our application secret (confidential client)
   *   - code:          The authorization code from the callback
   *   - grant_type:    'authorization_code'
   *   - redirect_uri:  Must match the one used in the authorization request
   *
   * PKCE parameter (sent when codeVerifier is provided):
   *   - code_verifier: The original random string. Google computes
   *                    SHA256(code_verifier) and compares it against the
   *                    code_challenge sent during authorization. If they
   *                    don't match, the token exchange is REJECTED — even
   *                    if the authorization code is valid.
   *
   * Note: Even though we're a confidential client (we have a client_secret),
   * PKCE adds defense-in-depth. OAuth 2.1 recommends PKCE for ALL clients.
   *
   * @param code         - Authorization code from Google callback
   * @param codeVerifier - Optional PKCE code_verifier for proof of possession
   * @returns            Access token from Google
   */
  async exchangeCodeForTokens(code: string, codeVerifier?: string): Promise<string> {
    const clientId = this.configService.get<string>('GOOGLE_CLIENT_ID');
    const clientSecret = this.configService.get<string>('GOOGLE_CLIENT_SECRET');
    const redirectUri = this.configService.get<string>('GOOGLE_REDIRECT_URI') || 'http://localhost:3001/auth/google/callback';

    // Build the token request body
    const tokenRequestBody: Record<string, string> = {
      client_id: clientId!,
      client_secret: clientSecret!,
      code,
      grant_type: 'authorization_code',
      redirect_uri: redirectUri,
    };

    // Include code_verifier in the token request when PKCE is active.
    // Google will compute SHA256(code_verifier) and compare it against
    // the code_challenge that was sent during authorization.
    // If they don't match → 400 Bad Request → token exchange fails.
    if (codeVerifier) {
      tokenRequestBody.code_verifier = codeVerifier;
      this.logger.debug('Token exchange includes PKCE code_verifier');
    }

    try {
      const response = await axios.post('https://oauth2.googleapis.com/token', tokenRequestBody);

      // We only need the access_token to fetch the profile
      return response.data.access_token;
    } catch (error: any) {
      this.logger.error(`Failed to exchange code for token: ${error.message}`);
      throw new UnauthorizedException('Failed to authenticate with Google');
    }
  }

  /**
   * Fetches the authenticated user's profile from Google's userinfo endpoint.
   *
   * This method is unchanged by PKCE — PKCE only affects the authorization
   * and token exchange steps. Once we have a valid access token, the profile
   * fetch works exactly the same way.
   *
   * @param accessToken - Valid Google access token
   * @returns           User profile with providerId, email, name, and provider
   */
  async getUserProfile(accessToken: string): Promise<IOAuthProfile> {
    try {
      const response = await axios.get('https://www.googleapis.com/oauth2/v2/userinfo', {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      });

      return {
        providerId: response.data.id,
        email: response.data.email,
        name: response.data.name,
        provider: 'GOOGLE',
      };
    } catch (error: any) {
      this.logger.error(`Failed to fetch user profile: ${error.message}`);
      throw new UnauthorizedException('Failed to fetch user profile from Google');
    }
  }
}
