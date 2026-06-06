/**
 * IOAuthProfile — Shape returned after fetching user info from an OAuth provider.
 *
 * SOLID — I (Interface Segregation):
 * Contains only the fields our system needs from the provider.
 * We don't carry the full Google/GitHub/Facebook profile shape — just what's relevant.
 */
export interface IOAuthProfile {
  providerId: string;
  email: string;
  name: string;
  provider: 'GOOGLE';
}

/**
 * IOAuthProvider — Interface for OAuth 2.0 Authorization Code Grant providers.
 *
 * SOLID — O (Open/Closed):
 * PKCE parameters (codeChallenge, state, codeVerifier) are OPTIONAL.
 * This means:
 *   - Existing providers that don't support PKCE continue to work unchanged.
 *   - New providers can be added with or without PKCE support.
 *   - The interface is open for extension (PKCE), closed for modification.
 *
 * SOLID — L (Liskov Substitution):
 * Any implementation of IOAuthProvider can be substituted for another.
 * The caller (AuthService) passes PKCE params — the provider decides whether
 * to use them. A provider that ignores PKCE params is still a valid IOAuthProvider.
 *
 * SOLID — D (Dependency Inversion):
 * AuthService depends on this abstraction, not on GoogleOAuthProvider directly.
 * Swapping Google for GitHub only requires a new IOAuthProvider implementation.
 *
 * PKCE parameters explained:
 *   - codeChallenge: SHA-256 hash of code_verifier, base64url-encoded.
 *                    Sent to the authorization endpoint in the initial redirect.
 *   - state:         Random string for CSRF protection + server-side verifier lookup.
 *                    Sent to authorization endpoint, echoed back in callback.
 *   - codeVerifier:  The original random string. Sent to the token endpoint
 *                    during code exchange. The provider verifies SHA256(verifier) === challenge.
 */
export interface IOAuthProvider {
  /**
   * Builds the authorization URL that the user is redirected to.
   *
   * When PKCE is enabled:
   *   - codeChallenge is appended as `code_challenge` query param
   *   - state is appended as `state` query param
   *   - `code_challenge_method=S256` is appended
   *
   * @param codeChallenge - Optional PKCE code_challenge (SHA-256, base64url)
   * @param state         - Optional state parameter for CSRF + verifier lookup
   */
  getAuthorizationUrl(codeChallenge?: string, state?: string): string;

  /**
   * Exchanges an authorization code for an access token.
   *
   * When PKCE is enabled:
   *   - codeVerifier is included in the token request body
   *   - The OAuth provider verifies SHA256(code_verifier) === code_challenge
   *
   * @param code         - Authorization code from the callback
   * @param codeVerifier - Optional PKCE code_verifier for proof of possession
   * @returns            The access token from the provider
   */
  exchangeCodeForTokens(code: string, codeVerifier?: string): Promise<string>;

  /**
   * Fetches the authenticated user's profile from the provider.
   *
   * @param accessToken - Access token obtained from code exchange
   */
  getUserProfile(accessToken: string): Promise<IOAuthProfile>;
}
