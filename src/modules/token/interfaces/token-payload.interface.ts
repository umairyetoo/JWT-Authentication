// src/modules/token/interfaces/token-payload.interface.ts

/**
 * ITokenPayload — Shape of data encoded inside a JWT.
 *
 * SOLID — I (Interface Segregation):
 * Kept small and focused — only what belongs in a token.
 * Not mixed with user profile data or DB models.
 */
export interface ITokenPayload {
  sub: string;    // userId — subject of the token
  email: string;  // user email
  role: string;   // user role — for authorization decisions
  jti: string;    // unique token ID — used for blacklisting
  type: 'access' | 'refresh'; // prevents refresh tokens being used as access tokens
  iat?: number;   // issued at (set automatically by jwt.sign)
  exp?: number;   // expiry (set automatically by jwt.sign)
}