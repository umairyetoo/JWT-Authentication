// src/modules/token/interfaces/token-pair.interface.ts

/**
 * ITokenPair — Return type when issuing a new access + refresh token pair.
 *
 * SOLID — I (Interface Segregation):
 * Separate interface for the token pair response.
 * Not bundled with user data or other unrelated fields.
 */
export interface ITokenPair {
  accessToken: string;
  refreshToken: string;
}