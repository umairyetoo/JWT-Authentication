// src/modules/auth/interfaces/pkce.interface.ts

/**
 * IPkceChallenge — Shape returned when generating a new PKCE challenge.
 *
 * PKCE (Proof Key for Code Exchange — RFC 7636) requires three values:
 *   - codeVerifier:  A cryptographically random string (43–128 chars, unreserved URI chars).
 *                    This is the "proof" — sent to the token endpoint during code exchange.
 *   - codeChallenge: SHA-256 hash of the codeVerifier, base64url-encoded.
 *                    This is sent to the authorization endpoint upfront.
 *   - state:         A random string for CSRF protection AND for keying the
 *                    code_verifier in server-side storage. Links the authorization
 *                    request to its callback.
 *
 * The authorization server (e.g., Google) verifies:
 *   SHA256(code_verifier) === code_challenge
 * If they don't match, the token exchange is rejected — even if the attacker
 * has the authorization code, they can't exchange it without the verifier.
 */
export interface IPkceChallenge {
  codeVerifier: string;
  codeChallenge: string;
  state: string;
}

/**
 * IPkceService — Interface for PKCE operations.
 *
 * SOLID — I (Interface Segregation):
 * Only the 3 methods consumers need are exposed:
 *   1. Generate a challenge (crypto)
 *   2. Store the verifier (persistence)
 *   3. Retrieve and delete the verifier (one-time use)
 *
 * Redis internals (TTL, key format, connection handling) are hidden.
 * Consumers don't need to know HOW the verifier is stored — just that it IS.
 *
 * SOLID — D (Dependency Inversion):
 * AuthService depends on this interface, not the concrete PkceService.
 * In tests, a mock implementation can be injected transparently.
 */
export interface IPkceService {
  /**
   * Generates a new PKCE challenge set (verifier + challenge + state).
   * Pure cryptographic operation — no I/O, no side effects.
   */
  generatePkceChallenge(): IPkceChallenge;

  /**
   * Stores the code_verifier in server-side storage, keyed by state.
   * Must have a TTL — verifiers should not persist indefinitely.
   *
   * @param state        - The state parameter (used as the storage key)
   * @param codeVerifier - The code_verifier to store
   */
  storeCodeVerifier(state: string, codeVerifier: string): Promise<void>;

  /**
   * Retrieves and atomically deletes the code_verifier for a given state.
   * One-time use — once retrieved, the verifier is gone.
   * Throws if the state is not found (expired or CSRF attack).
   *
   * @param state - The state parameter from the callback query
   * @returns     The code_verifier originally stored
   * @throws      UnauthorizedException if state not found
   */
  retrieveAndDeleteCodeVerifier(state: string): Promise<string>;
}
