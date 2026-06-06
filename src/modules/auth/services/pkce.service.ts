// src/modules/auth/services/pkce.service.ts
import { Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import * as crypto from 'crypto';
import { RedisService } from '../../redis/redis.service';
import { IPkceChallenge, IPkceService } from '../interfaces/pkce.interface';

/**
 * PkceService — Handles PKCE (Proof Key for Code Exchange) operations.
 *
 * SOLID — S (Single Responsibility):
 * Only responsible for:
 *   1. Generating cryptographically secure PKCE challenges
 *   2. Storing/retrieving code_verifier values via Redis
 * Does NOT know about Google, OAuth flows, tokens, or users.
 * One reason to change: PKCE specification or storage strategy changes.
 *
 * SOLID — D (Dependency Inversion):
 * Implements IPkceService — consumers depend on the abstraction.
 * Uses RedisService for storage — but only through its generic methods.
 * Swapping Redis for Memcached or DynamoDB would only change this class.
 *
 * Security design:
 *   - code_verifier is generated with 32 bytes of crypto.randomBytes (256 bits of entropy)
 *   - code_challenge uses SHA-256 (S256 method — the ONLY method recommended by RFC 7636)
 *   - state is generated with 32 bytes of crypto.randomBytes for CSRF protection
 *   - code_verifier is stored server-side in Redis, NEVER sent to the client
 *   - TTL of 10 minutes — authorization codes expire quickly, no reason to keep verifiers longer
 *   - Retrieval is atomic (get + delete) — one-time use, prevents replay attacks
 */
@Injectable()
export class PkceService implements IPkceService {
  private readonly logger = new Logger(PkceService.name);

  /**
   * Redis key prefix for PKCE code_verifier storage.
   * Keys follow the pattern: pkce:verifier:{state}
   * Namespaced to avoid collisions with token blacklist keys.
   */
  private static readonly REDIS_KEY_PREFIX = 'pkce:verifier:';

  /**
   * TTL for stored code_verifier values (in seconds).
   * 10 minutes — generous enough for the user to complete the OAuth flow,
   * short enough that Redis doesn't accumulate stale entries.
   * Google authorization codes expire in ~10 minutes anyway.
   */
  private static readonly VERIFIER_TTL_SECONDS = 600;

  constructor(private readonly redisService: RedisService) {}

  /**
   * Generates a complete PKCE challenge set.
   *
   * Steps:
   * 1. Generate code_verifier: 32 random bytes → base64url encoded (43 chars)
   *    RFC 7636 §4.1 requires 43–128 chars from the unreserved character set.
   *    Base64url encoding of 32 bytes = 43 chars — meets the minimum exactly.
   *
   * 2. Generate code_challenge: SHA-256 hash of verifier → base64url encoded
   *    RFC 7636 §4.2 — S256 method: BASE64URL(SHA256(code_verifier))
   *    Plain method (code_challenge = code_verifier) is NOT used — it provides
   *    zero security benefit and is only allowed for backward compatibility.
   *
   * 3. Generate state: 32 random bytes → hex encoded (64 chars)
   *    Used for both CSRF protection and as the Redis key for verifier lookup.
   *
   * @returns IPkceChallenge with codeVerifier, codeChallenge, and state
   */
  generatePkceChallenge(): IPkceChallenge {
    // Step 1 — Generate code_verifier (43 chars, base64url, 256 bits entropy)
    const codeVerifier = this.generateBase64UrlString(32);

    // Step 2 — Derive code_challenge: SHA-256 → base64url
    const codeChallenge = this.sha256Base64Url(codeVerifier);

    // Step 3 — Generate state (64 hex chars, 256 bits entropy)
    const state = crypto.randomBytes(32).toString('hex');

    this.logger.debug(`PKCE challenge generated for state: ${state}`);

    return { codeVerifier, codeChallenge, state };
  }

  /**
   * Stores the code_verifier in Redis, keyed by state.
   *
   * The verifier is stored with a TTL so it auto-expires.
   * This prevents Redis from accumulating entries for abandoned OAuth flows
   * (user starts OAuth, never completes the callback).
   *
   * @param state        - Random state string (used as Redis key suffix)
   * @param codeVerifier - The verifier to store (retrieved during callback)
   */
  async storeCodeVerifier(state: string, codeVerifier: string): Promise<void> {
    const key = PkceService.REDIS_KEY_PREFIX + state;
    await this.redisService.setWithTtl(key, codeVerifier, PkceService.VERIFIER_TTL_SECONDS);
    this.logger.debug(`Code verifier stored for state: ${state}`);
  }

  /**
   * Retrieves and atomically deletes the code_verifier for a given state.
   *
   * Atomic get-and-delete ensures one-time use:
   *   - If a valid state arrives → returns the verifier and deletes it
   *   - If the same state arrives again → returns null → throws UnauthorizedException
   *   - If an unknown state arrives → returns null → throws UnauthorizedException
   *
   * This prevents:
   *   - Replay attacks (reusing the same state/code pair)
   *   - CSRF attacks (forged state values won't have a matching verifier)
   *   - Timing attacks (expired verifiers are auto-deleted by Redis TTL)
   *
   * @param state - The state parameter from the OAuth callback query string
   * @returns     The code_verifier that was stored during authorization
   * @throws      UnauthorizedException if no verifier found for the given state
   */
  async retrieveAndDeleteCodeVerifier(state: string): Promise<string> {
    const key = PkceService.REDIS_KEY_PREFIX + state;
    const codeVerifier = await this.redisService.getAndDelete(key);

    if (!codeVerifier) {
      this.logger.warn(`No PKCE verifier found for state: ${state}. Possible CSRF or expired flow.`);
      throw new UnauthorizedException(
        'Invalid or expired OAuth state. Please try logging in again.',
      );
    }

    this.logger.debug(`Code verifier retrieved and deleted for state: ${state}`);
    return codeVerifier;
  }

  /**
   * Generates a cryptographically random base64url-encoded string.
   *
   * Base64url encoding (RFC 4648 §5):
   *   - Uses '-' instead of '+'
   *   - Uses '_' instead of '/'
   *   - No padding ('=') — not needed for PKCE
   *
   * @param byteLength - Number of random bytes (32 bytes = 43 base64url chars)
   */
  private generateBase64UrlString(byteLength: number): string {
    return crypto
      .randomBytes(byteLength)
      .toString('base64url');
  }

  /**
   * Computes SHA-256 hash and returns base64url-encoded result.
   * Implements the S256 code_challenge_method from RFC 7636 §4.2:
   *   code_challenge = BASE64URL(SHA256(ASCII(code_verifier)))
   *
   * @param input - The string to hash (code_verifier)
   */
  private sha256Base64Url(input: string): string {
    return crypto
      .createHash('sha256')
      .update(input, 'ascii')
      .digest('base64url');
  }
}
