# JWT Authentication || OAuth 2.0 Authorization Code Grant Flow

A NestJS authentication service using JWT, Prisma, and Redis.

## Features

- User registration and login
- Access token + refresh token issuance
- Refresh token rotation
- **Google OAuth 2.0 login (Authorization Code Grant)**
- Logout and password-based token revocation
- Redis-backed JWT blacklist for token invalidation
- Swagger API documentation at `/api`
- `.env`-driven configuration

## Requirements

- Node.js 20+ (or compatible)
- PostgreSQL (or configured Prisma database)
- Redis for token revocation

## Setup

1. Install dependencies:

```bash
npm install
```

2. Copy environment variables:

```bash
cp .env.example .env
```

3. Update `.env` values:

- `DATABASE_URL`
- `REDIS_HOST`
- `REDIS_PORT`
- `JWT_PRIVATE_KEY_PATH`
- `JWT_PUBLIC_KEY_PATH`
- `JWT_ACCESS_EXPIRY`
- `JWT_REFRESH_EXPIRY`
- `JWT_ISSUER`
- `JWT_AUDIENCE`

4. Ensure `keys/private.pem` and `keys/public.pem` exist.

## Run the application

### Development

```bash
npm run start:dev
```

### Production build

```bash
npm run build
npm start
```

The app listens on `http://localhost:3001` by default.

## Swagger docs

Open Swagger UI at:

```text
http://localhost:3001/api
```

This will display all available authentication endpoints.

## How token revocation works with Redis

This app uses Redis to revoke JWT access tokens immediately after logout or password change.

- When a user logs out, the access token's `jti` is stored in Redis as a blacklist entry.
- Each protected request checks Redis for the token's `jti`.
- If the token is blacklisted, the request is rejected even if the JWT is otherwise valid.
- On password change, the app also writes a user-level blacklist key.
  - This invalidates all tokens for that user, not just the current one.

Redis therefore provides fast, in-memory invalidation for tokens that should no longer be accepted.

## JWT asymmetric signing

This service uses asymmetric JWT signing with RSA key pairs.

- Private key: `keys/private.pem`
- Public key: `keys/public.pem`

### Why asymmetric is beneficial

- The private key signs tokens and is kept secret.
- The public key verifies tokens and can be safely distributed to other services.
- This supports secure token validation across microservices without sharing the private signing key.

### Symmetric vs asymmetric

- Symmetric JWTs use the same secret for signing and verification.
  - If that secret is shared, every verifying service can also sign tokens.
  - This increases attack surface and reduces trust boundaries.

- Asymmetric JWTs separate concerns:
  - Private key: signing only.
  - Public key: verification only.
  - This is safer for distributed systems and better for long-term key management.

## OAuth 2.0 — Google Login (Authorization Code Grant)

This project implements Google OAuth 2.0 using the **Authorization Code Grant** flow. This is the most secure standard OAuth flow for server-side applications — the user's credentials are never exposed to the frontend.

### How the flow works

```
┌──────────┐      1. Click "Login with Google"      ┌──────────────┐
│          │ ──────────────────────────────────────▶ │              │
│ Frontend │                                        │   Backend    │
│ (HTML)   │ ◀────────────────────────────────────── │  (NestJS)    │
│          │      2. Redirect to Google              │              │
└──────────┘                                        └──────┬───────┘
     │                                                     │
     │  3. User logs in on Google                          │
     ▼                                                     │
┌──────────────┐                                           │
│   Google     │  4. Redirects back with `code`            │
│   Consent    │ ─────────────────────────────────────────▶ │
│   Screen     │                                           │
└──────────────┘                                           │
                                                           │
                   5. Backend exchanges `code` for         │
                      Google access token (server-to-      │
                      server, secret never exposed)        │
                                                           │
                   6. Backend fetches user profile          │
                      from Google People API               │
                                                           │
                   7. Backend creates/finds user in DB     │
                                                           │
                   8. Backend generates JWT pair            │
                      (access + refresh token)             │
                                                           │
     ┌──────────┐  9. Redirect to frontend with           │
     │ Frontend │◀──── tokens in URL params  ◀─────────────┘
     └──────────┘
          │
          │ 10. Frontend calls GET /auth/me with
          │     access token to display user profile
          ▼
     ┌──────────┐
     │Dashboard │  Shows: name, masked email, role
     └──────────┘
```

### PKCE (Proof Key for Code Exchange) Protection

This implementation uses **PKCE** (RFC 7636) to secure the Authorization Code Grant flow. While originally designed for public clients (like mobile apps or SPAs), OAuth 2.1 recommends PKCE for *all* clients, including confidential server-side applications like this one.

**Why it was added:**
Standard Authorization Code Grant is vulnerable to **Authorization Code Interception Attacks**. If an attacker manages to intercept the `code` returned by Google in step 4 (e.g., via a compromised browser extension, malicious proxy, or log leakage), they could theoretically exchange it for an access token.

**How PKCE protects the flow:**
1. **Challenge Generation:** Before redirecting to Google, the server generates a cryptographically random `code_verifier` and its SHA-256 hash (`code_challenge`).
2. **Authorization:** The server sends the `code_challenge` to Google in the initial redirect. It stores the `code_verifier` in Redis (keyed by a random `state` parameter).
3. **Token Exchange:** When the callback returns with the `code`, the server retrieves the `code_verifier` from Redis and sends it alongside the `code` to Google's token endpoint.
4. **Verification:** Google hashes the provided `code_verifier` and compares it to the `code_challenge` from step 2. If they match, the token is issued.

Even if an attacker intercepts the `code` in step 4, they cannot exchange it for a token because they do not have the `code_verifier`, which is securely stored in the backend's Redis instance and never exposed to the frontend or network.

### Step 1: Create a Google OAuth App

1. Go to the [Google Cloud Console](https://console.cloud.google.com/).
2. Create a new project (or select an existing one).
3. Navigate to **APIs & Services → Credentials**.
4. Click **Create Credentials → OAuth client ID**.
5. Select **Web application** as the application type.
6. Set the following:
   - **Authorized JavaScript origins**: `http://localhost:3001`
   - **Authorized redirect URIs**: `http://localhost:3001/auth/google/callback`
7. Click **Create**. Copy the **Client ID** and **Client Secret**.

> **Note:** You may also need to configure the **OAuth consent screen** under APIs & Services → OAuth consent screen. Set the app to "External" for testing, add your email as a test user, and add the scopes `email`, `profile`, and `openid`.

### Step 2: Add environment variables

Add the following to your `.env` file:

```env
# Google OAuth 2.0
GOOGLE_CLIENT_ID="your-client-id.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET="your-client-secret"
GOOGLE_REDIRECT_URI="http://localhost:3001/auth/google/callback"
```

These are **required** for Google login to work. Without them, the backend will throw an error when the Google button is clicked.

### Step 3: Run the app and test

1. Start the backend:
   ```bash
   npm run start:dev
   ```
2. Open `http://localhost:3001` in your browser (the backend serves `public/index.html`).
3. Click **"Sign in with Google (OAuth 2.0 Auth Code)"**.
4. Sign in with your Google account on the consent screen.
5. You will be redirected back to the dashboard showing your **name** and **masked email**.

### OAuth endpoints

| Method | Endpoint                | Description                                  |
| ------ | ----------------------- | -------------------------------------------- |
| GET    | `/auth/google`          | Redirects user to Google's consent screen    |
| GET    | `/auth/google/callback` | Handles the callback, exchanges code, issues JWT |
| GET    | `/auth/me`              | Returns the current user's profile (protected) |

### Architecture (SOLID)

The OAuth implementation follows strict SOLID principles:

- **`IOAuthProvider` interface** (`interfaces/oauth-provider.interface.ts`)
  Defines the contract: `getAuthorizationUrl()`, `exchangeCodeForTokens()`, `getUserProfile()`.
  Any new provider (GitHub, Facebook) can implement this same interface.

- **`GoogleOAuthProvider`** (`providers/google-oauth.provider.ts`)
  Implements `IOAuthProvider` specifically for Google. Handles Google URLs, token exchange via `axios`, and profile fetching. *Single Responsibility — only knows about Google's API.*

- **`AuthService`**
  Orchestrates the OAuth login flow: calls the provider, creates/finds the user, generates JWT tokens. *Does not know how Google's API works — delegates to the provider.*

- **`AuthController`**
  HTTP layer only — redirects and extracts query params. *Zero business logic.*

- **`UserService`**
  Handles `createOAuthUser()` — creates a new user without a password, or links an existing email-based user to a Google account. *Single Responsibility — only knows about user data.*

### Database changes for OAuth

The `User` model was updated to support OAuth users:

```prisma
model User {
  id            String         @id @default(uuid())
  email         String         @unique
  name          String?        // Display name from Google profile
  password      String?        // Optional — null for OAuth-only users
  authProvider  AuthProvider   @default(LOCAL)
  providerId    String?        @unique  // Google's unique user ID
  // ... other fields
}

enum AuthProvider {
  LOCAL
  GOOGLE
}
```

- `password` is now optional (`String?`) — Google users don't have a local password.
- `authProvider` tracks how the user signed up (`LOCAL` or `GOOGLE`).
- `providerId` stores Google's unique user ID to prevent duplicate accounts.

## Notes

- The generated `dist/` folder is ignored in Git.
- Use `npm run start:dev` for local testing and Swagger access.
