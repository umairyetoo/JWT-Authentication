# JWT Authentication

A NestJS authentication service using JWT, Prisma, and Redis.

## Features

- User registration and login
- Access token + refresh token issuance
- Refresh token rotation
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

## Notes

- The generated `dist/` folder is ignored in Git.
- Use `npm run start:dev` for local testing and Swagger access.
