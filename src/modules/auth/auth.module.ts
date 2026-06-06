// src/modules/auth/auth.module.ts
import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { UserModule } from '../user/user.module';
import { TokenModule } from '../token/token.module';
import { JwtAuthGuard } from '../../common/guards/jwt.guard';
import { GoogleOAuthProvider } from './providers/google-oauth.provider';
import { PkceService } from './services/pkce.service';

/**
 * AuthModule — Wires together all auth-related providers.
 *
 * Imports UserModule and TokenModule — their services are injected
 * into AuthService via NestJS DI container.
 *
 * Exports JwtAuthGuard — other modules (OrderService, VenueService)
 * can import AuthModule and use the guard without re-wiring.
 *
 * PKCE integration:
 * PkceService is registered here as a provider. It depends on RedisService
 * (from RedisModule, which is global) for code_verifier storage.
 * PkceService is NOT exported — it's an internal implementation detail
 * of the auth flow. Other modules should not need PKCE directly.
 *
 * SOLID — D (Dependency Inversion):
 * NestJS DI container resolves all dependencies. AuthService depends on
 * PkceService interface, and the container injects the concrete class.
 * Swapping PkceService for a mock in tests only requires overriding the provider.
 */
@Module({
  imports: [
    UserModule,  // provides UserService
    TokenModule, // provides TokenService + JwtModule
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    JwtAuthGuard, // registered here — use @UseGuards(JwtAuthGuard) in controllers
    GoogleOAuthProvider,
    PkceService,  // PKCE challenge generation + code_verifier storage
  ],
  exports: [
    JwtAuthGuard, // export so other microservices can import and use
    TokenModule,  // export JwtModule inside TokenModule for guard injection
  ],
})
export class AuthModule {}