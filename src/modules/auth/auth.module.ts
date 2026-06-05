// src/modules/auth/auth.module.ts
import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { UserModule } from '../user/user.module';
import { TokenModule } from '../token/token.module';
import { JwtAuthGuard } from '../../common/guards/jwt.guard';
import { GoogleOAuthProvider } from './providers/google-oauth.provider';

/**
 * AuthModule — Wires together all auth-related providers.
 *
 * Imports UserModule and TokenModule — their services are injected
 * into AuthService via NestJS DI container.
 *
 * Exports JwtAuthGuard — other modules (OrderService, VenueService)
 * can import AuthModule and use the guard without re-wiring.
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
  ],
  exports: [
    JwtAuthGuard, // export so other microservices can import and use
    TokenModule,  // export JwtModule inside TokenModule for guard injection
  ],
})
export class AuthModule {}