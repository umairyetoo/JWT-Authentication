// src/modules/token/token.module.ts
import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { TokenService } from './token.service';
import { buildJwtConfig } from '../../config/jwt.config';

@Module({
  imports: [
    /**
     * JwtModule registered with RS256 keys.
     * registerAsync used to read keys after ConfigModule initializes.
     * Default options set here — overridden per-sign in TokenService
     * when different expiry or claims are needed.
     */
    JwtModule.registerAsync({
      useFactory: () => {
        const config = buildJwtConfig();
        return {
          // Default verify options — used by jwtService.verifyAsync
          // when no override passed
          verifyOptions: {
            algorithms: ['RS256'],
            issuer: config.issuer,
            audience: config.audience,
          },
          publicKey: config.publicKey,
          privateKey: config.privateKey,
        };
      },
    }),
  ],
  providers: [TokenService],
  exports: [TokenService, JwtModule], // export JwtModule so guards can inject JwtService
})
export class TokenModule {}