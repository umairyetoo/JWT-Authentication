// src/common/decorators/current-user.decorator.ts
import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { ITokenPayload } from '../../modules/token/interfaces/token-payload.interface';
import { IRequestWithUser } from '../interfaces/request-with-user.interface';

/**
 * @CurrentUser() — Parameter decorator to extract authenticated user from request.
 *
 * Usage in controller:
 *   async logout(@CurrentUser() user: ITokenPayload) { ... }
 *
 * Replaces boilerplate:
 *   @Req() req: IRequestWithUser → req.user
 *
 * Only works on routes protected by JwtAuthGuard —
 * guard populates req.user before controller runs.
 */
export const CurrentUser = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext): ITokenPayload => {
    const request = ctx.switchToHttp().getRequest<IRequestWithUser>();
    return request.user;
  },
);