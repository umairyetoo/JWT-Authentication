// src/common/interfaces/request-with-user.interface.ts
import { Request } from 'express';
import { ITokenPayload } from './token-payload.interface';

/**
 * IRequestWithUser — Extends Express Request to include authenticated user.
 * Used in controllers to access req.user with full type safety.
 */
export interface IRequestWithUser extends Request {
  user: ITokenPayload;
}