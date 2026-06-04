import { Request } from 'express';
import { ITokenPayload } from '../../modules/token/interfaces/token-payload.interface';

export interface IRequestWithUser extends Request {
  user: ITokenPayload;
}
