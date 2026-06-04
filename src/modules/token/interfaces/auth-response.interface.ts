// src/modules/auth/interfaces/auth-response.interface.ts
import { IUser } from '../../user/interfaces/user.interface';
import { ITokenPair } from '../../token/interfaces/token-pair.interface';

/**
 * IAuthResponse — Shape returned to the client after login or register.
 *
 * SOLID — I (Interface Segregation):
 * Combines user info and tokens into one clean response shape.
 * Neither UserService nor TokenService returns this — AuthService composes it.
 */
export interface IAuthResponse extends ITokenPair {
  user: IUser;
}