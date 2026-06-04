// src/modules/user/interfaces/user.interface.ts

/**
 * IUser — Core user shape used across the auth domain.
 *
 * SOLID — I (Interface Segregation):
 * Only contains fields relevant to auth operations.
 * Does not expose password outside of UserService.
 */
export interface IUser {
  id: string;
  email: string;
  role: string;
  isActive: boolean;
}

/**
 * IUserWithPassword — Extended shape used only inside UserService
 * for password verification. Never returned to callers.
 */
export interface IUserWithPassword extends IUser {
  password: string;
}