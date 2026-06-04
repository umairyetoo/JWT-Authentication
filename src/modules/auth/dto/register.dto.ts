// src/modules/auth/dto/register.dto.ts
import { IsEmail, IsString, MinLength, MaxLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

/**
 * RegisterDto — Validates input for user registration.
 * class-validator decorators enforce rules before reaching AuthService.
 */
export class RegisterDto {
  @IsEmail({}, { message: 'Please provide a valid email address' })
  @ApiProperty({ example: 'user@example.com', description: 'User email' })
  email: string;

  @IsString()
  @MinLength(8, { message: 'Password must be at least 8 characters' })
  @MaxLength(64, { message: 'Password must not exceed 64 characters' })
  @ApiProperty({ example: 'P@ssw0rd!', description: 'User password' })
  password: string;
}