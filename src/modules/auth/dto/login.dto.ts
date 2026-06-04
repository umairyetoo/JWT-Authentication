// src/modules/auth/dto/login.dto.ts
import { IsEmail, IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

/**
 * LoginDto — Validates input for user login.
 */
export class LoginDto {
  @IsEmail({}, { message: 'Please provide a valid email address' })
  @ApiProperty({ example: 'user@example.com', description: 'User email' })
  email: string;

  @IsString()
  @ApiProperty({ example: 'P@ssw0rd!', description: 'User password' })
  password: string;
}