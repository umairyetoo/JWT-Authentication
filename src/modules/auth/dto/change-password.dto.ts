// src/modules/auth/dto/change-password.dto.ts
import { IsString, MinLength, MaxLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

/**
 * ChangePasswordDto — Validates input for password change.
 */
export class ChangePasswordDto {
  @IsString()
  @ApiProperty({ example: 'oldP@ssw0rd', description: 'Current password' })
  currentPassword: string;

  @IsString()
  @MinLength(8, { message: 'New password must be at least 8 characters' })
  @MaxLength(64, { message: 'New password must not exceed 64 characters' })
  @ApiProperty({ example: 'NewP@ssw0rd1', description: 'New password' })
  newPassword: string;
}