import { Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import axios from 'axios';
import { IOAuthProvider, IOAuthProfile } from '../interfaces/oauth-provider.interface';

@Injectable()
export class GoogleOAuthProvider implements IOAuthProvider {
  private readonly logger = new Logger(GoogleOAuthProvider.name);

  constructor(private readonly configService: ConfigService) {}

  getAuthorizationUrl(): string {
    const clientId = this.configService.get<string>('GOOGLE_CLIENT_ID');
    const redirectUri = this.configService.get<string>('GOOGLE_REDIRECT_URI') || 'http://localhost:3001/auth/google/callback';
    
    if (!clientId) {
      this.logger.error('GOOGLE_CLIENT_ID is not configured');
      throw new Error('Google OAuth is not configured properly');
    }

    const scope = 'openid email profile';
    const responseType = 'code';
    const accessType = 'offline';
    const prompt = 'consent';

    return `https://accounts.google.com/o/oauth2/v2/auth?client_id=${clientId}&redirect_uri=${redirectUri}&response_type=${responseType}&scope=${scope}&access_type=${accessType}&prompt=${prompt}`;
  }

  async exchangeCodeForTokens(code: string): Promise<string> {
    const clientId = this.configService.get<string>('GOOGLE_CLIENT_ID');
    const clientSecret = this.configService.get<string>('GOOGLE_CLIENT_SECRET');
    const redirectUri = this.configService.get<string>('GOOGLE_REDIRECT_URI') || 'http://localhost:3001/auth/google/callback';

    try {
      const response = await axios.post('https://oauth2.googleapis.com/token', {
        client_id: clientId,
        client_secret: clientSecret,
        code,
        grant_type: 'authorization_code',
        redirect_uri: redirectUri,
      });

      // We only need the access_token to fetch the profile
      return response.data.access_token;
    } catch (error: any) {
      this.logger.error(`Failed to exchange code for token: ${error.message}`);
      throw new UnauthorizedException('Failed to authenticate with Google');
    }
  }

  async getUserProfile(accessToken: string): Promise<IOAuthProfile> {
    try {
      const response = await axios.get('https://www.googleapis.com/oauth2/v2/userinfo', {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      });

      return {
        providerId: response.data.id,
        email: response.data.email,
        name: response.data.name,
        provider: 'GOOGLE',
      };
    } catch (error: any) {
      this.logger.error(`Failed to fetch user profile: ${error.message}`);
      throw new UnauthorizedException('Failed to fetch user profile from Google');
    }
  }
}
