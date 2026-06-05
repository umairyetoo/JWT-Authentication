export interface IOAuthProfile {
  providerId: string;
  email: string;
  name: string;
  provider: 'GOOGLE';
}

export interface IOAuthProvider {
  getAuthorizationUrl(): string;
  exchangeCodeForTokens(code: string): Promise<string>; // Returns the access token from the provider
  getUserProfile(accessToken: string): Promise<IOAuthProfile>;
}
