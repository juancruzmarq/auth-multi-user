import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Profile, Strategy, VerifyCallback } from 'passport-google-oauth20';

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  constructor() {
    super({
      clientID: process.env.GOOGLE_CLIENT_ID!,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
      callbackURL: process.env.GOOGLE_CALLBACK_URL!,
      scope: ['email', 'profile'],
      passReqToCallback: true,
    });
  }

  validate(
    req: any,
    accessToken: string,
    refreshToken: string,
    profile: Profile,
    done: VerifyCallback,
  ) {
    // Lo que pase al done() queda en req.user en el callback
    const primaryEmail = profile.emails?.[0];
    const payload = {
      provider: 'GOOGLE' as const,
      id_provider: profile.id,
      email: primaryEmail?.value ?? null,
      email_verified: primaryEmail?.verified ?? false,
      name: profile.displayName ?? '',
      photo_url: profile.photos?.[0]?.value ?? null,
      oauth: { accessToken, refreshToken },
    };
    return done(null, payload);
  }
}
