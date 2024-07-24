declare module 'passport-google-oauth20' {
  import { Strategy as PassportStrategy } from 'passport';
  import { Request } from 'express';

  export interface Profile {
    provider: string;
    id: string;
    displayName: string;
    name: {
      familyName: string;
      givenName: string;
    };
    emails: Array<{
      value: string;
    }>;
    photos: Array<{
      value: string;
    }>;
  }

  export interface VerifyCallback {
    (error: any, user?: any, info?: any): void;
  }

  export interface StrategyOptions {
    clientID: string;
    clientSecret: string;
    callbackURL: string;
    passReqToCallback?: boolean;
    scope?: string[];
  }

  export interface StrategyOptionsWithRequest extends StrategyOptions {
    passReqToCallback: true;
  }

  export class Strategy extends PassportStrategy {
    constructor(
      options: StrategyOptions,
      verify: (accessToken: string, refreshToken: string, profile: Profile, done: VerifyCallback) => void,
    );
    constructor(
      options: StrategyOptionsWithRequest,
      verify: (req: Request, accessToken: string, refreshToken: string, profile: Profile, done: VerifyCallback) => void,
    );

    name: string;
  }
}
