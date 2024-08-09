import { Module } from '@nestjs/common';
import { PassportModule } from '@nestjs/passport';
import { GoogleStrategy } from './google.strategy';

@Module({
  imports: [PassportModule],
  providers: [GoogleStrategy],
})
export class GoogleAuthModule {}
