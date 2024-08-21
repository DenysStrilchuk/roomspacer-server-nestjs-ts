import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtStrategy } from './strategies/jwt.strategy';
import { FirebaseService } from '../firebase/firebase.service';
import * as process from 'process';
import { UsersService } from '../users/users.service';
import { MailModule } from '../mail/mail.module';
import { AuthGuard } from './guards/auth.guard';

@Module({
  imports: [
    PassportModule,
    JwtModule.register({
      secret: process.env.JWT_SECRET,
      signOptions: { expiresIn: '60m' },
    }),
    MailModule,
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    AuthGuard,
    JwtStrategy,
    FirebaseService,
    UsersService,
  ],
  exports: [AuthService],
})
export class AuthModule {}
