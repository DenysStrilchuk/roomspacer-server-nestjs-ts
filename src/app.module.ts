import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
import { FirebaseModule } from './firebase/firebase.module';
import { MailModule } from './mail/mail.module';
import { MainModule } from './main/main.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    AuthModule,
    MainModule,
    UsersModule,
    FirebaseModule,
    MailModule,
  ],
})
export class AppModule {}
