import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
import { FirebaseModule } from './firebase/firebase.module';
import { MailModule } from './mail/mail.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true, // робить ConfigModule доступним глобально
    }),
    AuthModule,
    UsersModule,
    FirebaseModule,
    MailModule,
  ],
})
export class AppModule {}
