import { Module } from '@nestjs/common';
import { UsersService } from './users.service';
import { UsersController } from './users.controller';
import { FirebaseService } from '../firebase/firebase.service';
import { AuthModule } from '../auth/auth.module';
import { MailModule } from '../mail/mail.module'; // Імпорт AuthModule для доступу до AuthService

@Module({
  imports: [AuthModule, MailModule],
  providers: [UsersService, FirebaseService],
  controllers: [UsersController],
  exports: [UsersService],
})
export class UsersModule {}
