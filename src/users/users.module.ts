import { Module } from '@nestjs/common';
import { UsersService } from './users.service';
import { UsersController } from './users.controller';
import { FirebaseService } from '../firebase/firebase.service';
import { AuthModule } from '../auth/auth.module'; // Імпорт AuthModule для доступу до AuthService

@Module({
  imports: [AuthModule],
  providers: [UsersService, FirebaseService],
  controllers: [UsersController],
  exports: [UsersService],
})
export class UsersModule {}
