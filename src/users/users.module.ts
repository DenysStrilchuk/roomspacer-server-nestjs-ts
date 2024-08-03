import { Module } from '@nestjs/common';
import { UsersService } from './users.service';
import { FirebaseService } from '../firebase/firebase.service';

@Module({
  providers: [UsersService, FirebaseService],
  exports: [UsersService],
})
export class UsersModule {}
