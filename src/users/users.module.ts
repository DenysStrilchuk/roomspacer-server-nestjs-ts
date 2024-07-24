import { Module } from '@nestjs/common';
import { UsersService } from './users.service';
import { UsersController } from './users.controller';
import { FirebaseService } from '../ config/firebase.config';

@Module({
  providers: [UsersService, FirebaseService],
  controllers: [UsersController],
  exports: [UsersService],
})
export class UsersModule {}
