import { Module } from '@nestjs/common';
import { MainService } from './main.service';
import { MainController } from './main.controller';
import { AuthModule } from '../auth/auth.module';

@Module({
  imports: [AuthModule],
  providers: [MainService],
  controllers: [MainController],
})
export class MainModule {}
