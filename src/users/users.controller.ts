import { Controller, Get, UseGuards } from '@nestjs/common';
import { UsersService } from './users.service';
import { AuthGuard } from '../auth/guards/auth.guard';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @UseGuards(AuthGuard) // Використання створеного AuthGuard
  @Get('find-all')
  async findAll() {
    return await this.usersService.findAll();
  }
}