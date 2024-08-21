import { Controller, Get, UseGuards } from '@nestjs/common';
import { UsersService } from './users.service';
import { AuthGuard } from '../auth/guards/auth.guard';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @UseGuards(AuthGuard) // Використання створеного AuthGuard
  @Get('find-all')
  async findAll() {
    const users = await this.usersService.findAll();
    return { users }; // Повертаємо об'єкт з масивом users
  }
}
