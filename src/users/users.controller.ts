import { Body, Controller, Get, Post, UseGuards } from '@nestjs/common';
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

  @Get('users-status')
  async getUsersStatus(): Promise<
    Array<{
      uid: string;
      email: string;
      online: boolean;
      lastOnline: Date | null;
    }>
  > {
    return this.usersService.getUsersStatus();
  }

  @UseGuards(AuthGuard)
  @Post('invite')
  async inviteUserByEmail(@Body('email') email: string): Promise<void> {
    return this.usersService.inviteUserByEmail(email);
  }
}
