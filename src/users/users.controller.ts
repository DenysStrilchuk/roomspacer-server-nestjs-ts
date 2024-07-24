import {
  Controller,
  Get,
  Post,
  Body,
  Param,
  Patch,
  UseGuards,
} from '@nestjs/common';
import { UsersService } from './users.service';
import { CreateUserDto } from './dto/create-user.dto';
import { User } from './interfaces/user.interface';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Post()
  async create(@Body() createUserDto: CreateUserDto): Promise<User> {
    return await this.usersService.create(createUserDto);
  }

  @Get(':email')
  async findByEmail(@Param('email') email: string): Promise<User> {
    return await this.usersService.findByEmail(email);
  }

  @Patch(':id/password')
  @UseGuards(JwtAuthGuard)
  async updatePassword(
    @Param('id') id: string,
    @Body('password') password: string,
  ): Promise<void> {
    return await this.usersService.updatePassword(id, password);
  }
}
