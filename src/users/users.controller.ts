import {
  Controller,
  Get,
  Post,
  Body,
  Param,
  Patch,
  UseGuards,
  InternalServerErrorException,
  Logger,
} from '@nestjs/common';
import { UsersService } from './users.service';
import { CreateUserDto } from './dto/create-user.dto';
import { User } from './interfaces/user.interface';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';

@Controller('users')
export class UsersController {
  private readonly logger = new Logger(UsersController.name);

  constructor(private readonly usersService: UsersService) {}

  @Post()
  async create(@Body() createUserDto: CreateUserDto): Promise<User> {
    try {
      return await this.usersService.create(createUserDto);
    } catch (error) {
      this.logger.error('Failed to create user', error.stack);
      throw new InternalServerErrorException('Failed to create user');
    }
  }

  @Get(':email')
  async findByEmail(@Param('email') email: string): Promise<User> {
    try {
      return await this.usersService.findByEmail(email);
    } catch (error) {
      this.logger.error('Failed to find user by email', error.stack);
      throw new InternalServerErrorException('Failed to find user by email');
    }
  }

  @Patch(':id/password')
  @UseGuards(JwtAuthGuard)
  async updatePassword(
    @Param('id') id: string,
    @Body('password') password: string,
  ): Promise<void> {
    try {
      return await this.usersService.updatePassword(id, password);
    } catch (error) {
      this.logger.error(
        `Failed to update password for user with id: ${id}`,
        error.stack,
      );
      throw new InternalServerErrorException('Failed to update password');
    }
  }

  @Patch(':id/email')
  @UseGuards(JwtAuthGuard)
  async changeEmail(
    @Param('id') id: string,
    @Body('email') email: string,
  ): Promise<void> {
    try {
      return await this.usersService.changeEmail(id, email);
    } catch (error) {
      this.logger.error(
        `Failed to change email for user with id: ${id}`,
        error.stack,
      );
      throw new InternalServerErrorException('Failed to change email');
    }
  }
}
