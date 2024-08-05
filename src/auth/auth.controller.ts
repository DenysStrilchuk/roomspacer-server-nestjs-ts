import {
  Controller,
  Get,
  Post,
  Body,
  UnauthorizedException,
  Logger,
  BadRequestException,
  InternalServerErrorException, Param,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto } from '../users/dto/create-user.dto';
import { LoginUserDto } from '../users/dto/login-user.dto';
import { UpdatePasswordDto } from '../users/dto/update-password.dto';

@Controller('auth')
export class AuthController {
  private readonly logger = new Logger(AuthController.name);

  constructor(private readonly authService: AuthService) {}

  @Get('confirm/:token')
  async confirmEmail(@Param('token') token: string): Promise<void> {
    try {
      await this.authService.confirmEmail(token);
    } catch (error) {
      throw new UnauthorizedException('Invalid or expired token');
    }
  }

  @Post('register')
  async register(@Body() createUserDto: CreateUserDto) {
    try {
      return await this.authService.register(createUserDto);
    } catch (error) {
      if (error instanceof BadRequestException) {
        throw new BadRequestException(error.message);
      }
      throw new InternalServerErrorException('Something went wrong');
    }
  }

  @Post('login')
  async login(@Body() loginUserDto: LoginUserDto) {
    try {
      const token = await this.authService.login(loginUserDto);
      return { token };
    } catch (error) {
      throw new UnauthorizedException(error.message);
    }
  }

  @Post('update-password')
  async updatePassword(@Body() updatePasswordDto: UpdatePasswordDto) {
    await this.authService.updatePassword(updatePasswordDto);
    return { message: 'Password updated successfully' };
  }
}
