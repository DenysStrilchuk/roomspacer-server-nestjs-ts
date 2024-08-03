import { Controller, Get, Post, Body, UnauthorizedException, Query, Logger } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto } from '../users/dto/create-user.dto';
import { LoginUserDto } from '../users/dto/login-user.dto';
import { UpdatePasswordDto } from '../users/dto/update-password.dto';

@Controller('auth')
export class AuthController {
  private readonly logger = new Logger(AuthController.name);

  constructor(private readonly authService: AuthService) {}

  @Get('confirm')
  async confirmEmail(@Query('token') token: string) {
    this.logger.log(`Received token: ${token}`);
    await this.authService.confirmEmail(token);
    return { message: 'Email confirmed successfully' };
  }

  @Post('register')
  async register(@Body() createUserDto: CreateUserDto) {
    return this.authService.register(createUserDto);
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
