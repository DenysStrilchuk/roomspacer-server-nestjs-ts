import { Controller, Post, Body, UnauthorizedException } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto } from '../users/dto/create-user.dto';
import { LoginUserDto } from '../users/dto/login-user.dto';
import { UpdatePasswordDto } from '../users/dto/update-password.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

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
