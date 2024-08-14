import {
  Controller,
  Get,
  Post,
  Body,
  UnauthorizedException,
  BadRequestException,
  InternalServerErrorException,
  Param,
} from '@nestjs/common';
import { AuthService, ILoginResponse } from './auth.service';
import { CreateUserDto } from '../users/dto/create-user.dto';
import { LoginUserDto } from '../users/dto/login-user.dto';
import { ResetPasswordDto } from '../users/dto/reset-password.dto';
import { ForgotPasswordDto } from '../users/dto/forgot-password.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Get('confirm/:token')
  async confirmEmail(@Param('token') token: string): Promise<void> {
    try {
      await this.authService.confirmEmail(token);
    } catch (error) {
      throw new UnauthorizedException('Invalid or expired token');
    }
  }

  @Post('register-with-google')
  async registerWithGoogle(
    @Body('idToken') idToken: string,
  ): Promise<ILoginResponse> {
    try {
      return await this.authService.registerWithGoogle(idToken);
    } catch (error) {
      throw new InternalServerErrorException('Failed to register with Google');
    }
  }

  @Post('login-with-google')
  async loginWithGoogle(
    @Body('idToken') idToken: string,
  ): Promise<ILoginResponse> {
    try {
      return await this.authService.loginWithGoogle(idToken);
    } catch (error) {
      throw new UnauthorizedException('Invalid login credentials');
    }
  }

  @Post('register')
  async register(@Body() createUserDto: CreateUserDto) {
    try {
      return await this.authService.register(createUserDto);
    } catch (error) {
      if (
        error instanceof BadRequestException ||
        error instanceof UnauthorizedException
      ) {
        throw error;
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
      throw new UnauthorizedException('Invalid login credentials');
    }
  }

  @Post('forgot-password')
  async forgotPassword(@Body() forgotPasswordDto: ForgotPasswordDto) {
    try {
      await this.authService.forgotPassword(forgotPasswordDto);
      return { message: 'Reset password email sent successfully' };
    } catch (error) {
      if (
        error instanceof BadRequestException ||
        error instanceof InternalServerErrorException
      ) {
        throw error;
      }
      throw new InternalServerErrorException('Unexpected error occurred.');
    }
  }

  @Post('reset-password')
  async resetPassword(@Body() resetPasswordDto: ResetPasswordDto) {
    try {
      await this.authService.resetPassword(resetPasswordDto);
      return { message: 'Password reset successfully' };
    } catch (error) {
      throw new InternalServerErrorException('Something went wrong');
    }
  }
}
