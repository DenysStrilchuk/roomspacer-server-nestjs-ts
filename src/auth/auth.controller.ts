import {
  Controller,
  Get,
  Post,
  Body,
  UnauthorizedException,
  BadRequestException,
  InternalServerErrorException,
  Param,
  Logger,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto } from '../users/dto/create-user.dto';
import { LoginUserDto } from '../users/dto/login-user.dto';
import { ResetPasswordDto } from '../users/dto/reset-password.dto';
import { ForgotPasswordDto } from '../users/dto/forgot-password.dto';

@Controller('auth')
export class AuthController {
  private readonly logger = new Logger(AuthController.name);

  constructor(private readonly authService: AuthService) {}

  @Get('confirm/:token')
  async confirmEmail(@Param('token') token: string): Promise<void> {
    try {
      await this.authService.confirmEmail(token);
    } catch (error) {
      this.logger.error('Error confirming email', error.stack);
      throw new UnauthorizedException('Invalid or expired token');
    }
  }

  @Post('register')
  async register(@Body() createUserDto: CreateUserDto) {
    try {
      return await this.authService.register(createUserDto);
    } catch (error) {
      this.logger.error('Error registering user', error.stack);
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
      if (error instanceof UnauthorizedException) {
        this.logger.warn('Invalid login attempt');
      } else {
        this.logger.error('Error during login', error.stack);
      }
      throw new UnauthorizedException('Invalid login credentials');
    }
  }

  @Post('forgot-password')
  async forgotPassword(@Body() forgotPasswordDto: ForgotPasswordDto) {
    try {
      await this.authService.forgotPassword(forgotPasswordDto);
      return { message: 'Reset password email sent successfully' };
    } catch (error) {
      this.logger.error('Error during forgot password process', error.stack);
      throw new InternalServerErrorException('Something went wrong');
    }
  }

  @Post('reset-password')
  async resetPassword(@Body() resetPasswordDto: ResetPasswordDto) {
    try {
      await this.authService.resetPassword(resetPasswordDto);
      return { message: 'Password reset successfully' };
    } catch (error) {
      this.logger.error('Error resetting password', error.stack);
      throw new InternalServerErrorException('Something went wrong');
    }
  }
}
