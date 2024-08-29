import {
  Controller,
  Get,
  Post,
  Body,
  UnauthorizedException,
  BadRequestException,
  InternalServerErrorException,
  Param,
  Headers,
  Query,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { FirebaseService } from '../firebase/firebase.service';
import { CreateUserDto } from './dto/create-user.dto';
import { LoginUserDto } from './dto/login-user.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { ILoginResponse } from './interfaces/login-response.interface';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly firebaseService: FirebaseService,
  ) {}

  @Get('confirm/:token')
  async confirmEmail(@Param('token') token: string): Promise<void> {
    try {
      await this.authService.confirmEmail(token);
    } catch (error) {
      throw new UnauthorizedException('Invalid or expired token');
    }
  }

  @Get('check-user-exists')
  async checkUserExists(
    @Query('email') email: string,
  ): Promise<{ exists: boolean }> {
    if (!email) {
      throw new BadRequestException('Email is required');
    }

    try {
      const user = await this.firebaseService.getAuth().getUserByEmail(email);
      const userDoc = await this.firebaseService
        .getFirestore()
        .collection('users')
        .doc(user.uid)
        .get();

      return { exists: userDoc.exists };
    } catch (error) {
      if (error.code === 'auth/user-not-found') {
        return { exists: false };
      }
      throw new BadRequestException('Error checking user existence');
    }
  }

  @Post('check-token')
  async checkToken(@Headers('Authorization') token: string) {
    console.log('Received token for verification:', token);

    try {
      const decodedToken = await this.authService.verifyToken(token);
      console.log('Token verified successfully:', decodedToken);
      return { isLogin: true, user: decodedToken };
    } catch (error) {
      console.error('Token verification failed:', error.message);
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
  async login(@Body() loginUserDto: LoginUserDto): Promise<ILoginResponse> {
    try {
      return await this.authService.login(loginUserDto);
    } catch (error) {
      throw new UnauthorizedException('Invalid login credentials');
    }
  }

  @Post('logout')
  async logout(@Body('uid') uid: string): Promise<void> {
    console.log(`Logout request received for uid: ${uid}`);
    try {
      await this.authService.logout(uid);
      console.log(`Successfully logged out user with uid: ${uid}`);
    } catch (error) {
      console.error(`Failed to logout user with uid: ${uid}:`, error.message);
      throw new InternalServerErrorException('Failed to logout');
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
