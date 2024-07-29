import {
  Injectable,
  UnauthorizedException,
  NotFoundException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UsersService } from '../users/users.service';
import * as bcrypt from 'bcrypt';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { CreateUserDto } from '../users/dto/create-user.dto';

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
  ) {}

  async register(registerDto: RegisterDto) {
    const hashedPassword = await bcrypt.hash(registerDto.password, 10);

    const createUserDto: CreateUserDto = {
      email: registerDto.email,
      password: hashedPassword,
      name: registerDto.name,
    };

    const user = await this.usersService.create(createUserDto);

    return this.generateToken(user);
  }

  async login(loginDto: LoginDto) {
    const user = await this.usersService.findByEmail(loginDto.email);
    if (user && (await bcrypt.compare(loginDto.password, user.password))) {
      const userRecord = await this.usersService.getUserRecordByEmail(
        loginDto.email,
      );
      if (!userRecord.emailVerified) {
        throw new UnauthorizedException('Email not verified');
      }
      return this.generateToken(user);
    }
    throw new UnauthorizedException('Invalid credentials');
  }

  async resetPassword(resetPasswordDto: ResetPasswordDto) {
    const user = await this.usersService.findByEmail(resetPasswordDto.email);
    if (!user) {
      throw new NotFoundException('User not found');
    }

    const hashedPassword = await bcrypt.hash(resetPasswordDto.password, 10);
    await this.usersService.updatePassword(user.id, hashedPassword);

    return { message: 'Password updated successfully' };
  }

  private generateToken(user: any) {
    const payload = { sub: user.id, email: user.email };
    return {
      accessToken: this.jwtService.sign(payload),
    };
  }
}
