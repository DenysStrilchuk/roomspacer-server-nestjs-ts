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
import { CreateUserDto } from '../users/dto/create-user.dto';
import { FirebaseService } from '../ config/firebase.config';

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
    private readonly firebaseService: FirebaseService,
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

  async forgotPassword(email: string): Promise<void> {
    const user = await this.usersService.findByEmail(email);
    if (!user) {
      throw new NotFoundException('User not found');
    }
    await this.firebaseService.sendPasswordResetEmail(email);
  }

  async resetPassword(token: string, newPassword: string): Promise<void> {
    const decodedToken = await this.jwtService.verify(token, {
      algorithms: ['HS256'],
    });
    const user = await this.usersService.findById(decodedToken.sub);

    if (!user) {
      throw new NotFoundException('User not found');
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await this.usersService.updatePassword(user.id, hashedPassword);
  }

  private generateToken(user: any) {
    const payload = { sub: user.id, email: user.email };
    return {
      accessToken: this.jwtService.sign(payload),
    };
  }
}
