import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UsersService } from '../users/users.service';
import { hash, compare } from 'bcrypt';
import { auth } from '../firebase-admin';
import { SignInDto } from './dto/sign-in.dto';
import { SignUpDto } from './dto/sign-up.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
  ) {}

  async signIn(signInDto: SignInDto) {
    const { email, password } = signInDto;
    const user = await this.usersService.findByEmail(email);

    if (!user || !(await compare(password, user.password))) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const payload = { email: user.email, sub: user.id };
    return {
      access_token: this.jwtService.sign(payload),
    };
  }

  async signUp(signUpDto: SignUpDto) {
    const { name, email, password } = signUpDto;
    const hashedPassword = await hash(password, 10);
    const user = await this.usersService.create({
      name,
      email,
      password: hashedPassword,
    });

    const emailVerificationLink =
      await auth.generateEmailVerificationLink(email);
    // Send the verification email link to the user's email

    return {
      message: 'User created successfully, please verify your email',
    };
  }

  async forgotPassword(forgotPasswordDto: ForgotPasswordDto) {
    const { email } = forgotPasswordDto;
    const resetLink = await auth.generatePasswordResetLink(email);
    // Send the reset link to the user's email
    return {
      message: 'Password reset link sent to your email',
    };
  }

  async googleSignIn(token: string) {
    const decodedToken = await auth.verifyIdToken(token);
    const email = decodedToken.email;
    let user = await this.usersService.findByEmail(email);

    if (!user) {
      user = await this.usersService.create({
        name: decodedToken.name,
        email,
        password: '',
      });
    }

    const payload = { email: user.email, sub: user.id };
    return {
      access_token: this.jwtService.sign(payload),
    };
  }
}
