import {
  Injectable,
  UnauthorizedException,
  BadRequestException,
  InternalServerErrorException,
  Logger,
} from '@nestjs/common';
import * as admin from 'firebase-admin';
import * as bcrypt from 'bcrypt';
import { UserRecord } from 'firebase-admin/lib/auth';
import { CreateUserDto } from '../users/dto/create-user.dto';
import { LoginUserDto } from '../users/dto/login-user.dto';
import { ResetPasswordDto } from '../users/dto/reset-password.dto';
import { MailService } from '../mail/mail.service';
import * as crypto from 'crypto';
import { ForgotPasswordDto } from '../users/dto/forgot-password.dto';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(private readonly mailService: MailService) {}

  async register(createUserDto: CreateUserDto): Promise<UserRecord> {
    const { name, email, password } = createUserDto;
    const hashedPassword = await bcrypt.hash(password, 10);

    try {
      const userRecord = await admin.auth().createUser({
        displayName: name,
        email,
        password,
      });

      const confirmationToken = crypto.randomBytes(32).toString('hex');

      await admin.firestore().collection('users').doc(userRecord.uid).set({
        name,
        email,
        password: hashedPassword,
        emailConfirmed: false,
        confirmationToken,
      });

      const verificationLink = `http://localhost:3000/auth/confirm/${confirmationToken}`;

      await this.mailService.sendConfirmationEmail(
        email,
        name,
        verificationLink,
      );

      return userRecord;
    } catch (error) {
      this.logger.error('Error registering user', error.stack);
      if (error.code === 'auth/email-already-exists') {
        throw new BadRequestException(
          'The email address is already in use by another account.',
        );
      }
      throw new InternalServerErrorException('Internal server error');
    }
  }

  async confirmEmail(token: string): Promise<void> {
    const usersRef = admin.firestore().collection('users');
    const snapshot = await usersRef
      .where('confirmationToken', '==', token)
      .get();

    if (snapshot.empty) {
      throw new UnauthorizedException('Invalid or expired token');
    }

    const userDoc = snapshot.docs[0];

    try {
      await userDoc.ref.update({
        emailConfirmed: true,
        confirmationToken: admin.firestore.FieldValue.delete(),
      });
    } catch (error) {
      this.logger.error('Error confirming email', error.stack);
      throw new UnauthorizedException('Error confirming email');
    }
  }

  async login(loginUserDto: LoginUserDto): Promise<string> {
    const { email, password } = loginUserDto;

    try {
      const user = await admin.auth().getUserByEmail(email);

      const userDoc = await admin
        .firestore()
        .collection('users')
        .doc(user.uid)
        .get();
      const userData = userDoc.data();

      if (!userData || !userData.password) {
        throw new UnauthorizedException('User not found or missing password');
      }

      if (!userData.emailConfirmed) {
        throw new UnauthorizedException('Email not confirmed');
      }

      const isPasswordValid = await bcrypt.compare(password, userData.password);
      if (!isPasswordValid) {
        throw new UnauthorizedException('Invalid password');
      }

      return await admin.auth().createCustomToken(user.uid);
    } catch (error) {
      this.logger.error('Error during login', error.stack);
      throw new UnauthorizedException('Invalid login credentials');
    }
  }

  async forgotPassword(forgotPasswordDto: ForgotPasswordDto): Promise<void> {
    const { email } = forgotPasswordDto;

    try {
      const user = await admin.auth().getUserByEmail(email);

      const resetToken = crypto.randomBytes(32).toString('hex');

      await admin
        .firestore()
        .collection('users')
        .doc(user.uid)
        .update({
          resetPasswordToken: resetToken,
          resetPasswordExpires: admin.firestore.Timestamp.fromDate(
            new Date(Date.now() + 3600000), // 1 hour
          ),
        });

      const resetLink = `http://localhost:3000/auth/reset-password/${resetToken}`;

      await this.mailService.sendResetPasswordEmail(email, resetLink);
    } catch (error) {
      this.logger.error('Error during forgot password process', error.stack);
      throw new InternalServerErrorException('Something went wrong');
    }
  }

  async resetPassword(resetPasswordDto: ResetPasswordDto): Promise<void> {
    const { token, newPassword } = resetPasswordDto;

    const usersRef = admin.firestore().collection('users');
    const snapshot = await usersRef
      .where('resetPasswordToken', '==', token)
      .where('resetPasswordExpires', '>', admin.firestore.Timestamp.now())
      .get();

    if (snapshot.empty) {
      throw new UnauthorizedException('Invalid or expired token');
    }

    const userDoc = snapshot.docs[0];
    const uid = userDoc.id;

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await admin.auth().updateUser(uid, { password: newPassword });

    await userDoc.ref.update({
      password: hashedPassword,
      resetPasswordToken: admin.firestore.FieldValue.delete(),
      resetPasswordExpires: admin.firestore.FieldValue.delete(),
    });
  }
}
