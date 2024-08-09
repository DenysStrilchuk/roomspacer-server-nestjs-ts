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
        throw new BadRequestException('This email address is already in use.');
      } else if (error.code === 'auth/invalid-email') {
        throw new BadRequestException('Email address format is incorrect.');
      } else if (error.code === 'auth/weak-password') {
        throw new BadRequestException('The password is too weak.');
      } else {
        throw new InternalServerErrorException('Internal server error');
      }
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
        // Тільки логувати помилку у випадку невірного паролю
        throw new UnauthorizedException('Invalid password');
      }

      return await admin.auth().createCustomToken(user.uid);
    } catch (error) {
      // Логувати тільки одну помилку
      this.logger.error(`Login failed for email: ${email}`, error.stack);

      // Повертати лише одне повідомлення про помилку
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

  async googleLogin(user: any): Promise<string> {
    const { email, firstName, lastName } = user;

    try {
      // Перевіряємо, чи існує користувач з таким email
      let userRecord;
      try {
        userRecord = await admin.auth().getUserByEmail(email);
      } catch (error) {
        if (error.code === 'auth/user-not-found') {
          // Якщо користувача не існує, створюємо його
          userRecord = await admin.auth().createUser({
            email,
            displayName: `${firstName} ${lastName}`,
          });

          await admin.firestore().collection('users').doc(userRecord.uid).set({
            email,
            name: `${firstName} ${lastName}`,
            emailConfirmed: true, // Google користувачі автоматично підтверджуються
          });
        } else {
          throw error;
        }
      }

      // Генеруємо JWT токен для користувача
      return await admin.auth().createCustomToken(userRecord.uid);
    } catch (error) {
      this.logger.error('Error during Google login', error.stack);
      throw new InternalServerErrorException('Something went wrong during Google login');
    }
  }

}
