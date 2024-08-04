import {
  Injectable,
  UnauthorizedException,
  Logger,
  BadRequestException,
} from '@nestjs/common';
import * as admin from 'firebase-admin';
import * as bcrypt from 'bcrypt';
import { UserRecord } from 'firebase-admin/lib/auth';
import { CreateUserDto } from '../users/dto/create-user.dto';
import { LoginUserDto } from '../users/dto/login-user.dto';
import { UpdatePasswordDto } from '../users/dto/update-password.dto';
import { MailService } from '../mail/mail.service';
import * as crypto from 'crypto';

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

      const verificationLink = `http://localhost:3001/auth/confirm?token=${confirmationToken}`;

      await this.mailService.sendConfirmationEmail(
        email,
        name,
        verificationLink,
      );

      return userRecord;
    } catch (error) {
      if (error.code === 'auth/email-already-exists') {
        throw new BadRequestException(
          'The email address is already in use by another account.',
        );
      }
      throw error;
    }
  }

  async confirmEmail(token: string): Promise<void> {
    this.logger.log(`Confirming email with token: ${token}`);
    const usersRef = admin.firestore().collection('users');
    const snapshot = await usersRef
      .where('confirmationToken', '==', token)
      .get();

    if (snapshot.empty) {
      this.logger.error('Invalid or expired token');
      throw new UnauthorizedException('Invalid or expired token');
    }

    const userDoc = snapshot.docs[0];
    this.logger.log('User found:', userDoc.data());

    try {
      await userDoc.ref.update({
        emailConfirmed: true,
        confirmationToken: admin.firestore.FieldValue.delete(),
      });
      this.logger.log('Email confirmed successfully');
    } catch (error) {
      this.logger.error('Error updating user document:', error);
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
      throw new UnauthorizedException('Invalid login credentials');
    }
  }

  async updatePassword(updatePasswordDto: UpdatePasswordDto): Promise<void> {
    const { uid, newPassword } = updatePasswordDto;

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await admin.auth().updateUser(uid, { password: newPassword });

    await admin.firestore().collection('users').doc(uid).update({
      password: hashedPassword,
    });
  }
}
