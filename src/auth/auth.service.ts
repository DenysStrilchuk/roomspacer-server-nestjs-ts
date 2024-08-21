import {
  Injectable,
  UnauthorizedException,
  BadRequestException,
  InternalServerErrorException,
} from '@nestjs/common';
import * as admin from 'firebase-admin';
import * as bcrypt from 'bcrypt';
import { UserRecord } from 'firebase-admin/lib/auth';
import { CreateUserDto } from './dto/create-user.dto';
import { LoginUserDto } from './dto/login-user.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { MailService } from '../mail/mail.service';
import * as crypto from 'crypto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { FirebaseService } from '../firebase/firebase.service';
import { ILoginResponse } from './interfaces/login-response.interface';

@Injectable()
export class AuthService {
  constructor(
    private readonly firebaseService: FirebaseService,
    private readonly mailService: MailService,
  ) {}

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
      throw new UnauthorizedException('Error confirming email');
    }
  }

  async login(loginUserDto: LoginUserDto): Promise<{ token: string }> {
    const { email, password, token } = loginUserDto;

    try {
      if (!token || typeof token !== 'string') {
        console.error('Invalid or missing token:', token);
        throw new UnauthorizedException('Invalid or missing token');
      }

      const decodedToken = await admin.auth().verifyIdToken(token);
      if (decodedToken.email !== email) {
        throw new UnauthorizedException('Invalid token');
      }

      const user = await admin.auth().getUserByEmail(email);

      const userDoc = await admin
        .firestore()
        .collection('users')
        .doc(user.uid)
        .get();
      const userData = userDoc.data();

      if (!userData) {
        throw new UnauthorizedException('User not found');
      }

      // Перевірка, чи підтверджена електронна пошта
      if (!userData.emailConfirmed) {
        throw new UnauthorizedException(
          'Email not confirmed. Please check your inbox.',
        );
      }

      const isPasswordValid = await bcrypt.compare(password, userData.password);
      if (!isPasswordValid) {
        throw new UnauthorizedException('Invalid password');
      }

      return { token };
    } catch (error) {
      console.error('Login error:', error);
      throw new UnauthorizedException('Invalid login credentials');
    }
  }

  async forgotPassword(forgotPasswordDto: ForgotPasswordDto): Promise<void> {
    const { email } = forgotPasswordDto;

    try {
      const user = await admin.auth().getUserByEmail(email);

      const userDoc = await admin
        .firestore()
        .collection('users')
        .doc(user.uid)
        .get();
      const userData = userDoc.data();

      if (!userData || !userData.password) {
        throw new BadRequestException(
          'This user is registered through Google and cannot reset their password.',
        );
      }

      const resetToken = crypto.randomBytes(32).toString('hex');

      await admin
        .firestore()
        .collection('users')
        .doc(user.uid)
        .update({
          resetPasswordToken: resetToken,
          resetPasswordExpires: admin.firestore.Timestamp.fromDate(
            new Date(Date.now() + 3600000), // 1 година
          ),
        });

      const resetLink = `http://localhost:3000/auth/reset-password/${resetToken}`;

      // Відправка листа для скидання паролю
      await this.mailService.sendResetPasswordEmail(email, resetLink);
    } catch (error) {
      if (error instanceof BadRequestException) {
        throw error;
      }
      if (error.code === 'auth/user-not-found') {
        throw new BadRequestException('No user found with this email.');
      }
      if (error.code === 'auth/invalid-email') {
        throw new BadRequestException('Email format is incorrect.');
      }
      throw new InternalServerErrorException('Something went wrong.');
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

  async registerWithGoogle(idToken: string): Promise<ILoginResponse> {
    const decodedToken = await this.verifyGoogleToken(idToken);
    const { uid, name, email, picture } = decodedToken;

    try {
      let userRecord;
      try {
        userRecord = await admin.auth().getUser(uid);
      } catch (error) {
        if (error.code === 'auth/user-not-found') {
          userRecord = await admin.auth().createUser({
            uid,
            displayName: name,
            email,
          });

          await admin.firestore().collection('users').doc(uid).set({
            name,
            email,
            emailConfirmed: true,
          });
        } else {
          throw new InternalServerErrorException('Failed to create user');
        }
      }

      const userRef = admin.firestore().collection('users').doc(uid);
      await userRef.set({
        uid,
        email,
        name,
        picture,
      });

      return {
        user: {
          uid: userRecord.uid,
          email: decodedToken.email,
          name: decodedToken.name,
          picture: decodedToken.picture,
        },
        token: idToken, // Повертаємо токен, отриманий з фронтенду
      };
    } catch (error) {
      throw new InternalServerErrorException('Failed to register with Google');
    }
  }

  async loginWithGoogle(idToken: string): Promise<ILoginResponse> {
    try {
      const decodedToken = await this.verifyGoogleToken(idToken);
      const { email } = decodedToken;

      // Перевіряємо, чи існує користувач з такою електронною поштою
      let user;
      try {
        user = await admin.auth().getUserByEmail(email);
      } catch (error) {
        if (error.code === 'auth/user-not-found') {
          // Якщо користувача не знайдено, повертаємо помилку
          throw new BadRequestException(
            'User not registered. Please sign up first.',
          );
        } else {
          throw new UnauthorizedException('Login with Google failed');
        }
      }

      // Отримуємо інформацію про користувача з Firestore
      const userDoc = await admin
        .firestore()
        .collection('users')
        .doc(user.uid)
        .get();

      if (!userDoc.exists) {
        throw new BadRequestException(
          'User not found in Firestore. Please register first.',
        );
      }

      return {
        user: {
          uid: user.uid,
          email: user.email,
          name: user.displayName,
          picture: user.photoURL,
        },
        token: idToken, // Повертаємо токен, отриманий з фронтенду
      };
    } catch (error) {
      throw new UnauthorizedException('Login with Google failed');
    }
  }

  async verifyGoogleToken(idToken: string): Promise<admin.auth.DecodedIdToken> {
    try {
      return await admin.auth().verifyIdToken(idToken);
    } catch (error) {
      throw new UnauthorizedException('Invalid Google token');
    }
  }

  async verifyToken(authHeader: string): Promise<admin.auth.DecodedIdToken> {
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      throw new UnauthorizedException('Invalid token format');
    }

    const token = authHeader.split(' ')[1]; // Отримуємо чистий токен

    try {
      return await admin.auth().verifyIdToken(token);
    } catch (error) {
      console.error('Token verification failed:', error.message);
      throw new UnauthorizedException('Token verification failed');
    }
  }
}
