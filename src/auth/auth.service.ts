import {
  Injectable,
  UnauthorizedException,
  BadRequestException,
  InternalServerErrorException,
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

export interface ILoginResponse {
  user: {
    uid: string;
    email: string;
    name?: string;
    picture?: string;
  };
  token: string;
}

@Injectable()
export class AuthService {
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

      return await this.createToken(user);
    } catch (error) {
      throw new UnauthorizedException('Invalid login credentials');
    }
  }

  async forgotPassword(forgotPasswordDto: ForgotPasswordDto): Promise<void> {
    const { email } = forgotPasswordDto;

    try {
      // Отримуємо користувача за його email
      const user = await admin.auth().getUserByEmail(email);

      // Отримуємо дані користувача з Firestore
      const userDoc = await admin
        .firestore()
        .collection('users')
        .doc(user.uid)
        .get();
      const userData = userDoc.data();

      // Перевірка наявності користувача та його пароля
      if (!userData || !userData.password) {
        throw new BadRequestException(
          'Цей користувач зареєстрований через Google і не може відновити пароль.',
        );
      }

      // Генерація токена відновлення паролю
      const resetToken = crypto.randomBytes(32).toString('hex');

      // Оновлення документу користувача в Firestore з токеном та часом його дії
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

      // Формування посилання для скидання паролю
      const resetLink = `http://localhost:3000/auth/reset-password/${resetToken}`;

      // Відправка листа для скидання паролю
      await this.mailService.sendResetPasswordEmail(email, resetLink);
    } catch (error) {
      if (error instanceof BadRequestException) {
        throw error;
      }
      if (error.code === 'auth/user-not-found') {
        throw new BadRequestException(
          'Користувача з такою поштою не знайдено.',
        );
      }
      if (error.code === 'auth/invalid-email') {
        throw new BadRequestException('Неправильний формат електронної пошти.');
      }
      throw new InternalServerErrorException('Щось пішло не так.');
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

      const token = await this.createToken(userRecord);

      return {
        user: {
          uid: userRecord.uid,
          email: decodedToken.email,
          name: decodedToken.name,
          picture: decodedToken.picture,
        },
        token: token,
      };
    } catch (error) {
      throw new InternalServerErrorException('Failed to register with Google');
    }
  }

  async loginWithGoogle(idToken: string): Promise<ILoginResponse> {
    try {
      const decodedToken = await this.verifyGoogleToken(idToken);
      const { email } = decodedToken;

      const user = await admin.auth().getUserByEmail(email);
      const userDoc = await admin
        .firestore()
        .collection('users')
        .doc(user.uid)
        .get();

      if (!userDoc.exists) {
        throw new BadRequestException('User not found. Please register first.');
      }

      const token = await this.createToken(user);
      return {
        user: {
          uid: user.uid,
          email: user.email,
          name: user.displayName,
          picture: user.photoURL,
        },
        token: token,
      };
    } catch (error) {
      throw new UnauthorizedException('Login with Google failed');
    }
  }

  async createToken(user: admin.auth.UserRecord): Promise<string> {
    try {
      return await admin.auth().createCustomToken(user.uid);
    } catch (error) {
      throw new InternalServerErrorException('Could not create token');
    }
  }

  async verifyGoogleToken(idToken: string): Promise<admin.auth.DecodedIdToken> {
    try {
      return await admin.auth().verifyIdToken(idToken);
    } catch (error) {
      throw new UnauthorizedException('Invalid Google token');
    }
  }
}
