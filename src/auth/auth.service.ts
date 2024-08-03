import { Injectable, UnauthorizedException } from '@nestjs/common';
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
  constructor(private readonly mailService: MailService) {}

  async register(createUserDto: CreateUserDto): Promise<UserRecord> {
    const { name, email, password } = createUserDto;
    const hashedPassword = await bcrypt.hash(password, 10);

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

    const verificationLink = await admin
      .auth()
      .generateEmailVerificationLink(email);

    await this.mailService.sendConfirmationEmail(email, verificationLink);

    return userRecord;
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
    await userDoc.ref.update({
      emailConfirmed: true,
      confirmationToken: admin.firestore.FieldValue.delete(),
    });
  }
  // Метод для входу користувача
  async login(loginUserDto: LoginUserDto): Promise<string> {
    const { email, password } = loginUserDto;

    try {
      // Отримати користувача за email з Firebase Authentication
      const user = await admin.auth().getUserByEmail(email);

      // Перевірити, чи електронна пошта користувача підтверджена
      if (!user.emailVerified) {
        throw new UnauthorizedException('Електронна пошта не підтверджена');
      }

      // Отримати документ користувача з Firestore
      const userDoc = await admin
        .firestore()
        .collection('users')
        .doc(user.uid)
        .get();
      const userData = userDoc.data();

      // Перевірка наявності даних користувача і пароля
      if (!userData || !userData.password) {
        throw new UnauthorizedException(
          'Користувача не знайдено або відсутній пароль',
        );
      }

      // Перевірка правильності пароля
      const isPasswordValid = await bcrypt.compare(password, userData.password);
      if (!isPasswordValid) {
        throw new UnauthorizedException('Невірний пароль');
      }

      // Створення кастомного токена
      return await admin.auth().createCustomToken(user.uid);
    } catch (error) {
      throw new UnauthorizedException('Невірні дані для входу');
    }
  }

  // Метод для оновлення пароля
  async updatePassword(updatePasswordDto: UpdatePasswordDto): Promise<void> {
    const { uid, newPassword } = updatePasswordDto;

    // Хешування нового пароля
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Оновлення пароля в Firebase Authentication
    await admin.auth().updateUser(uid, { password: newPassword });

    // Оновлення захешованого пароля в Firestore
    await admin.firestore().collection('users').doc(uid).update({
      password: hashedPassword,
    });
  }
}
