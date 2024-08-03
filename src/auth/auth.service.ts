import { Injectable, UnauthorizedException } from '@nestjs/common';
import * as admin from 'firebase-admin';
import * as bcrypt from 'bcrypt';
import { UserRecord } from 'firebase-admin/lib/auth';
import { CreateUserDto } from '../users/dto/create-user.dto';
import { LoginUserDto } from '../users/dto/login-user.dto';
import { UpdatePasswordDto } from '../users/dto/update-password.dto';

@Injectable()
export class AuthService {
  // Метод для реєстрації користувача
  async register(createUserDto: CreateUserDto): Promise<UserRecord> {
    const { email, password } = createUserDto;

    // Хешування пароля
    const hashedPassword = await bcrypt.hash(password, 10);

    // Створення користувача у Firebase Authentication з незахешованим паролем
    const userRecord = await admin.auth().createUser({
      email,
      password, // Використовуємо незахешований пароль для створення користувача у Firebase
    });

    // Збереження захешованого пароля в Firestore
    await admin.firestore().collection('users').doc(userRecord.uid).set({
      email,
      password: hashedPassword, // Зберігаємо захешований пароль у Firestore
    });

    return userRecord;
  }

  // Метод для входу користувача
  async login(loginUserDto: LoginUserDto): Promise<string> {
    const { email, password } = loginUserDto;

    try {
      // Отримання користувача за email з Firebase Authentication
      const user = await admin.auth().getUserByEmail(email);

      // Отримання документа користувача з Firestore
      const userDoc = await admin
        .firestore()
        .collection('users')
        .doc(user.uid)
        .get();
      const userData = userDoc.data();

      // Перевірка наявності даних користувача і пароля
      if (!userData || !userData.password) {
        throw new UnauthorizedException(
          'User not found or password is missing',
        );
      }

      // Перевірка правильності пароля
      const isPasswordValid = await bcrypt.compare(password, userData.password);
      if (!isPasswordValid) {
        throw new UnauthorizedException('Invalid credentials');
      }

      // Створення кастомного токена
      return await admin.auth().createCustomToken(user.uid);
    } catch (error) {
      throw new UnauthorizedException('Invalid credentials');
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
