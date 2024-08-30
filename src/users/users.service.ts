import { Injectable } from '@nestjs/common';
import { FirebaseService } from '../firebase/firebase.service';
import { MailService } from '../mail/mail.service';

@Injectable()
export class UsersService {
  constructor(
    private readonly firebaseService: FirebaseService,
    private readonly mailService: MailService,
  ) {}

  async findOneByEmail(email: string) {
    return await this.firebaseService.getAuth().getUserByEmail(email);
  }

  async updatePassword(uid: string, newPassword: string) {
    return await this.firebaseService
      .getAuth()
      .updateUser(uid, { password: newPassword });
  }

  async findAll() {
    const usersList = await this.firebaseService.getAuth().listUsers();
    return usersList.users.map((user) => ({
      uid: user.uid,
      email: user.email,
      name: user.displayName,
    }));
  }

  async getUsersStatus(): Promise<
    Array<{
      uid: string;
      email: string;
      online: boolean;
      lastOnline: Date | null;
    }>
  > {
    // Отримання даних з Firestore
    const usersSnapshot = await this.firebaseService
      .getFirestore()
      .collection('users')
      .get();

    // Обробка даних та їх повернення
    return usersSnapshot.docs.map((doc) => {
      const data = doc.data();
      return {
        uid: doc.id,
        email: data.email,
        online: data.online,
        lastOnline: data.lastOnline ? data.lastOnline.toDate() : null,
      };
    });
  }

  async inviteUserByEmail(email: string): Promise<void> {
    try {
      const userRecord = await this.firebaseService
        .getAuth()
        .getUserByEmail(email);

      // Якщо користувач вже зареєстрований
      if (userRecord) {
        throw new Error('User already exists.');
      }
    } catch (error) {
      if (error.code === 'auth/user-not-found') {
        // Якщо користувача не знайдено, надсилаємо запрошення
        const invitationLink = `http://localhost:3000/auth/register`;
        await this.mailService.sendInvitationEmail(email, invitationLink);
      } else {
        throw error;
      }
    }
  }
}
