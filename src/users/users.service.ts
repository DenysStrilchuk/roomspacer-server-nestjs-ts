import { Injectable } from '@nestjs/common';
import { FirebaseService } from '../firebase/firebase.service';

@Injectable()
export class UsersService {
  constructor(private readonly firebaseService: FirebaseService) {}

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
}
