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
}
