import { Injectable } from '@nestjs/common';
import { db } from '../firebase-admin';

@Injectable()
export class UsersService {
  async findByEmail(email: string) {
    const userDoc = await db.collection('users').doc(email).get();
    return userDoc.exists ? userDoc.data() : null;
  }

  async create(userDto: any) {
    await db.collection('users').doc(userDto.email).set(userDto);
    return userDto;
  }
}
