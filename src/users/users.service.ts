import { Injectable } from '@nestjs/common';
import { db } from '../firebase-admin';

@Injectable()
export class UsersService {
  async findByEmail(email: string) {
    // Implement Firebase query to find user by email
    const userDoc = await db.collection('users').doc(email).get();
    return userDoc.exists ? userDoc.data() : null;
  }

  async create(userDto: any) {
    // Implement Firebase to create a new user
    await db.collection('users').doc(userDto.email).set(userDto);
    return userDto;
  }
}
