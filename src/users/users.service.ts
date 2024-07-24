import { Injectable } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { User } from './interfaces/user.interface';
import { FirebaseService } from '../ config/firebase.config';

@Injectable()
export class UsersService {
  private readonly collection = this.firebaseService
    .getFirestore()
    .collection('users');

  constructor(private readonly firebaseService: FirebaseService) {}

  async create(createUserDto: CreateUserDto): Promise<User> {
    const docRef = this.collection.doc();
    await docRef.set({ ...createUserDto, id: docRef.id });
    const user = await docRef.get();
    return user.data() as User;
  }

  async findByEmail(email: string): Promise<User> {
    const snapshot = await this.collection.where('email', '==', email).get();
    if (snapshot.empty) {
      return null;
    }
    return snapshot.docs[0].data() as User;
  }

  async updatePassword(id: string, password: string): Promise<void> {
    const docRef = this.collection.doc(id);
    await docRef.update({ password });
  }

  async findOrCreate(userDto: CreateUserDto): Promise<User> {
    let user = await this.findByEmail(userDto.email);
    if (!user) {
      user = await this.create(userDto);
    }
    return user;
  }
}
