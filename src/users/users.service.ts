import { Injectable, Logger } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { User } from './interfaces/user.interface';
import * as bcrypt from 'bcrypt';
import { FirebaseService } from '../ config/firebase.config';

@Injectable()
export class UsersService {
  private readonly logger = new Logger(UsersService.name);
  private readonly collection = this.firebaseService
    .getFirestore()
    .collection('users');

  constructor(private readonly firebaseService: FirebaseService) {}

  async create(createUserDto: CreateUserDto): Promise<User> {
    const userRecord = await this.firebaseService.getAuth().createUser({
      email: createUserDto.email,
      password: createUserDto.password,
    });

    const docRef = this.collection.doc(userRecord.uid);
    await docRef.set({ ...createUserDto, id: docRef.id });

    await this.firebaseService.sendEmailVerification(userRecord.uid);

    return (await docRef.get()).data() as User;
  }

  async findByEmail(email: string): Promise<User> {
    const snapshot = await this.collection.where('email', '==', email).get();
    if (snapshot.empty) {
      return null;
    }
    return snapshot.docs[0].data() as User;
  }

  async getUserRecordByEmail(email: string) {
    return await this.firebaseService.getAuth().getUserByEmail(email);
  }

  async updatePassword(id: string, password: string): Promise<void> {
    this.logger.log(`Updating password for user with id: ${id}`);
    const docRef = this.collection.doc(id);
    try {
      const hashedPassword = await bcrypt.hash(password, 10);
      await docRef.update({ password: hashedPassword });

      await this.firebaseService.getAuth().updateUser(id, { password });

      this.logger.log(`Password updated successfully for user with id: ${id}`);
    } catch (error) {
      this.logger.error(
        `Failed to update password for user with id: ${id}`,
        error,
      );
      throw error;
    }
  }

  async findOrCreate(userDto: CreateUserDto): Promise<User> {
    let user = await this.findByEmail(userDto.email);
    if (!user) {
      user = await this.create(userDto);
    }
    return user;
  }

  async changeEmail(userId: string, newEmail: string): Promise<void> {
    await this.firebaseService.sendEmailChangeVerification(userId, newEmail);
  }
}
