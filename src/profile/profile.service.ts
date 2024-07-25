import { Injectable } from '@nestjs/common';

@Injectable()
export class ProfileService {
  getProfile(user: any) {
    // Логіка для отримання профілю користувача
    return user; // або більше інформації про користувача з БД
  }
}
