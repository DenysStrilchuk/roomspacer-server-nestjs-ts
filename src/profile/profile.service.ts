import { Injectable } from '@nestjs/common';

@Injectable()
export class ProfileService {
  getProfile(user: any) {
    return user;
  }
}
