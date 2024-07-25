import { Controller, Get } from '@nestjs/common';
import { ProfileService } from './profile.service';
import { User } from '../common/decorators/user.decorator';

@Controller('profile')
export class ProfileController {
  constructor(private readonly profileService: ProfileService) {}

  @Get()
  getProfile(@User() user: any) {
    // Отримуємо профіль користувача з сервісу
    return this.profileService.getProfile(user);
  }
}
