import { Controller, Get } from '@nestjs/common';
import { User } from '../common/decorators/user.decorator';
import { ProfileService } from './profile.service';

@Controller('profile')
export class ProfileController {
  constructor(private readonly profileService: ProfileService) {}

  @Get()
  getProfile(@User() user: any) {
    return this.profileService.getProfile(user);
  }
}
