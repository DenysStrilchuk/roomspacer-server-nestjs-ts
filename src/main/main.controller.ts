import { Controller, Get, UseGuards } from '@nestjs/common';
import { MainService } from './main.service';
import { AuthGuard } from '../auth/guards/auth.guard';

@Controller('main')
export class MainController {
  constructor(private readonly mainService: MainService) {}

  @Get()
  @UseGuards(AuthGuard)
  getMainPage() {
    return this.mainService.getMainContent();
  }
}
