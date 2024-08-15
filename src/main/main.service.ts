import { Injectable } from '@nestjs/common';

@Injectable()
export class MainService {
  getMainContent(): string {
    return 'This is the main page content for authenticated users only';
  }
}
