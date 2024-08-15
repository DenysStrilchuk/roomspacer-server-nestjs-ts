import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { Request } from 'express';

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(private authService: AuthService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request: Request = context.switchToHttp().getRequest();
    const token = request.headers.authorization?.split(' ')[1]; // Bearer <token>

    if (!token) {
      throw new UnauthorizedException('Token not provided');
    }

    try {
      // Перевіряємо токен і додаємо дані про користувача до запиту
      request.user = await this.authService.verifyToken(token);
      return true;
    } catch (e) {
      throw new UnauthorizedException('Invalid token');
    }
  }
}
