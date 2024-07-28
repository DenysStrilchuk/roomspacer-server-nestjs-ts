import { Module } from '@nestjs/common';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
import { ProfileModule } from './profile/profile.module';
import { ConfigModule } from '@nestjs/config';
import { FirebaseService } from './ config/firebase.config';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true, // Робить ConfigModule доступним у всьому додатку
    }),
    AuthModule,
    UsersModule,
    ProfileModule,
  ],
  providers: [FirebaseService], // Додайте FirebaseService до провайдерів
})
export class AppModule {}
