import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Додайте налаштування CORS
  app.enableCors({
    origin: 'http://localhost:3000', // Ваш фронтенд адрес
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS',
    credentials: true,
  });

  await app.listen(3001);
}
void bootstrap();
