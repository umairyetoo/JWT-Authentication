// src/main.ts
import { NestFactory } from '@nestjs/core';
import { ValidationPipe, Logger } from '@nestjs/common';
import { AppModule } from './app.module';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';

async function bootstrap(): Promise<void> {
  const logger = new Logger('Bootstrap');
  const app = await NestFactory.create(AppModule);

  /**
   * Global validation pipe — applies to ALL routes automatically.
   *
   * whitelist: true         — strips any fields not in DTO
   * forbidNonWhitelisted    — throws 400 if unknown fields sent
   * transform: true         — auto-converts types (string → number etc)
   */
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );

  const port = process.env.PORT || 3001;

  // Swagger setup
  const swaggerConfig = new DocumentBuilder()
    .setTitle('Auth API')
    .setDescription('JWT Authentication API')
    .setVersion('1.0')
    .addBearerAuth({
      type: 'http',
      scheme: 'bearer',
      bearerFormat: 'JWT',
    }, 'access-token')
    .build();

  const swaggerDoc = SwaggerModule.createDocument(app, swaggerConfig);
  SwaggerModule.setup('api', app, swaggerDoc);
  await app.listen(port);

  logger.log(`Auth service running on port ${port}`);
}

bootstrap();