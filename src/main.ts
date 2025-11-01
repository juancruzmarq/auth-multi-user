import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import * as cookieParser from 'cookie-parser';
import { Logger, ValidationPipe } from '@nestjs/common';
import { Config } from './common/config';
import { ConfigService } from '@nestjs/config';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const configService = app.get(ConfigService);
  const logger = new Logger('Bootstrap');
  const requiredEnvVariables = Object.values(Config);

  for (const envVariable of requiredEnvVariables) {
    if (!configService.get(envVariable)) {
      logger.error(`ENV variable ${envVariable} is missing`);
      process.exit(1);
    }
  }

  app.use(cookieParser());
  app.useGlobalPipes(new ValidationPipe({ whitelist: true, transform: true }));
  app.enableCors({
    origin: ['http://localhost:5173', '*'],
    credentials: true,
  });
  await app.listen(process.env.APP_PORT ?? 3000);
}
bootstrap();
