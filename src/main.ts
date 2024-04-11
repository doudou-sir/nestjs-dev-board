import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import { Logger } from '@nestjs/common';
import { setSwaggerDocument } from 'src/utils';
// import * as session from 'express-session';
// import * as passport from 'passport';

async function bootstrap() {
  const { NEST_PORT, SESSION_SECRET } = process.env;
  const app = await NestFactory.create(AppModule);
  const logger: Logger = new Logger('Main');
  // 全局路由
  app.setGlobalPrefix('api');
  // 设置Swagger文档
  setSwaggerDocument(app);
  // 跨域
  app.enableCors();
  // 设置session
  // app.use(
  //   session({
  //     secret: SESSION_SECRET,
  //     saveUninitialized: false,
  //     resave: false,
  //     name: 'GO_WHERE_SESSION_ID',
  //     cookie: {
  //       maxAge: 86400000, // cookie expires 1 day later
  //     },
  //   }),
  // );
  // app.use(passport.initialize());
  // app.use(passport.session());
  // 管道校验
  app.useGlobalPipes(new ValidationPipe());
  try {
    await app.listen(NEST_PORT, () => {
      logger.log(`server starting on http://localhost:${NEST_PORT}/api`);
    });
  } catch (e) {
    logger.error(e);
  }
}
bootstrap();
