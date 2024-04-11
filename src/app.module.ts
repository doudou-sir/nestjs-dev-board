import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { UserModule } from './user/user.module';
import { PrismaModule } from './prisma/prisma.module';
import { ConfigModule } from '@nestjs/config';
import { AuthModule } from 'src/auth/auth.module';
import { APP_GUARD } from '@nestjs/core';
import { AtGuard } from 'src/auth/guards';
import { MinioClientModule } from './minio-client/minio-client.module';
import { RedisModule } from './redis/redis.module';
import { EmailModule } from './email/email.module';
import { PassportModule } from '@nestjs/passport';
// import envConfig from './config/env';

@Module({
  imports: [
    // env配置
    ConfigModule.forRoot({
      isGlobal: true, // 设置为全局
      // envFilePath: [envConfig.path], // 设置环境变量文件路径
    }),
    // passport配置
    // PassportModule.register({ session: true }),
    UserModule,
    PrismaModule,
    AuthModule,
    MinioClientModule,
    RedisModule,
    EmailModule,
  ],
  controllers: [AppController],
  providers: [
    AppService,
    {
      provide: APP_GUARD,
      useClass: AtGuard,
    },
  ],
})
export class AppModule {}
