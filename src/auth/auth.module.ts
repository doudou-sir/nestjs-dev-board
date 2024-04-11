import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { IServices } from 'src/constant';
import { UserModule } from 'src/user/user.module';
import { JwtModule } from '@nestjs/jwt';
import { AtStrategy, LocalStrategy, RtStrategy } from './strategies';
import { SessionSerializer } from './serializer';

@Module({
  imports: [
    UserModule,
    // Jwt服务
    JwtModule.register({}),
  ],
  controllers: [AuthController],
  providers: [
    {
      // 注入IServices.IAUTH服务
      provide: IServices.IAUTH,
      // 使用AuthService类
      useClass: AuthService,
    },
    AtStrategy,
    RtStrategy,
    // LocalStrategy,
    SessionSerializer,
  ],
})
export class AuthModule {}
