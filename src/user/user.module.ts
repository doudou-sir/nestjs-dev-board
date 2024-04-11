import { Module } from '@nestjs/common';
import { UserController } from './user.controller';
import { UserService } from './user.service';
import { PrismaModule } from 'src/prisma/prisma.module';
import { IServices } from 'src/constant';

@Module({
  imports: [PrismaModule], // 导入其他模块
  controllers: [UserController],
  providers: [
    {
      provide: IServices.IUSER,
      useClass: UserService,
    },
  ],
  exports: [
    {
      provide: IServices.IUSER,
      useClass: UserService,
    },
  ],
})
export class UserModule {}
