import { Logger, Module } from '@nestjs/common';
import { PrismaService } from './prisma.service';

@Module({
  providers: [
    PrismaService,
    {
      provide: 'PrismaLogger', // 定义切面
      useFactory: () => {
        // 定义切面的逻辑
        return new Logger('PrismaConnected');
      },
    },
  ],
  exports: [PrismaService], // Export the PrismaService so other modules can use it
})
export class PrismaModule {}
