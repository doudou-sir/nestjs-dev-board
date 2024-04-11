import { Global, Module } from '@nestjs/common';
import { EmailService } from './email.service';

@Global() // 全局模块
@Module({
  providers: [EmailService],
  exports: [EmailService], // 导出服务，以便在其他模块中使用
})
export class EmailModule {}
