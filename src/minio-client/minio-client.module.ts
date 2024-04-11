import { Global, Module } from '@nestjs/common';
import { MinioClientService } from './minio-client.service';
import { UserModule } from 'src/user/user.module';

@Global()
@Module({
  imports: [UserModule],
  providers: [MinioClientService],
  exports: [MinioClientService],
})
export class MinioClientModule {}
