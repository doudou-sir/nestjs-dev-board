import { Global, Module } from '@nestjs/common';
import { RedisService } from './redis.service';
import { createClient } from 'redis';
const { REDIS_HOST, REDIS_PORT, REDIS_PASSWORD } = process.env;

@Global() // 全局模块
@Module({
  providers: [
    RedisService,
    {
      provide: 'REDIS_CLIENT',
      useFactory: async () => {
        const client = createClient({
          password: REDIS_PASSWORD,
          socket: {
            host: REDIS_HOST,
            port: +REDIS_PORT,
          },
          // database: 0, // 默认数据库
        });
        await client.connect();
        return client;
      },
    },
  ],
  exports: [RedisService],
})
export class RedisModule {}
