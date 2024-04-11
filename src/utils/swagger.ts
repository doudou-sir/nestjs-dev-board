import { INestApplication } from '@nestjs/common';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

const swaggerConfig = new DocumentBuilder()
  .setTitle('go-where 哪都通后台服务') // 设置文档标题
  .setDescription('哪都通后台服务 0.0.1') // 设置文档描述
  .setVersion('0.0.1') // 设置文档版本
  .addBearerAuth() // 添加认证
  .build(); // 构建文档配置

export const setSwaggerDocument = (app: INestApplication<any>) => {
  // 创建文档
  const document = SwaggerModule.createDocument(app, swaggerConfig);
  SwaggerModule.setup('docs', app, document); // 将文档绑定到路由 /docs
};
