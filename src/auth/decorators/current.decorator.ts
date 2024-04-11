import { ExecutionContext, createParamDecorator } from '@nestjs/common';

// 创建一个装饰器，用于获取当前用户
export const GetCurrentUser = createParamDecorator(
  (data: string | undefined, ctx: ExecutionContext) => {
    const request: Express.Request = ctx.switchToHttp().getRequest();
    if (data) return request.user[data];
    return request.user;
  },
);
