import {
  ExecutionContext,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthGuard } from '@nestjs/passport';
import { Request } from 'express';
import { Observable } from 'rxjs';

@Injectable()
export class AtGuard extends AuthGuard('jwt') {
  constructor(private reflector: Reflector) {
    super();
  }

  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    // 需要使用到反射器reflector
    const isPublic = this.reflector.getAllAndOverride<boolean>('isPublic', [
      context.getHandler(),
      context.getClass(),
    ]);

    if (isPublic) return true;

    // 获取请求头
    const request: Request = context.switchToHttp().getRequest();
    const authorization = request.headers.authorization;
    const token = authorization.split(' ')[1];
    // 判断用户是否登录
    if (!token) {
      throw new NotFoundException('用户未登录, 请先登录');
    }

    return super.canActivate(context);
  }
}
