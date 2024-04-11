import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { Request } from 'express';
import { JwtPayload } from '../auth.types';

@Injectable() // 注入服务
export class AtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(configService: ConfigService) {
    super({
      // 简单来说就是提取token
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: configService.get('JWT_ACCESS_SECRET'), // 设置你的用来签署令牌的密钥
      passReqToCallback: true, // 拿回刷新令牌
    });
  }

  // 验证函数,接收有效负载
  validate(req: Request, payload: JwtPayload) {
    const accessToken = req.get('authorization').replace('Bearer ', '').trim();
    return {
      ...payload,
      accessToken,
    };
  }
}
