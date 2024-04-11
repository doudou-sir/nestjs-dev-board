import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { Request } from 'express';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { JwtRefreshPayload } from '../auth.types';

@Injectable() // 注入服务
export class RtStrategy extends PassportStrategy(Strategy, 'jwt-refresh') {
  constructor(configService: ConfigService) {
    super({
      // 简单来说就是提取token
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: configService.get('JWT_REFRESH_SECRET'), // 设置你的用来签署令牌的密钥
      passReqToCallback: true, // 拿回刷新令牌
    });
  }

  // 验证函数,接收有效负载
  validate(req: Request, payload: JwtRefreshPayload) {
    const refreshToken = req.get('authorization').replace('Bearer ', '').trim();
    return {
      ...payload,
      refreshToken,
    };
  }
}
