import {
  ForbiddenException,
  Inject,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { IAuthService } from './auth.iservice';
import { Prisma } from '@prisma/client';
import { IServices } from 'src/constant';
import { IUserService } from 'src/user/user.iservice';
import { formatDate, verifyPassword } from 'src/utils';
import { SetTokensData } from './auth.types';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService implements IAuthService {
  constructor(
    @Inject(IServices.IUSER)
    private readonly userService: IUserService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  // 校验用户
  async validateUser(data: Prisma.UserWhereInput) {
    // 查找邮箱
    const user = await this.userService.findUserByEmail(data.email);
    if (!user) throw new NotFoundException('用户不存在，请先注册');

    // 验证密码是否正确
    const isPasswordValid = await verifyPassword(
      user.password,
      data.password as string,
    );
    if (!isPasswordValid) throw new NotFoundException('密码错误，请重新输入');

    // 不显示密码字段
    // email.password = undefined;
    delete user.password;

    // 获得token
    const { id, email, role } = user;
    const tokens = await this.setTokens(id, email, role);

    return tokens;
  }

  // 获取当前用户
  async getCurrent(id: number) {
    const user = await this.userService.getUserById(id);
    delete user.password;
    user.createdAt = formatDate(user.createdAt);
    user.updatedAt = formatDate(user.updatedAt);
    return user;
  }

  async refreshToken(refreshToken: string) {
    try {
      // 解析refreshToken
      const verify = await this.jwtService.verify(refreshToken, {
        secret: this.configService.get('JWT_REFRESH_SECRET'),
      });
      if (!verify) throw new ForbiddenException('无效的刷新令牌');

      const { sub } = verify as { sub: number };
      const user = await this.userService.getUserById(sub);
      const tokens = await this.setTokens(user.id, user.email, user.role);
      return tokens;
    } catch (e) {
      throw new UnauthorizedException('令牌过期，请重新登录');
    }
  }

  async setTokens(
    id: number,
    email: string,
    role: number,
  ): Promise<SetTokensData> {
    const [at, rt] = await Promise.all([
      this.jwtService.signAsync(
        {
          sub: id,
          email,
          role,
        },
        {
          secret: this.configService.get('JWT_ACCESS_SECRET'),
          // expiresIn: 60 * 15, // 15分钟
          expiresIn: 60 * 60 * 24 * 30, // 30天 开发阶段
        },
      ),
      this.jwtService.signAsync(
        {
          sub: id,
        },
        {
          secret: this.configService.get('JWT_REFRESH_SECRET'),
          expiresIn: 60 * 60 * 24 * 7, // 7天
        },
      ),
    ]);

    return {
      accessToken: at,
      refreshToken: rt,
    };
  }
}
