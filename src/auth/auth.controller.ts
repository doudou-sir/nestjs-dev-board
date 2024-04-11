import {
  BadRequestException,
  Body,
  ConflictException,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Inject,
  ParseIntPipe,
  Post,
  Query,
  Session,
  UseGuards,
} from '@nestjs/common';
import { IServices, Routes } from 'src/constant';
import { IAuthService } from './auth.iservice';
import { RegisterDto } from './dtos';
import { IUserService } from 'src/user/user.iservice';
import { ApiBody, ApiOperation, ApiTags } from '@nestjs/swagger';
import { LoginDto } from './dtos/login.dto';
import { GetCurrentUser } from './decorators';
import { Public } from 'src/auth/decorators';
import { EmailService } from 'src/email/email.service';
import { RedisService } from 'src/redis/redis.service';
import { LocalAuthGuard } from './guards';

@ApiTags('auth用户权限')
@Controller(Routes.Auth)
export class AuthController {
  constructor(
    @Inject(IServices.IAUTH) private authSerivce: IAuthService,
    @Inject(IServices.IUSER) private userService: IUserService,
    @Inject(EmailService) private emailService: EmailService,
    @Inject(RedisService) private redisService: RedisService,
  ) {}

  @Public()
  @Post(Routes.Register)
  // @ApiOperation({ summary: '用户注册' })
  // @ApiBody({ type: RegisterDto })
  @HttpCode(HttpStatus.OK)
  async register(@Body() registerDto: RegisterDto) {
    // 调用用户服务注册用户
    return await this.userService.createUser(registerDto);
  }

  @Public()
  @Get(Routes.Captcha)
  @HttpCode(HttpStatus.OK)
  async getCaptcha(@Query('email') email: string) {
    // 随机生成六位验证码
    const code = Math.random().toString().slice(-6);
    await this.redisService.set(`captcha_${email}`, code, 60 * 5);
    await this.emailService.sendMail({
      to: email,
      subject: '注册验证码',
      html: `<p>你的注册验证码为 ${code}</p>`,
    });
  }

  // 忘记密码-通过邮箱验证-设置新密码
  @Public()
  @Post(Routes.Forget)
  @HttpCode(HttpStatus.OK)
  async forgetPass(
    @Query('email') email: string,
    @Query('captcha') captcha: string,
  ) {
    const code = await this.redisService.get(`captcha_${email}`);
    if (!code) throw new ConflictException('验证码已过期，请重新发送');
    if (code !== captcha) throw new BadRequestException('验证码错误');
  }

  // 修改密码
  @Public()
  @Post(Routes.Reset)
  @HttpCode(HttpStatus.OK)
  async resetPass(@Body() resetDto: any) {}

  @UseGuards(LocalAuthGuard)
  @Public()
  @Post(Routes.Login)
  @HttpCode(HttpStatus.OK)
  async login(@Body() loginDto: LoginDto) {
    // 调用用户服务注册用户
    return await this.authSerivce.validateUser(loginDto);
  }

  // 当前用户
  @Get(Routes.Current)
  // @UseGuards(AtGuard)
  @HttpCode(HttpStatus.OK)
  getCurrent(@GetCurrentUser('sub', ParseIntPipe) id: number) {
    return this.authSerivce.getCurrent(id);
  }

  // 刷新token
  @Public()
  @Get(Routes.Refresh)
  @HttpCode(HttpStatus.OK)
  refreshToken(@Query('refreshToken') refreshToken: string) {
    return this.authSerivce.refreshToken(refreshToken);
  }
}
