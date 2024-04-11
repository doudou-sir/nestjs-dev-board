# 1. 创建项目：

```cmd
nest new go-where-server
$ pnpm
```

先不删除其他文件，到最后会有用。

# 2. prisma：

- 官网：https://www.prisma.io/docs/getting-started/quickstart

~~~bash
pnpm install prisma -D
# 创建本地MySQL数据库
mysql -u root -p
123456
create database go_where_db;
# 初始化prisma
npx prisma init
# 会生成两个文件 .env、prisma/schema.prisma，修改下这两文件
# .env
DATABASE_URL="mysql://root:123456@localhost:3306/go_where_db?schema=public"
# prisma/schema.prisma 刚用时vscode无法识别到该文件，需安装 prisma 插件
generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "mysql"
  url      = env("DATABASE_URL")
}

# 创建用户模型并赋予相应字段
model User {
  id Int @id @default(autoincrement())
  email String @unique
  username String?
  password String
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt
}

model UserSetting {
  id Int @id @default(autoincrement())
  status BigInt  @default(0)
  role BigInt @default(0)
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt
}

model UserProfile {
  id Int @id @default(autoincrement())
  avatar String?
  phone String?
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt
}

# 运行SQL迁移
# --name 后名字随意
npx prisma migrate dev --name db_init
# 会创建 prisma/migrations
~~~

# 3. 连接数据库：

~~~bash
# 创建 prisma 模块 和 user
nest g mo prisma
nest g mo user
nest g s prisma --no-spec
~~~

~~~ts
// prisma.service.ts
import { Injectable, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';

@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit {
  onModuleInit() {
    this.$connect()
      .then(() => {
        console.log('Connected to database');
      })
      .catch((error) => {
        console.error('Failed to connect to database', error);
      });
  }
}

// 在 prisma.module.ts 中提供并导出以便其他模块使用
import { Module } from '@nestjs/common';
import { PrismaService } from './prisma.service';

@Module({
  providers: [PrismaService],
  exports: [PrismaService], // Export the PrismaService so other modules can use it
})
export class PrismaModule {}
~~~

~~~bash
nest g co user --no-spec
nest g s user --no-spec
~~~

~~~ts
// 在 user.module.ts 导入prisma模块
@Module({
  imports: [PrismaModule], // 导入其他模块
  controllers: [UserController],
  providers: [UserService],
})
export class UserModule {}
~~~

# 4. 实现路由逻辑：

~~~ts
// user.service.ts
import { Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { PrismaService } from 'src/prisma/prisma.service';

@Injectable()
export class UserService {
  constructor(private prisma: PrismaService) {}

  // 创建用户
  async createUser(data: Prisma.UserCreateInput) {
    return this.prisma.user.create({ data });
  }

  // 获取用户列表
  async getUsers() {
    return this.prisma.user.findMany();
  }

  // 获取单个用户
  async getUserById(id: number) {
    return this.prisma.user.findUnique({ where: { id } });
  }

  // 更新用户
  async updateUserById(id: number, data: any) {
    return this.prisma.user.update({ where: { id }, data });
  }

  // 删除用户
  async deleteUserById(id: number) {
    return this.prisma.user.delete({ where: { id } });
  }
}

// 在 user.controller.ts 实现路由逻辑

// 创建dtos数据传输对象
// create-user.dto.ts
export class CreateUserDto {
  username: string;

  email: string;

  password: string;
}

// 添加管道验证
pnpm i class-validator class-transformer
// create-user.dto.ts
import { IsEmail, IsNotEmpty, IsString, Length } from 'class-validator';

export class CreateUserDto {
  @IsNotEmpty()
  @IsString()
  username: string;

  @IsEmail()
  @IsNotEmpty()
  @IsString()
  email: string;

  @IsNotEmpty()
  @Length(6, 20)
  @IsString()
  password: string;
}

// 在 main.ts 全局注册管道校验
// 管道校验
  app.useGlobalPipes(new ValidationPipe());

// user.controller.ts
import { Body, Controller, Get, Post } from '@nestjs/common';
import { UserService } from './user.service';
import { CreateUserDto } from './dtos';

@Controller()
export class UserController {
  constructor(private userService: UserService) {}

  @Post('create')
  createUser(@Body() createUserDto: CreateUserDto) {
    return this.userService.createUser(createUserDto);
  }

  @Get('finds')
  getUsers() {
    return this.userService.getUsers();
  }
}
~~~

# 5. env 配置：

~~~bash
pnpm i @nestjs/config -D
~~~

~~~ts
// 在 src/config 下新建 env.ts 用于判断服务是开发环境 .env.dev 还是生产环境 .env.prod，将该两个配置文件放在项目跟目录下：
// env.ts
import * as fs from 'fs';
import * as path from 'path';
const isProd = process.env.NODE_ENV === 'production';

const parseEnv = () => {
  const devEnv = path.resolve('.env.development');
  const prodEnv = path.resolve('.env.production');

  if (!fs.existsSync(devEnv) && !fs.existsSync(prodEnv)) {
    throw new Error('缺少环境配置文件');
  }

  const filePath = isProd && fs.existsSync(prodEnv) ? prodEnv : devEnv;
  return { path: filePath };
};

export default parseEnv();

// 在 .gitignore 中添加忽略跟目录下 .env.dev 和 .env.prod 文件
.env.*
~~~

~~~bash
# .env.development
# 数据库地址
DATABASE_URL="mysql://root:123456@localhost:3306/go_where_db?schema=public"
~~~

~~~ts
// app.module.ts
import { ConfigModule } from '@nestjs/config';
import envConfig from './config/env';
@Module({
  imports: [
    // env配置
    ConfigModule.forRoot({
      isGlobal: true, // 设置为全局
      envFilePath: [envConfig.path], // 设置环境变量文件路径
    })
  ]
})
export class AppModule {}
~~~

# 6. 用户相关模型：

~~~sql
# prisma/schema.prisma
model User {
  id Int @id @default(autoincrement())
  uuid String @default(uuid())
  email String @unique
  username String @unique
  password String
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt
}

model UserProfile {
  id Int @id @default(autoincrement())
  avatar String?
  phone String?
  status BigInt @default(1) // 1 = 登录中, 2 = 退出登录, 3 = 注销用户
  role BigInt @default(1) // 1 = 普通用户, 2 = 管理员
  ipAddress String? // 用户登录IP地址
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt
}

# 运行SQL迁移
# --name 后名字随意
npx prisma migrate dev --name db_init
# 会创建 prisma/migrations
# 每修改一次 schema.prisma ,变执行迁移命令 --name 后名字可与修改有相关性
~~~

# 7. 设置端口：

~~~ts
// 控制台打印连接日志
// main.ts
async function bootstrap() {
  const { NEST_PORT } = process.env;
  const app = await NestFactory.create(AppModule);
  const logger: Logger = new Logger('Main');
  // 管道校验
  app.useGlobalPipes(new ValidationPipe());
  try {
    await app.listen(NEST_PORT, () => {
      logger.log(`server starting on http://localhost:${NEST_PORT}`);
    });
  } catch (e) {
    logger.error(e);
  }
}
bootstrap();
~~~

# 8. 全局路由：

```ts
// main.ts
// 全局路由
app.setGlobalPrefix('api');
```

# 9. 跨域：

```ts
// main.ts
// 跨域
app.enableCors();
```

~~~ts
async function bootstrap() {
  const { NEST_PORT } = process.env;
  const app = await NestFactory.create(AppModule);
  const logger: Logger = new Logger('Main');
  // 全局路由
  app.setGlobalPrefix('api');
  // 跨域
  app.enableCors();
  // 管道校验
  app.useGlobalPipes(new ValidationPipe());
  try {
    await app.listen(NEST_PORT, () => {
      logger.log(`server starting on http://localhost:${NEST_PORT}/api`);
    });
  } catch (e) {
    logger.error(e);
  }
}
bootstrap();
~~~

# 10. 数据库连接模块日志：

~~~ts
// 依赖注入——面向切面(AOP)，根据某个服务或者切面来统一日志的上下文
// prisma.service.ts
@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit {
  constructor(
    @Inject('PrismaLogger')
    private readonly logger: Logger,
  ) {
    super();
  }
  onModuleInit() {
    this.$connect()
      .then(() => {
        this.logger.log('Connected to database');
      })
      .catch((error) => {
        this.logger.log('Failed to connect to database', error);
      });
  }
}

// prisma.module.ts
@Module({
  providers: [
    PrismaService,
    {
      provide: 'PrismaLogger', // 定义切面
      useFactory: () => {
        // 定义切面的逻辑
        return new Logger('PrismaConnected');
      },
    },
  ],
  exports: [PrismaService], // Export the PrismaService so other modules can use it
})
export class PrismaModule {}

// 控制台打印
[Nest] 21972  - 2024/04/02 20:12:58     LOG [Main] server starting on http://localhost:3000/api
[Nest] 21972  - 2024/04/02 20:12:58     LOG [PrismaConnected] Connected to database
~~~

# 11. 用户与用户详情模型一对一关联：

~~~sql
model User {
  id Int @id @default(autoincrement())
  uuid String @default(uuid())
  email String @unique
  username String @unique
  password String
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt
  userProfile UserProfile?
}

model UserProfile {
  id Int @id @default(autoincrement())
  avatar String?
  phone String?
  status BigInt @default(1) // 1 = 登录中, 2 = 退出登录, 3 = 注销用户
  role BigInt @default(1) // 1 = 普通用户, 2 = 管理员
  ipAddress String? // 用户登录IP地址
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt
  // 用户与用户详情表关联
  user User @relation(fields: [userId], references: [id])
  userId Int @unique
}
~~~

~~~bash
# 执行SQL迁移
npx prisma migrate dev --name user_usersetting_onetoone
$ yes
~~~

# 12. 导入 RM 元数据：

```ts
// main.ts
// 导入 reflect-metadata 元数据，因为使用的是 RM 类型
import 'reflect-metadata';
```

# 13. swagger 接口文档：

```cmd
pnpm i @nestjs/swagger swagger-ui-express
```

```ts
// utils/swagger.ts
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

// 在main.ts中使用
async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  // 设置Swagger文档
  setSwaggerDocument(app);
  ...
}
bootstrap();
```

# 14. 创建 constant 常量：

```ts
// constant/iservices.ts
export enum IServices {
  IAUTH = 'IAUTH_SERVICE',
  IUSER = 'IUSER_SERVICE',
  IMINIO = 'IMINIO_SERVICE',
}

// index.ts
export * from './iservices';
```

# 15. 创建 IService 相关：

~~~bash
# 创建 两个模块 auth 、user
nest g res auth
nest g res user
~~~

~~~ts
// 新建 auth/auth.iservice.ts
export interface IAuthService {
  // 用户验证
  validateUser();
}

// 在 auth.service.ts 中实现 IAuthService
@Injectable()
export class AuthService implements IAuthService {
  validateUser() {}
}

// 在 auth.controller.ts 使用 IAuthService
@Controller(AuthRoutes.AUTH)
export class AuthController {
  constructor(@Inject(IServices.IAUTH) private authSerivce: IAuthService) {}
}

// 在 auth.module.ts 注入提供商 providers
@Module({
  controllers: [AuthController],
  // 配置服务提供者
  providers: [
    {
      // 注入IServices.IAUTH服务
      provide: IServices.IAUTH,
      // 使用AuthService类
      useClass: AuthService,
    },
  ],
})
export class AuthModule {}
~~~

# 16. auth服务模块中逻辑相关：

~~~ts
// 由于创建用户，登录用户中的逻辑是user模块中的，需要在user模块中编写还再导出并在auth模块中导入后使用
// 新建 user/user.iservice.ts
export interface IUserService {
  // 创建用户
  createUser(data: any): Promise<any>;
}

// user.module.ts
@Module({
  imports: [PrismaModule], // 导入其他模块
  controllers: [UserController],
  providers: [
    {
      provide: IServices.IUSER,
      useClass: UserService,
    },
  ],
  exports: [
    {
      provide: IServices.IUSER,
      useClass: UserService,
    },
  ],
})
export class UserModule {}
~~~

# 17. 密码加密：

~~~bash
pnpm i argon2
~~~

~~~ts
// utils/helper.ts
import * as argon2 from 'argon2';

interface Hash {
  password: string;
  email: string;
}

// 密码加密
export async function hashPassword(hash: Hash): Promise<string> {
  return await argon2.hash(hash.password, {
    type: argon2.argon2id,
    salt: Buffer.from(hash.email, 'utf-8'),
  });
}

// 匹配密码
export async function verifyPassword(hash: string, password: string) {
  return await argon2.verify(hash, password);
}

// user.service.ts
@Injectable()
export class UserService implements IUserService {
  constructor(private prisma: PrismaService) {}

  // 创建用户
  async createUser(data: Prisma.UserCreateInput) {
    // 查找邮箱和用户名是否已存在
    const user = await this.prisma.user.findUnique({
      where: { email: data.email, username: data.username },
    });
    if (!user) throw new NotFoundException('用户不存在');

    // 密码加密
    const hash = await hashPassword({
      password: data.password,
      email: data.email,
    });

    return this.prisma.user.create({
      data: {
        ...data,
        password: hash,
      },
    });
  }
}

// 在 auth.module.ts 导入 user模块
imports: [UserModule],
~~~

# 18. 创建数据传输对象 dtos：

~~~ts
// 创建dtos数据传输对象
// create-user.dto.ts
export class CreateUserDto {
  username: string;

  email: string;

  password: string;
}

// 添加管道验证
pnpm i class-validator class-transformer
// create-user.dto.ts
import { IsEmail, IsNotEmpty, IsString, Length } from 'class-validator';

export class RegisterDto {
  @IsNotEmpty()
  @IsString()
  username: string;

  @IsEmail()
  @IsNotEmpty()
  @IsString()
  email: string;

  @IsNotEmpty()
  @Length(6, 20)
  @IsString()
  password: string;
}

// 在 main.ts 全局注册管道校验
// 管道校验
  app.useGlobalPipes(new ValidationPipe());
~~~

# 19. 注册用户：

~~~ts
// auth.controller.ts
@Controller('auth')
export class AuthController {
  constructor(
    @Inject(IServices.IAUTH) private authSerivce: IAuthService,
    @Inject(IServices.IUSER) private userService: IUserService,
  ) {}

  @Post('register')
  @HttpCode(HttpStatus.OK)
  async register(@Body() registerDto: RegisterDto) {
    // 调用用户服务注册用户
    return await this.userService.createUser(registerDto);
  }
}
~~~

# 20. 登录用户：

~~~ts
// 查找用户用户邮箱
// user.iservice.ts
export interface IUserService {
  // 创建用户
  createUser(data: any): Promise<any>;
  // 查找用户邮箱
  findUserByEmail(data: any): Promise<any>;
}

// user.service.ts
// 查找用户邮箱
  async findUserByEmail(email: string) {
    return this.prisma.user.findUnique({ where: { email } });
  }

// auth.iservice.ts
export interface IAuthService {
  // 用户验证
  validateUser(data: any): Promise<any>;
}

// auth.service.ts
@Injectable()
export class AuthService implements IAuthService {
  constructor(
    @Inject(IServices.IUSER) private readonly userService: IUserService,
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

    return user;
  }
}

// auth/dtos/login.dto.ts
import { IsEmail, IsNotEmpty, IsString, Length } from 'class-validator';

export class LoginDto {
  @IsEmail()
  @IsNotEmpty()
  @IsString()
  email: string;

  @IsNotEmpty()
  @IsString()
  @Length(6, 20)
  password: string;
}

// auth.controller.ts
@Post('login')
  @HttpCode(HttpStatus.OK)
  async login(@Body() loginDto: LoginDto) {
    // 调用用户服务注册用户
    return await this.authSerivce.validateUser(loginDto);
  }
~~~

# 21. token生成：

~~~bash
pnpm i @nestjs/jwt
~~~

~~~bash
# .env
# jwt-access-token secret密钥
JWT_ACCESS_SECRET="jwt-access-c80b4b4c-0714-4c75-9600-cb03f04ea5c1"
# jwt-refresh-token secret密钥
JWT_REFRESH_SECRET="jwt-refresh-59fbac3c-5f22-42c4-aa4c-c119365f9593"
~~~

~~~ts
// 在user模块注入JwtModule.register({})，这里可以配置一些解析Json Web Token的相关属性，但我喜欢将其留空，到会面就晓得了
// auth.module.ts
@Module({
  imports: [
    UserModule,
    // Jwt服务
    JwtModule.register({}),
  ],
})

// 同时为 setTokens 定义返回的数据类型
// auth.types.ts
export type SetTokensData = {
  accessToken: string;
  refreshToken: string;
};

// auth.iservice.ts
// 制作token
  setTokens(id: number, email: string, role: number): Promise<SetTokensData>;
  
// 将 role 字段放在 User 模型中
// 执行新的迁移
npx prisma migrate dev --name role_to_user

// tokens
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
          expiresIn: 60 * 15, // 15分钟
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
~~~

# 22. 权限验证：

~~~bash
pnpm i @nestjs/passport passport passport-jwt
pnpm i @types/passport-jwt -D
~~~

~~~ts
// 修改用户信息
// 这个需要鉴权身份
// 创建auth/strategies，在其下新建index.ts统一导出文件，at.strategy.ts短时token策略，rt.strategy.ts长时token策略
// at.strategy.ts
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';

@Injectable() // 注入服务
export class AtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(configService: ConfigService) {
    super({
      // 简单来说就是提取token
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: configService.get('JWT_ACCESS_SECRET'), // 设置你的用来签署令牌的密钥
    });
  }

  // 验证函数,接收有效负载
  validate(payload: any) {
    console.log(payload);
    return payload;
  }
}

// rt.strategy.ts
import { Request } from 'express';
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
  validate(req: Request, payload: any) {
    const refreshToken = req.get('authorization').replace('Bearer ', '').trim();
    return {
      ...payload,
      refreshToken,
    };
  }
}

// index.ts
export * from './at.strategy';
export * from './rt.strategy';

// 为 payload 负载提供类型
export type JwtPayload = {
  sub: string;
  email: string;
  userRole: number;
};
export type JwtRefreshPayload = {
  sub: string;
};

// 在 auth.module.ts 提供注入
@Module({
  imports: [
    // 注入在当前作用域中注册的存储库
    TypeOrmModule.forFeature([Auth]),
    // 注入JWT模块
    JwtModule.register({}),
  ],

  controllers: [AuthController],
  providers: [
    {
      // 注入IServices.IAUTH服务
      provide: IServices.IAUTH,
      // 使用AuthService类
      useClass: AuthService,
    },
    AtStrategy,
    RtStrategy,
  ],
})
export class AuthModule {}

// 当前用户
  @Get('current')
  @UseGuards(AuthGuard('jwt'))
  @HttpCode(HttpStatus.OK)
  getTest(@Req() req: Request) {
    return req.user;
  }
~~~

# 23. 自定义守卫：

~~~ts
// 创建 auth/guards
// at.guard.ts
import { AuthGuard } from '@nestjs/passport';

export class AtGuard extends AuthGuard('jwt') {
  constructor() {
    super();
  }
}

// rt.guard.ts
import { AuthGuard } from '@nestjs/passport';

export class RtGuard extends AuthGuard('jwt-refresh') {
  constructor() {
    super();
  }
}

// index.ts
export * from './at.guard';
export * from './rt.guard';

// 在控制模块中使用将AuthGuard()替换
// 获取用户信息接口
  @UseGuards(AtGuard)
~~~

# 24. 自定义装饰器：

~~~ts
// 创建 auth/decorators
// 自定义个装饰器，用来获取当前用户
// current.decorator.ts，以便获取用户的 uuid即sub 和 email 和 userRole
import { ExecutionContext, createParamDecorator } from '@nestjs/common';

// 创建一个装饰器，用于获取当前用户
export const GetCurrentUser = createParamDecorator(
  (data: string | undefined, ctx: ExecutionContext) => {
    const request: Express.Request = ctx.switchToHttp().getRequest();
    if (data) return request.user[data];
    return request.user;
  },
);

// index.ts
export * from './current.decorator';

// 当前用户
  @Get('current')
  @UseGuards(AtGuard)
  @HttpCode(HttpStatus.OK)
  getTest(@GetCurrentUser() user: any, @GetCurrentUser('sub') id: number) {
    console.log('id', id);
    return user;
  }
~~~

# 25. 全局守卫：

~~~ts
// 除了jwt受AtGuard守卫保护，其他的路由可能也会收到保护，要是在每个路由上都添加AtGuard的话显得会很麻烦，这你可以设置全局守卫
// 在 at.guard.ts 提供注入装饰器 @Injectable() // 提供注入器，用于全局注入
// 将current上的@UseGuards(AtGuard)注释掉
// 这样所有的路由都需要访问令牌，但本地注册和登录是不需要的
// 创建个装饰器，指定啥啥啥路由是公开的
// decorators/public.decorator.ts
import { SetMetadata } from '@nestjs/common';

export const Public = () => SetMetadata('isPublic', true);

// 既然用Public了那得跟AtGuard说一声呀，不然它不知道
// at.guard.ts
@Injectable()
export class AtGuard extends AuthGuard('jwt') {
  constructor(private reflector: Reflector) {
    super();
  }
}

// 在 app.module.ts 全局提供去使用它
providers: [
    {
      provide: APP_GUARD,
      useClass: AtGuard,
    },
  ]

// 如果检测到isPublic元数据为true，绕过AtGuard，否则就激活AtGuard，因为在app.module.ts的providers中使用了它，需要在其用到 @Injectable() // 声明为注射器
// at.guard.ts
import { ExecutionContext, Injectable, NotFoundException } from '@nestjs/common';
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
~~~

# 26. 获取当前用户信息：

~~~ts
// auth.iservice.ts
// 获取当前用户
  getCurrent(email: string): Promise<any>;
  
// auth.service.ts
// 获取当前用户
  async getCurrent(email: string) {
    const user = await this.userService.findUserByEmail(email);
    delete user.password;
    return user;
  }
  
// autn.controller.ts
// 当前用户
  @Get('current')
  // @UseGuards(AtGuard)
  @HttpCode(HttpStatus.OK)
  getCurrent(@GetCurrentUser('email') email: string) {
    return this.authSerivce.getCurrent(email);
  }
~~~

# 27. 刷新权限：(展示用不上)

~~~ts
// 修改 rt.guard.ts 逻辑
import {
  ExecutionContext,
  ForbiddenException,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Request } from 'express';

export class RtGuard extends AuthGuard('jwt-refresh') {
  canActivate(context: ExecutionContext) {
    const request: Request = context.switchToHttp().getRequest();
    const authorization = request.headers.authorization;
    const token = authorization.split(' ')[1];
    // 判断用户是否登录
    if (!token) {
      throw new UnauthorizedException('用户未登录, 请先登录');
    }

    return super.canActivate(context);
  }

  handleRequest(err: any, user: any) {
    if (err || !user) {
      throw err || new ForbiddenException('登录过期, 请重新登录');
    }

    return user;
  }
}

// is.auth.ts
refreshToken(refreshToken: string);

// auth.service.ts
async refreshToken(refreshToken: string) {
    // 解析refreshToken
    const verify = await this.jwtService.verify(refreshToken, {
      secret: this.configService.get('JWT_REFRESH_SECRET'),
    });
    if (!verify) {
      throw new ForbiddenException('无效的刷新令牌');
    }

    const user = await this.userService.findUser({ uuid: verify.sub });
    if (!user) {
      throw new NotFoundException('用户不存在，请先注册');
    }

    const tokens = await this.getTokens(user.uuid, user.email, user.role);

    return {
      message: '刷新成功',
      tokens,
    };
  }

// auth.controller.ts
// 刷新token
  @Public()
  @Get('refresh')
  @UseGuards(RtGuard)
  async refreshToken(@GetCurrentUser('refreshToken') refreshToken: string) {
    return await this.authSerivce.refreshToken(refreshToken);
  }
~~~

# 28. 刷新tokens：

~~~ts
// auth.iservice.ts
// 刷新tokens
  refreshToken(refreshToken: string): Promise<any>;
  
// auth.service.ts
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
  
// auth.controller.ts
// 刷新token
  @Public()
  @Get('refresh')
  @HttpCode(HttpStatus.OK)
  refreshToken(@Query('refreshToken') refreshToken: string) {
    return this.authSerivce.refreshToken(refreshToken);
  }
~~~

# 29. 统一返回数据：（暂时不喜欢这样）

~~~ts
// 设置个全局的拦截器，拦截成功请求的结果，接着统一响应数据
// src/interceptor/success.interceptor.ts
import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';

export interface Response<T> {
  data: T;
}

@Injectable()
export class SuccessInterceptor<T> implements NestInterceptor<T, Response<T>> {
  intercept(
    context: ExecutionContext,
    next: CallHandler,
  ): Observable<Response<T>> {
    return next.handle().pipe(
      map((data) => {
        return {
          statusCode: 200,
          message: '请求成功',
          data,
          success: true,
        };
      }),
    );
  }
}

// 在 app模块中提供注入
// app.module.ts
@Module({
  ...
  providers: [
    ...
    {
      provide: APP_INTERCEPTOR,
      useClass: SuccessInterceptor,
    },
  ],
})
~~~

~~~ts
// 定义统一异常拦截器，返回统一异常拦截数据
// src/filter/http-exception.filter.ts
import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
} from '@nestjs/common';
import { Request, Response } from 'express';

@Catch(HttpException)
export class HttpExceptionFilter implements ExceptionFilter {
  catch(exception: HttpException, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();
    const status = exception.getStatus();

    response.status(status).json({
      statusCode: status,
      message: exception.message,
      timestamp: new Date().toISOString(),
      path: request.url,
      success: false,
    });
  }
}

// 在 app模块中提供注入
// app.module.ts
@Module({
  ...
  providers: [
    ...
    {
      provide: APP_FILTER,
      useClass: HttpExceptionFilter,
    },
  ],
})
~~~

# 30. 添加用户配置相关：

~~~ts
// 需要在登录的同时获取登录IP地址，通过后端获取用户id
// at.strategy.ts
import { Request } from 'express';
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

// user.iservice.ts
// 创建用户配置文件
  createUserProfile(id: number, data: any): Promise<any>;
  
// user.service.ts
// 创建用户配置文件
  async createUserProfile(id: number, data: Prisma.UserProfileCreateInput) {
    await this.prisma.userProfile.create({
      data: {
        ...data,
        user: {
          connect: { id },
        },
      },
    });
  }
  
// user.controller.ts
// 创建用户配置
  @Post('profile')
  @HttpCode(HttpStatus.OK)
  createUserProfile(
    @GetCurrentUser('sub') id: number,
    @Body() profileDto: ProfileDto,
  ) {
    return this.userSerivce.createUserProfile(id, profileDto);
  }

// 修改 UserProfile model
model UserProfile {
  id Int @id @default(autoincrement())
  avatar String? @db.Text
  phone String?
  status Int @default(1) // 1 = 登录中, 2 = 退出登录, 3 = 注销用户
  address Json?
  longitude Float?
  latitude Float?
  gender Int? // 1 = 男, 2 = 女, 3 = 保密
  birthday String?
  motto String? // 座右铭
  grade Int @default(0) // 等级
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt
  // 用户与用户详情关联
  user User @relation(fields: [userId], references: [id])
  userId Int @unique
}

// 执行迁移
npx prisma migrate dev --name update_userprofile
  
// profile.dto.ts
import { IsString, IsOptional, IsArray } from 'class-validator';

export class ProfileDto {
  @IsString()
  @IsOptional() // 非必传
  avatar?: string;

  @IsString()
  @IsOptional() // 非必传
  phone?: string;
  // gender: number;

  @IsString()
  @IsOptional() // 非必传
  status?: number;

  @IsArray()
  @IsOptional() // 非必传
  address?: string;

  @IsOptional()
  longitude?: number;

  @IsOptional()
  latitude?: number;

  @IsOptional()
  gender?: number;

  @IsString()
  @IsOptional()
  birthday?: string;

  @IsString()
  @IsOptional()
  motto?: string;

  @IsOptional()
  grade?: number;
}

// 获取当前用户信息
// user.service.ts
// 获取用户id
  async getUserById(id: number) {
    return this.prisma.user.findUnique({
      where: { id },
      include: { userProfile: true },
    });
  }

// auth.service.ts
// 获取当前用户
  async getCurrent(id: number) {
    const user = await this.userService.getUserById(id);
    delete user.password;
    return user;
  }
~~~

# 31. 更新用户配置文件：

~~~ts
// user.iservice.ts
// 更新用户配置文件
  updateUserProfile(id: number, data: any): Promise<any>;
  
// user.service.ts
// 更新用户配置文件
  async updateUserProfile(id: number, data: Prisma.UserProfileUpdateInput) {
    await this.prisma.userProfile.update({
      data,
      where: { userId: id },
    });
  }
  
// user.controller.ts
// 更新用户配置
  @Put('profile')
  @HttpCode(HttpStatus.OK)
  updateUserProfile(
    @GetCurrentUser('sub') id: number,
    @Body() profileDto: ProfileDto,
  ) {
    return this.userSerivce.updateUserProfile(id, profileDto);
  }
~~~

# 32. 用户头像：

```powershell
# 拉取镜像
docker pull minio/minio:latest
# 运行容器
docker run -d -p 9000:9000 -p 9001:9001 --name minio1 -v /mnt/data:/data -e "MINIO_ROOT_USER=minioadmin" -e "MINIO_ROOT_PASSWORD=minioadmin" minio/minio server /data --console-address ":9001"

docker run \
 --name minio \  #docker 镜像名称
  -p 9000:9000  \ #服务端口号
  -p 9001:9001  \ #映射端口号
  -d --restart=always \ #docker设置容器随系统开机启动 minio
  -e "MINIO_ACCESS_KEY=admin"  \ #登录用户名
  -e "MINIO_SECRET_KEY=123456"  \ #登录密码
  -v "/usr/local/minio/data":"/data" \  # 存储文件位置
  -v "/usr/local/minio/config":"/root/.minio"  \ # 配置文件位置
  minio/minio server /data --console-address ":9001"    #启动服务对外端口号 访问主机ip+9001 就能打开
```

```powershell
# 强制删除容器
docker rm -f 容器id

# 删除镜像
docker rmi 镜像id

# 新版有点高级来，试试旧版的
docker pull minio/minio:RELEASE.2021-06-17T00-10-46Z

# 查看所有镜像
docker images

# --restart=always 设置容器随系统开机启动 minio
# /usr/local/minio/data:/data 存储文件位置
# /usr/local/minio/config:/root/.minio 配置文件位置
docker run -p 9001:9000 --name minio -d --restart=always \
  -e "MINIO_ROOT_USER=minio" \
  -e "MINIO_ROOT_PASSWORD=minio123456" \
  -v /usr/local/minio/data:/data \
  -v /usr/local/minio/config:/root/.minio \
  minio/minio:RELEASE.2021-06-17T00-10-46Z server /data
  
docker run -d -p 9001:9000 --name minio-go-where \
  -e "MINIO_ROOT_USER=minio" \
  -e "MINIO_ROOT_PASSWORD=minio123456" \
  -v /e/Desktop/GoWhere/go-where-server/minio/data:/data \
  minio/minio:RELEASE.2021-06-17T00-10-46Z server /data
```

```bash
pnpm i minio
pnpm i -D @types/multer

# 创建 minio-client 模块
nest g res minio-client
```

~~~bash
# .env
# minio服务IP
MINIO_ENDPOINT="localhost"
# minio服务端口
MINIO_PORT=9001
# minio账号名
MINIO_ACCESS_KEY="minio"
# minio密码
MINIO_SECRET_KEY="minio123456"
# minio文件桶
MINIO_BUCKET="filepocket"
# minio头像文件桶
MINIO_AVATAR_BUCKET="avatar"
~~~

~~~ts
// 在 minio-client.module.ts 配置minio连接
@Global()
@Module({
  imports: [UserModule],
  providers: [MinioClientService],
  exports: [MinioClientService],
})
export class MinioClientModule {}


// minio-client 需要用到 user 模块，将其导入
imports: [
    。。。
    UserModule,
  ]

// minio-client.service.ts
// 上传用户头像
import * as crypto from 'node:crypto';
import * as Minio from 'minio';

@Injectable()
export class MinioClientService {
  @Inject(IServices.IUSER)
  private readonly userService: IUserService;
  private readonly client: Minio.Client;
  constructor(private readonly configService: ConfigService) {
    this.client = new Minio.Client({
      endPoint: this.configService.get('MINIO_ENDPOINT'),
      port: parseInt(this.configService.get('MINIO_PORT')),
      useSSL: false, // 默认是true
      accessKey: this.configService.get('MINIO_ACCESS_KEY'),
      secretKey: this.configService.get('MINIO_SECRET_KEY'),
    });
  }

  // 上传头像
  async uploadAvatar(
    id: number,
    file: Express.Multer.File,
    bucketName: string = this.configService.get('MINIO_AVATAR_BUCKET'),
  ) {
    const user = await this.userService.getUserById(id);

    // 获取文件名前缀
    const profix = file.originalname.split('.')[0];

    // 将文件名从latin1转换为utf8
    const filename = Buffer.from(profix, 'latin1').toString('utf8');

    // 使用md5加密文件名
    const hashedFilename = crypto
      .createHash('md5')
      .update(filename)
      .digest('hex');

    // 获取文件名后缀
    // const suffix = file.originalname.split('.')[1];
    const suffix = file.originalname.substring(
      file.originalname.lastIndexOf('.'),
      file.originalname.length,
    );

    // 获取当前时间
    const date = new Date().getTime();

    // 拼接文件名
    const fileName = `${hashedFilename}${suffix}`;

    // 获取文件内容
    const fileBuffer = file.buffer;

    await this.client.putObject(bucketName, fileName, fileBuffer, {
      'Content-Type': file.mimetype,
    });

    // 预览链接
    const avatarUrl = await this.client.presignedGetObject(
      bucketName,
      fileName,
    );

    try {
      if (!user.userProfile) {
        // 如果头像为空就调用创建
        await this.userService.createUserProfile(id, { avatar: avatarUrl });
      } else {
        const { avatar } = user.userProfile;
        if (avatar) {
          // 提取avatar中的文件名
          const avatarFileName = avatar.split('/').pop().split('?')[0];
          // 删除之前的头像
          await this.client.removeObject(bucketName, avatarFileName);
        }
        // 如果头像不为空就调用更新
        await this.userService.updateUserProfile(id, { avatar: avatarUrl });
      }
    } catch (e) {
      throw new ConflictException('上传失败, 请稍后再试');
    }

    return avatarUrl;
  }
}

// user.controller.ts
import { MinioClientService } from 'src/minio-client/minio-client.service';
import { FileInterceptor } from '@nestjs/platform-express';

@ApiTags('用户相关')
@Controller('user')
export class UserController {
  constructor(
    @Inject(MinioClientService)
    private readonly minioClientService: MinioClientService,
  ) {}

  // 上传用户头像
  @Post('upload/avatar')
  @UseInterceptors(FileInterceptor('file'))
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: '上传头像' })
  @ApiConsumes('multipart/form-data')
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        file: { type: 'string', format: 'binary', description: '文件' },
      },
    },
  })
  async uploadAvatar(
    @GetCurrentUser('sub') id: number,
    @UploadedFile() file: Express.Multer.File,
  ) {
    return await this.minioClientService.uploadAvatar(id, file);
  }
}
~~~



# 33. 格式化时间：

~~~bash
pnpm i moment
~~~

~~~ts
// helper.ts
import * as moment from 'moment';
export function formatDate(date: Date) {
  return moment(date).format('YYYY-MM-DD HH:mm:ss');
}
~~~

# 34. Redis 使用：

~~~bash
# 数据的缓存，key value 的形式
docker run -p 6379:6379 -v /e/Desktop/GoWhere/go-where-server/redis/data:/data --name redis-go-where -d redis --protected-mode no --appendonly yes --requirepass 12345678
# -p 6379:6379 映射端口
# --network doudou-sir 网关
# -v /home/doudo/Desktop/nest-study/learn/eight-day/nest-app/redis-data:/data 挂载数据目录
# --name redis 为容器命名
# -d redis redis-server /etc/redis/redis.conf 表示后台启动redis，以配置文件启动redis，加载容器内的conf文件
# --appendonly yes 开启redis 持久化
# --requirepass 123456 设置密码
# protected-mode no 默认yes，如果设置为yes，则只允许在本机的回环连接，其他机器无法连接

# 在终端中操作
redis-cli -a 12345678
# Warning: Using a password with '-a' or '-u' option on the command line interface may not be safe. 不用管
set dou good
# OK
get dou
# "good"
~~~

~~~bash
pnpm i redis
nest g mo redis
nest g s redis --no-spec
~~~

~~~ts
// redis.module.ts
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
        });
        await client.connect();
        // 监听连接成功
        client.on('connect', () => console.log('Redis Client Connected'));
        // 监听连接断开
        client.on('error', (err) => console.log('Redis Client Error', err));
        return client;
      },
    },
  ],
  exports: [RedisService],
})
export class RedisModule {}

// redis.service.ts
import { Inject, Injectable } from '@nestjs/common';
import { RedisClientType } from 'redis';

@Injectable()
export class RedisService {
  constructor(
    @Inject('REDIS_CLIENT')
    private readonly redisClient: RedisClientType,
  ) {}

  // 获取
  async get(key: string) {
    return await this.redisClient.get(key);
  }

  // 设置
  async set(key: string, value: string | number, ttl?: number) {
    await this.redisClient.set(key, value);

    if (ttl) {
      await this.redisClient.expire(key, ttl);
    }
  }
}
~~~

# 35. 邮箱发送验证码：

~~~bash
pnpm i nodemailer
pnpm i -D @types/nodemailer
nest g res email --no-spec
~~~

~~~ts
// email.service.ts
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Transporter, createTransport } from 'nodemailer';

@Injectable()
export class EmailService {
  transporter: Transporter;
  constructor(private configService: ConfigService) {
    this.transporter = createTransport({
      host: this.configService.get('SMTP_HOST'),
      port: +this.configService.get('SMTP_PORT'),
      auth: {
        user: this.configService.get('SMTP_USER'),
        pass: this.configService.get('SMTP_PASS'),
      },
    });
  }
  async sendMail({ to, subject, html }) {
    await this.transporter.sendMail({
      from: {
        name: '哪都通',
        address: this.configService.get('SMTP_USER'),
      }, // sender address
      to,
      subject,
      html,
    });
  }
}

// email.module.ts
@Global() // 全局模块
@Module({
  controllers: [EmailController],
  providers: [EmailService],
  exports: [EmailService], // 导出服务，以便在其他模块中使用
})
export class EmailModule {}

// auth.controller.ts
@ApiTags('auth用户权限')
@Controller('auth')
export class AuthController {
  constructor(
    @Inject(EmailService) private emailService: EmailService,
    @Inject(RedisService) private redisService: RedisService,
  ) {}
  @Public()
  @Get('captcha')
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
}

@Public()
  @Post('register')
  // @ApiOperation({ summary: '用户注册' })
  // @ApiBody({ type: RegisterDto })
  @HttpCode(HttpStatus.OK)
  async register(@Body() registerDto: RegisterDto) {
    const { email, captcha } = registerDto;
    const code = await this.redisService.get(`captcha_${email}`);
    if (!code) throw new ConflictException('验证码已过期，请重新发送');
    if (code !== captcha) throw new BadRequestException('验证码错误');
    // 调用用户服务注册用户
    return await this.userService.createUser(registerDto);
  }
~~~

# 36. 忘记密码：

~~~ts
// 忘记密码-通过邮箱验证-设置新密码
~~~

# 37. session 会话机制(用的话就不需要token了)：

~~~bash
$ pnpm i express-session
$ pnpm i -D @types/express-session
~~~

~~~bash
# 会话密钥
SESSION_SECRET="be7c6398-172d-4703-990f-c88d7949fc54"
~~~

~~~ts
// main.ts
// 设置session
  app.use(
    session({
      secret: SESSION_SECRET,
      saveUninitialized: false,
      resave: false,
      name: 'GO_WHERE_SESSION_ID',
      cookie: {
        maxAge: 86400000, // cookie expires 1 day later
      },
    }),
  );
  app.use(passport.initialize());
  app.use(passport.session());

// 在 app.module.ts 使用 PassportModule 模块，以便实现消费者之间的互通
imports: [
    // passport配置
    PassportModule.register({ session: true }),
  ]

// 创建会话序列化程序 serializer/session.serializer.ts
import { Inject, Injectable } from '@nestjs/common';
import { PassportSerializer } from '@nestjs/passport';
import { User } from '@prisma/client';
import { IServices } from 'src/constant';
import { IUserService } from 'src/user/user.iservice';

@Injectable()
export class SessionSerializer extends PassportSerializer {
  constructor(
    @Inject(IServices.IUSER)
    private readonly userService: IUserService,
  ) {
    super();
  }

  serializeUser(user: User, done: Function) {
    done(null, user.id);
  }

  async deserializeUser(user: User, done: Function) {
    const u = await this.userService.getUserById(user.id);
    return u ? done(null, u) : done(null, null);
  }
}

// auth.module.ts 提供注入会话序列化
providers: [
    // ...
    SessionSerializer,
  ]

// 你会发现不起作用，因为它需要通过本地的身份验证才可以
~~~

~~~bash
$ pnpm i passport-local
$ pnpm i @types/passport-local -D
~~~

~~~ts
// 新建本地策略文件 local.strategy.ts 
import { Inject, Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-local';
import { NotFoundException } from '@nestjs/common';
import { IServices } from 'src/constant';
import { IAuthService } from '../auth.iservice';

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
  constructor(
    @Inject(IServices.IAUTH) private readonly authService: IAuthService,
  ) {
    super();
  }

  async validate(email: string, password: string) {
    console.log(email, password);
    return this.authService.validateUser({ email, password });
  }
}

// local.guard.ts
import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class LocalAuthGuard extends AuthGuard('local') {
  async canActivate(context: ExecutionContext) {
    const result = (await super.canActivate(context)) as boolean;
    const request = context.switchToHttp().getRequest();
    await super.logIn(request);
    return result;
  }
}

@Injectable()
export class AuthenticatedGuard implements CanActivate {
  async canActivate(context: ExecutionContext): Promise<any> {
    const req = context.switchToHttp().getRequest();
    return req.isAuthenticated();
  }
}
~~~

