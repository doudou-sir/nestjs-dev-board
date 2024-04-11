import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Inject,
  Post,
  Put,
  UploadedFile,
  UseInterceptors,
} from '@nestjs/common';
import { IServices } from 'src/constant';
import { IUserService } from './user.iservice';
import { ApiBody, ApiConsumes, ApiOperation, ApiTags } from '@nestjs/swagger';
import { GetCurrentUser } from 'src/auth/decorators';
import { ProfileDto } from './dtos';
import { MinioClientService } from 'src/minio-client/minio-client.service';
import { FileInterceptor } from '@nestjs/platform-express';

@ApiTags('用户相关')
@Controller('user')
export class UserController {
  constructor(
    @Inject(IServices.IUSER)
    private userSerivce: IUserService,
    @Inject(MinioClientService)
    private readonly minioClientService: MinioClientService,
  ) {}

  // 创建用户配置
  @Post('profile')
  @HttpCode(HttpStatus.OK)
  createUserProfile(
    @GetCurrentUser('sub') id: number,
    @Body() profileDto: ProfileDto,
  ) {
    return this.userSerivce.createUserProfile(id, profileDto);
  }

  // 更新用户配置
  @Put('profile')
  @HttpCode(HttpStatus.OK)
  updateUserProfile(
    @GetCurrentUser('sub') id: number,
    @Body() profileDto: ProfileDto,
  ) {
    return this.userSerivce.updateUserProfile(id, profileDto);
  }

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

  // @Post('create')
  // createUser(@Body() createUserDto: CreateUserDto) {
  //   return this.userService.createUser(createUserDto);
  // }

  // @Get('finds')
  // getUsers() {
  //   return this.userService.getUsers();
  // }
}
