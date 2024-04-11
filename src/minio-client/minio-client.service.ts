import { ConflictException, Inject, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { IServices } from 'src/constant';
import { IUserService } from 'src/user/user.iservice';
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
