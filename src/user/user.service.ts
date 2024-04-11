import { ConflictException, Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { PrismaService } from 'src/prisma/prisma.service';
import { IUserService } from './user.iservice';
import { hashPassword } from 'src/utils';

@Injectable()
export class UserService implements IUserService {
  constructor(private prisma: PrismaService) {}

  // 创建用户
  async createUser(data: Prisma.UserCreateInput) {
    // 查找邮箱和用户名是否已存在
    const email = await this.prisma.user.findUnique({
      where: { email: data.email },
    });
    const username = await this.prisma.user.findUnique({
      where: { username: data.username },
    });
    if (email || username) throw new ConflictException('用户已存在');

    // 密码加密
    const hash = await hashPassword({
      password: data.password,
      email: data.email,
    });

    await this.prisma.user.create({
      data: {
        ...data,
        password: hash,
      },
    });
  }

  // 查找用户邮箱
  async findUserByEmail(email: string) {
    return this.prisma.user.findUnique({ where: { email } });
  }

  // 获取用户id
  async getUserById(id: number) {
    return this.prisma.user.findUnique({
      where: { id },
      include: { userProfile: true },
    });
  }

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

  // 更新用户配置文件
  async updateUserProfile(id: number, data: Prisma.UserProfileUpdateInput) {
    await this.prisma.userProfile.update({
      data,
      where: { userId: id },
    });
  }

  // 通过头像上传创建用户配置
  async createUserProfileByAvatar(id: number, avatar: string) {
    await this.prisma.userProfile.create({
      data: {
        avatar,
        user: {
          connect: { id },
        },
      },
    });
  }

  // 通过头像上传更新用户配置
  async updateUserProfileByAvatar(id: number, avatar: string) {
    await this.prisma.userProfile.update({
      data: {
        avatar,
      },
      where: { userId: id },
    });
  }

  // // 获取用户列表
  // async getUsers() {
  //   return this.prisma.user.findMany();
  // }

  // // 获取单个用户
  // async getUserById(id: number) {
  //   return this.prisma.user.findUnique({ where: { id } });
  // }

  // // 更新用户
  // async updateUserById(id: number, data: any) {
  //   return this.prisma.user.update({ where: { id }, data });
  // }

  // // 删除用户
  // async deleteUserById(id: number) {
  //   return this.prisma.user.delete({ where: { id } });
  // }
}
