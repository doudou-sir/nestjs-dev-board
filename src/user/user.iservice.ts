export interface IUserService {
  // 创建用户
  createUser(data: any): Promise<any>;

  // 查找用户邮箱
  findUserByEmail(data: any): Promise<any>;

  // 通过ID获取用户
  getUserById(id: number): Promise<any>;

  // 创建用户配置文件
  createUserProfile(id: number, data: any): Promise<any>;

  // 更新用户配置文件
  updateUserProfile(id: number, data: any): Promise<any>;

  // 通过头像上传创建用户配置
  createUserProfileByAvatar(id: number, avatar: string): Promise<any>;

  // 通过头像上传更新用户配置
  updateUserProfileByAvatar(id: number, avatar: string): Promise<any>;
}
