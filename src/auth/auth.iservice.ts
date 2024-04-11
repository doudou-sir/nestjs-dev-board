import { SetTokensData } from './auth.types';

export interface IAuthService {
  // 用户验证
  validateUser(data: any): Promise<any>;

  // 制作token
  setTokens(id: number, email: string, role: number): Promise<SetTokensData>;

  // 获取当前用户
  getCurrent(id: number): Promise<any>;

  // 刷新tokens
  refreshToken(refreshToken: string): Promise<any>;
}
