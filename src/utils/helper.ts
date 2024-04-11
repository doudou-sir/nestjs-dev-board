import * as argon2 from 'argon2';
import * as moment from 'moment';

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

export function formatDate(date: Date) {
  return moment(date).format('YYYY-MM-DD HH:mm:ss');
}
