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
