import { Inject, Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-local';
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
