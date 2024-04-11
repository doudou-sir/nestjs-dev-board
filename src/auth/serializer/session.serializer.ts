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
    console.log('serializeUser', user);
    done(null, user);
  }

  async deserializeUser(user: User, done: Function) {
    const u = await this.userService.getUserById(user.id);
    return u ? done(null, u) : done(null, null);
  }
}
