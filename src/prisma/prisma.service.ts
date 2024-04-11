import { Inject, Injectable, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';
import { Logger } from '@nestjs/common';

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
