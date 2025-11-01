import { Injectable } from '@nestjs/common';
import { UserStatus } from 'generated/prisma/enums';
import { PrismaService } from 'src/prisma/prisma.service';

@Injectable()
export class UserService {
  constructor(private readonly prismaService: PrismaService) {}

  findByEmail(email: string) {
    return this.prismaService.user.findUnique({ where: { email } });
  }

  findById(id: string) {
    return this.prismaService.user.findUnique({ where: { id_user: id } });
  }

  async createUser(email: string, name?: string) {
    return this.prismaService.user.create({
      data: {
        email,
        name: name,
      },
    });
  }

  async setActiveVerified(id_user: string) {
    return await this.prismaService.user.update({
      where: { id_user },
      data: {
        status: UserStatus.ACTIVE,
        email_verified: true,
        email_verified_at: new Date(),
      },
    });
  }

  publicUser(user: any) {
    if (!user) return null;
    const { password_hash, ...rest } = user;
    return rest;
  }
}
