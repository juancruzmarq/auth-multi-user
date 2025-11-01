import { Controller, Get, Req, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from 'src/common/guards/jwt-auth.guard';

@Controller('me')
export class UserController {
  @UseGuards(JwtAuthGuard)
  @Get()
  me(@Req() req: any) {
    return req.user;
  }
}
