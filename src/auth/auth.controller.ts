import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Query,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignupDto } from './dto/signup.dto';
import { LoginDto } from './dto/login.dto';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { VerifyEmailDto } from './dto/verify-email.dto';

@Controller('auth')
export class AuthController {
  constructor(private auth: AuthService) {}

  // Registro de usuario
  @Post('signup')
  async signup(@Body() dto: SignupDto) {
    return this.auth.signup(dto);
  }

  // Login de usuario
  @HttpCode(HttpStatus.OK)
  @Post('login')
  async login(
    @Body() dto: LoginDto,
    @Req() req: any,
    @Res({ passthrough: true }) res: any,
  ) {
    return this.auth.login(dto, req, res);
  }

  @Get('verify-email')
  async verifyEmail(@Query('token') q: VerifyEmailDto) {
    return this.auth.verifyEmail(q.token);
  }

 @Post('verify-email')
    async verifyEmailPost(@Body() dto: VerifyEmailDto) {
    return this.auth.verifyEmail(dto.token);
    }
    
  @HttpCode(HttpStatus.OK)
  @Post('refresh')
  async refresh(@Req() req: any, @Res({ passthrough: true }) res: any) {
    return this.auth.refresh(req, res);
  }

  @HttpCode(HttpStatus.OK)
  @Post('logout')
  async logout(@Req() req: any, @Res({ passthrough: true }) res: any) {
    return this.auth.logout(req, res);
  }

  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  @Post('logout-all')
  async logoutAll(@Req() req: any, @Res({ passthrough: true }) res: any) {
    return this.auth.logoutAll(req.user.sub, res);
  }

  @UseGuards(JwtAuthGuard)
  @Get('check')
  health() {
    return { ok: true };
  }
}
