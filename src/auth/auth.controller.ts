import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignupDto } from './dto/signup.dto';
import { LoginDto } from './dto/login.dto';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { VerifyEmailDto } from './dto/verify-email.dto';
import { AuthGuard } from '@nestjs/passport';

@Controller('auth')
export class AuthController {
  constructor(private auth: AuthService) {}

  @Get('google')
  @UseGuards(AuthGuard('google'))
  googleAuth() {
    // Passport redirige a Google
  }

  @Get('google/callback')
  @UseGuards(AuthGuard('google'))
  async googleCallback(@Req() req: any, @Res({ passthrough: true }) res: any) {
    // req.user viene del validate() de la strategy
    const { access_token, user } = await this.auth.oauthLogin(
      'GOOGLE',
      req.user,
      req,
      res,
    );

    // Podés redirigir al front con el token en fragment/param si querés
    // return res.redirect(`${process.env.APP_FRONTEND_URL}/auth/cb#access=${access_token}`);
    return { access_token, user };
  }

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
    return await this.auth.login(dto, req, res);
  }

  @Post('verify-email')
  async verifyEmailPost(@Body() dto: VerifyEmailDto) {
    return await this.auth.verifyEmail(dto.token);
  }

  @Post('reset-password-request')
  async resetPasswordRequest(
    @Body('email') email: string,
  ): Promise<{ message: string }> {
    return await this.auth.resetPasswordRequest(email);
  }

  @Post('reset-password')
  async resetPassword(
    @Body('token') token: string,
    @Body('password') newPassword: string,
  ): Promise<{ message: string }> {
    return await this.auth.resetPassword(token, newPassword);
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
