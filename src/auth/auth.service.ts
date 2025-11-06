// src/auth/auth.service.ts
import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import {
  hashPassword,
  verifyPassword,
  hashTokenStable,
} from '../common/utils/crypto.util';
import { JwtService } from '@nestjs/jwt';
import { addDays } from 'date-fns';
import { randomBytes } from 'crypto';
import { UserService } from '../user/user.service';
import { AuthProvider, MailStatus, UserStatus } from 'generated/prisma/enums';
import { MailService } from 'src/mail/mail.service';
import { createHash } from 'crypto';
import { errorHandler } from 'src/common/utils/error.handler';
import { Config, isProduction } from 'src/common/config';
import { ConfigService } from '@nestjs/config';

type GooglePayload = {
  provider: 'GOOGLE';
  id_provider: string;
  email: string | null;
  email_verified: boolean;
  name: string;
  photo_url: string | null;
  oauth?: { accessToken: string; refreshToken: string };
};

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  // Config
  private accessTTLsec: number;
  private refreshTTLDays: number;
  private pepper: string;
  private rtCookie: string;
  private sameSite: string;
  private cookieDomain: string | undefined;

  constructor(
    private prisma: PrismaService,
    private users: UserService,
    private jwt: JwtService,
    private mailService: MailService,
    private config: ConfigService,
  ) {
    this.accessTTLsec = Number(
      this.config.get<string>(Config.ACCESS_TOKEN_TTL) || 900,
    );
    this.refreshTTLDays = Number(
      this.config.get<string>(Config.REFRESH_TOKEN_TTL) || 30,
    );
    this.pepper =
      this.config.get<string>(Config.TOKEN_HASH_PEPPER) || 'default_pepper';
    this.rtCookie =
      this.config.get<string>(Config.REFRESH_COOKIE_NAME) || 'refresh_token';
    this.sameSite = this.config.get<string>(Config.COOKIE_SAMESITE) || 'lax';
    this.cookieDomain =
      this.config.get<string>(Config.COOKIE_DOMAIN) || undefined;
  }

  // Helpers
  // Funciones para firmar y manejar tokens y cookies
  private signAccess(sub: string, email: string) {
    return this.jwt.sign(
      { sub, email },
      { secret: process.env.JWT_ACCESS_SECRET!, expiresIn: this.accessTTLsec },
    );
  }
  // Función para firmar refresh tokens
  private signRefresh(sub: string) {
    return this.jwt.sign(
      { sub, typ: 'refresh', jti: randomBytes(12).toString('hex') },
      {
        secret: process.env.JWT_REFRESH_SECRET!,
        expiresIn: `${this.refreshTTLDays}d`,
      },
    );
  }

  // Funciones para manejar la cookie del refresh token
  private setRefreshCookie(res: any, token: string) {
    res.cookie(this.rtCookie, token, {
      httpOnly: true,
      secure: isProduction,
      sameSite: this.sameSite,
      domain: this.cookieDomain,
      maxAge: this.refreshTTLDays * 24 * 60 * 60 * 1000, // en ms
      path: '/auth', // Se envía solo en /auth/*
    });
  }
  private clearRefreshCookie(res: any) {
    res.clearCookie(this.rtCookie, {
      httpOnly: true,
      secure: process.env.COOKIE_SECURE === 'true',
      sameSite: this.sameSite,
      domain: this.cookieDomain,
      path: '/auth', // Mismo path que al setear
    });
  }

  // GOOGLE

  async oauthLogin(
    provider: 'GOOGLE',
    payload: GooglePayload,
    req: any,
    res: any,
  ) {
    // 1) ¿Existe Account por provider/id_provider?
    let account = await this.prisma.account.findUnique({
      where: {
        provider_id_provider: {
          provider: AuthProvider.GOOGLE,
          id_provider: payload.id_provider,
        },
      },
      include: { user: true },
    });

    let user = account?.user ?? null;

    // 2) Si no hay Account:
    if (!account) {
      // Buscar por email para “linkear” si ya se registró por email/password
      if (payload.email) {
        user = await this.users.findByEmail(payload.email);
      }

      // Crear user si no existe
      if (!user) {
        user = await this.prisma.user.create({
          data: {
            email: payload.email ?? `${payload.id_provider}@google.local`, // fallback si Google no da email (raro)
            name: payload.name,
            photo_url: payload.photo_url ?? undefined,
            status: UserStatus.ACTIVE,
            email_verified: !!payload.email_verified,
            email_verified_at: payload.email_verified ? new Date() : null,
          },
        });
        // Enviar mail de bienvenida si el email fue verificado por Google
        if (payload.email_verified && payload.email) {
          await this.mailService.createWelcomeEmail(
            user.id_user,
            payload.email,
            payload.name,
          );
        }
      } else {
        // Si ya existía y Google verifica el email, actualizá flags
        if (payload.email_verified && !user.email_verified) {
          user = await this.prisma.user.update({
            where: { id_user: user.id_user },
            data: {
              email_verified: true,
              email_verified_at: new Date(),
              status: UserStatus.ACTIVE,
            },
          });
        }
      }

      // Crear/adjuntar Account
      account = await this.prisma.account.create({
        data: {
          id_user: user.id_user,
          provider: AuthProvider.GOOGLE,
          id_provider: payload.id_provider,
          email: payload.email ?? undefined,
          access_token: payload.oauth?.accessToken ?? undefined,
          refresh_token: payload.oauth?.refreshToken ?? undefined,
        },
        include: { user: true },
      });
    }

    // 3) Emitir tokens y crear sesión (igual que tu login())
    const access = this.signAccess(user!.id_user, user!.email);
    const refresh = this.signRefresh(user!.id_user);

    await this.prisma.session.create({
      data: {
        id_user: user!.id_user,
        refresh_token_hash: hashTokenStable(refresh, this.pepper),
        user_agent: req.headers['user-agent'],
        ip: (req.ip || '').toString(),
        expires_at: addDays(new Date(), this.refreshTTLDays),
      },
    });

    this.setRefreshCookie(res, refresh);

    return {
      access_token: access,
      user: {
        id_user: user!.id_user,
        email: user!.email,
        name: user!.name,
        photo_url: user!.photo_url,
      },
    };
  }

  // SIGNUP
  async signup(dto: { email: string; password: string; name: string }) {
    const exists = await this.users.findByEmail(dto.email);
    if (exists) throw new BadRequestException('Email already in use');

    const user = await this.prisma.$transaction(async (tx) => {
      const u = await tx.user.create({
        data: {
          email: dto.email,
          name: dto.name,
          status: UserStatus.PENDING,
        },
      });
      // Se crea credencial
      await tx.credential.create({
        data: {
          id_user: u.id_user,
          password_hash: await hashPassword(dto.password),
          algo: 'bcrypt',
        },
      });
      return u;
    });

    await this.mailService.createVerificationEmail(user.id_user, user.email);

    return {
      message: 'User created. Please verify your email.',
      user_id: user.id_user,
    };
  }

  // LOGIN
  async login(dto: { email: string; password: string }, req: any, res: any) {
    const user = await this.users.findByEmail(dto.email);
    if (!user) throw new UnauthorizedException('Invalid credentials');

    if (user.status === 'SUSPENDED')
      throw new ForbiddenException('Account suspended');
    if (!user.email_verified)
      throw new ForbiddenException('Email not verified');

    const cred = await this.prisma.credential.findUnique({
      where: { id_user: user.id_user },
    });
    if (!cred || !(await verifyPassword(cred.password_hash, dto.password))) {
      // opcional: registrar LOGIN_FAILURE
      throw new UnauthorizedException('Invalid credentials');
    }

    const access = this.signAccess(user.id_user, user.email);
    const refresh = this.signRefresh(user.id_user);

    const rtHash = hashTokenStable(refresh, this.pepper);
    await this.prisma.session.create({
      data: {
        id_user: user.id_user,
        refresh_token_hash: rtHash,
        user_agent: req.headers['user-agent'],
        ip: (req.ip || '').toString(),
        expires_at: addDays(new Date(), this.refreshTTLDays),
      },
    });

    this.setRefreshCookie(res, refresh);
    return {
      access_token: access,
      user: { id_user: user.id_user, email: user.email, name: user.name },
    };
  }

  async verifyEmail(plainToken: string) {
    const tokenHash = createHash('sha256').update(plainToken).digest('hex');

    // Buscar token por hash (asegurate que token_hash sea UNIQUE)
    const vt = await this.prisma.verificationToken.findUnique({
      where: { token_hash: tokenHash },
    });
    if (!vt || vt.expires_at < new Date()) {
      throw new BadRequestException('Invalid or expired token');
    }

    // Activar usuario y borrar token en una transacción
    await this.prisma.$transaction(async (tx) => {
      await tx.user.update({
        where: { id_user: vt.id_user },
        data: {
          email_verified: true,
          email_verified_at: new Date(),
          status: UserStatus.ACTIVE,
        },
      });

      await tx.verificationToken.delete({ where: { id: vt.id } });

      // (Opcional) Encolar un mail de bienvenida
      const u = await tx.user.findUnique({
        where: { id_user: vt.id_user },
        select: { email: true, name: true },
      });
      await tx.mailOutbox.create({
        data: {
          id_user: vt.id_user,
          to: u!.email,
          subject: '¡Bienvenido!',
          type: 'WELCOME_EMAIL' as any, // o MailType.WELCOME_EMAIL si lo tenés
          template: 'welcome-email', // si usás templates
          payload: {
            name: u?.name ?? '',
            appName: process.env.APP_NAME,
            year: new Date().getFullYear(),
            appUrl: process.env.APP_FRONTEND_URL,
          },
          status: MailStatus.PENDING,
        },
      });
    });

    return { message: 'Email verified successfully' };
  }

  // Reset password request
  async resetPasswordRequest(email: string): Promise<{ message: string }> {
    const user = await this.users.findByEmail(email);
    if (!user) {
      // No revelar si el email existe o no
      return {
        message: 'If that email is registered, a reset link has been sent.',
      };
    }

    await this.mailService.createPasswordResetEmail(user.id_user, user.email);

    return {
      message: 'If that email is registered, a reset link has been sent.',
    };
  }

  // Reset password
  async resetPassword(
    token: string,
    newPassword: string,
  ): Promise<{ message: string }> {
    const tokenHash = createHash('sha256').update(token).digest('hex');

    const vt = await this.prisma.verificationToken.findUnique({
      where: { token_hash: tokenHash },
    });
    if (!vt || vt.expires_at < new Date() || vt.purpose !== 'PASSWORD_RESET') {
      throw new BadRequestException('Invalid or expired token');
    }

    const newHashedPassword = await hashPassword(newPassword);

    await this.prisma.$transaction(async (tx) => {
      await tx.credential.updateMany({
        where: { id_user: vt.id_user },
        data: { password_hash: newHashedPassword, algo: 'bcrypt' },
      });

      await tx.verificationToken.delete({ where: { id: vt.id } });
    });
    this.logger.log(`Password reset for user ID: ${vt.id_user}`);
    return { message: 'Password has been reset successfully' };
  }

  // REFRESH con rotación y reuse detection
  async refresh(req: any, res: any) {
    const token: string | undefined = req.cookies?.[this.rtCookie];
    if (!token) throw new UnauthorizedException('Missing refresh token');

    let payload: any;
    try {
      payload = this.jwt.verify(token, {
        secret: process.env.JWT_REFRESH_SECRET!,
      });
    } catch (error) {
      throw errorHandler(this.logger, error, 'Invalid refresh token');
    }

    const hashed = hashTokenStable(token, this.pepper);
    const session = await this.prisma.session.findFirst({
      where: {
        id_user: payload.sub,
        refresh_token_hash: hashed,
        revoked_at: null,
      },
    });

    if (!session) {
      // reuse detection → revoco todo
      await this.prisma.session.updateMany({
        where: { id_user: payload.sub, revoked_at: null },
        data: { revoked_at: new Date() },
      });
      this.clearRefreshCookie(res);
      throw new UnauthorizedException('Session invalidated');
    }

    // rotar
    const newRefresh = this.signRefresh(payload.sub);
    const newAccess = this.signAccess(
      payload.sub,
      (await this.users.findById(payload.sub))!.email,
    );
    await this.prisma.session.update({
      where: { id_session: session.id_session },
      data: {
        refresh_token_hash: hashTokenStable(newRefresh, this.pepper),
        expires_at: addDays(new Date(), this.refreshTTLDays),
      },
    });

    this.setRefreshCookie(res, newRefresh);
    return { access_token: newAccess };
  }

  // LOGOUT actual
  async logout(req: any, res: any) {
    const token: string | undefined = req.cookies?.[this.rtCookie];
    if (token) {
      const payload: any = this.jwt.decode(token);
      if (payload?.sub) {
        await this.prisma.session.updateMany({
          where: {
            id_user: payload.sub,
            refresh_token_hash: hashTokenStable(token, this.pepper),
            revoked_at: null,
          },
          data: { revoked_at: new Date() },
        });
      }
    }
    this.clearRefreshCookie(res);
    return { message: 'Logged out' };
  }

  // LOGOUT ALL devices
  async logoutAll(userId: string, res: any) {
    await this.prisma.session.updateMany({
      where: { id_user: userId, revoked_at: null },
      data: { revoked_at: new Date() },
    });
    this.clearRefreshCookie(res);
    return { message: 'All sessions revoked' };
  }

  // Validar access token (usado en JwtStrategy)
  async validateUser(userId: string) {
    const user = await this.users.findById(userId);
    if (user && user.status === UserStatus.ACTIVE) {
      return this.users.publicUser(user);
    }
    return null;
  }
}
