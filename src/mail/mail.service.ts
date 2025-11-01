import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { randomBytes, createHash } from 'crypto';
import { addHours } from 'date-fns';
import { Cron, CronExpression } from '@nestjs/schedule';
import { MailStatus, MailType } from 'generated/prisma/enums';
import { MailerService } from '@nestjs-modules/mailer';

@Injectable()
export class MailService {
  private readonly logger: Logger = new Logger(MailService.name);
  constructor(
    private prisma: PrismaService,
    private mailer: MailerService,
  ) {}

  /**
   * Crea un token de verificación, lo asocia al usuario y genera el registro en MailOutbox.
   */
  async createVerificationEmail(userId: string, email: string) {
    // token plano (se enviará por email)
    const plainToken = randomBytes(32).toString('hex');
    const tokenHash = createHash('sha256').update(plainToken).digest('hex');

    // vence en 24 horas
    const expiresAt = addHours(new Date(), 24);

    // se guarda el token de verificación
    await this.prisma.verificationToken.create({
      data: {
        id_user: userId,
        purpose: 'EMAIL_VERIFICATION',
        token_hash: tokenHash,
        expires_at: expiresAt,
      },
    });

    // se genera el mail pendiente
    await this.prisma.mailOutbox.create({
      data: {
        id_user: userId,
        to: email,
        subject: 'Verifica tu cuenta',
        type: MailType.VERIFY_EMAIL,
        template: 'verify-email',
        payload: {
          token: plainToken,
          name: email,
          verificationUrl: `${process.env.APP_FRONTEND_URL}/verify?token=${plainToken}`,
          year: new Date().getFullYear(),
          appName: process.env.APP_NAME,
        },
      },
    });
  }

  /**
   * Crear un mail de restablecimiento de contraseña
   */
  async createPasswordResetEmail(userId: string, email: string) {
    // token plano (se enviará por email)
    const plainToken = randomBytes(32).toString('hex');
    const tokenHash = createHash('sha256').update(plainToken).digest('hex');

    // vence en 1 hora
    const expiresAt = addHours(new Date(), 1);

    // se guarda el token de restablecimiento
    await this.prisma.verificationToken.create({
      data: {
        id_user: userId,
        purpose: 'PASSWORD_RESET',
        token_hash: tokenHash,
        expires_at: expiresAt,
      },
    });

    // se genera el mail pendiente
    await this.prisma.mailOutbox.create({
      data: {
        id_user: userId,
        to: email,
        subject: 'Restablece tu contraseña',
        type: MailType.PASSWORD_RESET,
        template: 'reset-password',
        payload: {
          token: plainToken,
          name: email,
          resetUrl: `${process.env.APP_FRONTEND_URL}/reset-password?token=${plainToken}`,
          year: new Date().getFullYear(),
          appName: process.env.APP_NAME,
        },
      },
    });
  }
  /**
   * Cron job que procesa mails pendientes cada 5 segundos.
   */
  @Cron(CronExpression.EVERY_5_SECONDS)
  async processMails() {
    const pendings = await this.prisma.mailOutbox.findMany({
      where: { status: MailStatus.PENDING },
      take: 10, // procesar en lotes de 10, en un futuro se puede poner una variable de entorno
    });
    if (pendings.length === 0) return;

    // Separar por casos de accion segun el tipo de mail WELCOME_EMAIL | PASSWORD_RESET | VERIFY_EMAIL | NOTIFICATION
    for (const mail of pendings) {
      try {
        await this.prisma.mailOutbox.update({
          where: { id_mail_outbox: mail.id_mail_outbox },
          data: { status: MailStatus.SENDING },
        });

        await this.dispatch(mail);

        // Actualizar estado a SENT
        await this.prisma.mailOutbox.update({
          where: { id_mail_outbox: mail.id_mail_outbox },
          data: {
            status: MailStatus.SENT,
            sent_at: new Date(),
            last_error: null,
          },
        });
      } catch (error) {
        // Actualizar estado a FAILED
        await this.prisma.mailOutbox.update({
          where: { id_mail_outbox: mail.id_mail_outbox },
          data: {
            status: MailStatus.FAILED,
            retry: { increment: 1 },
            last_error: (error as Error).message,
          },
        });
      }
    }
  }

  private async dispatch(mail: {
    to: string;
    subject: string;
    type: MailType;
    payload: any;
    template: string | null;
  }) {
    this.logger.log(`Enviando mail tipo ${mail.type} a ${mail.to}`);
    try {
      switch (mail.type) {
        case MailType.VERIFY_EMAIL:
          await this.mailer.sendMail({
            to: mail.to,
            subject: mail.subject || 'Verificá tu cuenta',
            from: process.env.MAIL_FROM,
            template: mail.template || 'verify-email',
            context: mail.payload || {},
          });
          this.logger.log(`Mail de verificación enviado a ${mail.to}`);
          return;
        case MailType.WELCOME_EMAIL:
          await this.mailer.sendMail({
            to: mail.to,
            subject: mail.subject || '¡Bienvenido!',
            from: process.env.MAIL_FROM,
            template: mail.template || 'welcome-email',
            context: mail.payload || {},
          });
          this.logger.log(`Mail de bienvenida enviado a ${mail.to}`);
          return;
        case MailType.PASSWORD_RESET:
          await this.mailer.sendMail({
            to: mail.to,
            subject: mail.subject || 'Restablecé tu contraseña',
            template: mail.template || 'reset-password',
            from: process.env.MAIL_FROM,
            context: mail.payload || {},
          });
          this.logger.log(`Mail de restablecimiento enviado a ${mail.to}`);
          return;
        case MailType.NOTIFICATION:
          await this.mailer.sendMail({
            to: mail.to,
            subject: mail.subject || 'Notificación',
            template: mail.template || 'notification',
            from: process.env.MAIL_FROM,
            context: mail.payload || {},
          });
          this.logger.log(`Mail de notificación enviado a ${mail.to}`);
          return;
        default:
          // fallback: si no hay template, podés enviar como texto plano
          await this.mailer.sendMail({
            to: mail.to,
            subject: mail.subject || 'Mensaje',
            from: process.env.MAIL_FROM,
            text: JSON.stringify(mail.payload ?? {}),
          });
          this.logger.log(`Mail genérico enviado a ${mail.to}`);
          return;
      }
    } catch (error) {
      this.logger.error(
        `Error enviando mail a ${mail.to}: ${(error as Error).message}`,
      );
      throw error;
    }
  }
}
