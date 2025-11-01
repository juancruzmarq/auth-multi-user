// nestjs imports
import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  Logger,
  HttpStatus,
} from '@nestjs/common';

// Third dependencies imports
import { Response } from 'express';

// Local imports
import { ThrottlerException } from '@nestjs/throttler';
import { Status } from '../types/response.type';

@Catch(HttpException, ThrottlerException)
export class HttpExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(HttpExceptionFilter.name);

  catch(exception: any, host: ArgumentsHost) {
    try {
      const ctx = host.switchToHttp();
      const response = ctx.getResponse<Response>();
      const request = ctx.getRequest<Request>();
      const message = exception.message || 'Internal server error';
      let status = exception.getStatus ? exception.getStatus() : 500;

      // Console log de la excepción
      this.logger.error(
        `${status} ${request.method} ${request.url} error: ${message}`,
      );

      // If the exception is a ThrottlerException, respond with the standard format
      if (exception instanceof ThrottlerException) {
        status = HttpStatus.TOO_MANY_REQUESTS;

        response.status(status).json({
          status: Status.ERROR,
          data: null,
          message: 'Too many requests',
        });
      }

      // If the exception is an HttpException, respond with the standard format
      if (exception instanceof HttpException && exception.getResponse) {
        const errorResponse = exception.getResponse() as any;

        if (typeof errorResponse.message === 'string') {
          status = exception.getStatus();
        } else if (errorResponse.message?.length > 0) {
          // If the exception is a validation exception
          response.status(HttpStatus.NOT_FOUND).json({
            status: Status.ERROR,
            data: null,
            message: 'Validation error',
            errors: errorResponse.message,
          });

          return;
        }
      }

      // Respond with the standard format
      response.status(status).json({
        status: Status.ERROR,
        data: null,
        message: message,
      });
    } catch (error) {
      this.logger.error(`Error on catch exception: ${error}`);
    }
  }
}
