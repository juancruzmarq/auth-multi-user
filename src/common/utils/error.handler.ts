import { HttpException, HttpStatus, Logger } from '@nestjs/common';

export const errorHandler = (
  logger: Logger,
  error: any,
  message: string,
): HttpException => {
  logger.error(error);
  if (error instanceof HttpException) {
    throw error;
  }

  throw new HttpException(message, HttpStatus.INTERNAL_SERVER_ERROR);
};
