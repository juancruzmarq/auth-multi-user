/*
  Warnings:

  - The `status` column on the `mail_outbox` table would be dropped and recreated. This will lead to data loss if there is data in the column.

*/
-- CreateEnum
CREATE TYPE "MailStatus" AS ENUM ('PENDING', 'SENT', 'FAILED');

-- CreateEnum
CREATE TYPE "MailType" AS ENUM ('WELCOME_EMAIL', 'PASSWORD_RESET', 'VERIFY_EMAIL', 'NOTIFICATION');

-- AlterTable
ALTER TABLE "mail_outbox" ADD COLUMN     "type" "MailType" NOT NULL DEFAULT 'WELCOME_EMAIL',
DROP COLUMN "status",
ADD COLUMN     "status" "MailStatus" NOT NULL DEFAULT 'PENDING';
