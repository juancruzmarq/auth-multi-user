/*
  Warnings:

  - You are about to drop the column `template` on the `mail_outbox` table. All the data in the column will be lost.
  - A unique constraint covering the columns `[type,to,created_at]` on the table `mail_outbox` will be added. If there are existing duplicate values, this will fail.

*/
-- DropIndex
DROP INDEX "public"."mail_outbox_template_to_created_at_key";

-- AlterTable
ALTER TABLE "mail_outbox" DROP COLUMN "template";

-- CreateIndex
CREATE UNIQUE INDEX "mail_outbox_type_to_created_at_key" ON "mail_outbox"("type", "to", "created_at");
