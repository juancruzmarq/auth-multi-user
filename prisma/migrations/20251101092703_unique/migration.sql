/*
  Warnings:

  - A unique constraint covering the columns `[template,to,created_at]` on the table `mail_outbox` will be added. If there are existing duplicate values, this will fail.
  - A unique constraint covering the columns `[id_user,purpose]` on the table `verification_token` will be added. If there are existing duplicate values, this will fail.

*/
-- CreateIndex
CREATE UNIQUE INDEX "mail_outbox_template_to_created_at_key" ON "mail_outbox"("template", "to", "created_at");

-- CreateIndex
CREATE UNIQUE INDEX "verification_token_id_user_purpose_key" ON "verification_token"("id_user", "purpose");
