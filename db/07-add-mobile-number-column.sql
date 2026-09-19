/* =========================================================================
   Syncaxis IAM — add MobileNumber to Users

   Run this once against SYNCAXIS_AUTHCENTER using an account with ALTER
   rights on the table (db_owner/sysadmin) — NOT the syncaxisadmin service
   login, which is deliberately scoped to db_datareader/db_datawriter only
   (see 03-syncaxis-iam-create-login.sql) and can't run DDL by design.

   Idempotent - safe to run again; only adds the column if it isn't already
   there. Nullable and unenforced for now — collected for future OTP
   delivery (SMS/WhatsApp), not yet used by any login or verification flow.
   ========================================================================= */

USE SYNCAXIS_AUTHCENTER;
GO

IF COL_LENGTH('dbo.Users', 'MobileNumber') IS NULL
BEGIN
    ALTER TABLE Users ADD MobileNumber NVARCHAR(20) NULL;
END
GO
