/* =========================================================================
   Syncaxis IAM — add MiddleName to Users

   Run this once against SYNCAXIS_AUTHCENTER using an account with ALTER
   rights on the table (db_owner/sysadmin) — NOT the syncaxisadmin service
   login, which is deliberately scoped to db_datareader/db_datawriter only
   (see 03-syncaxis-iam-create-login.sql) and can't run DDL by design.

   Idempotent - safe to run again; only adds the column if it isn't already
   there.
   ========================================================================= */

USE SYNCAXIS_AUTHCENTER;
GO

IF COL_LENGTH('dbo.Users', 'MiddleName') IS NULL
BEGIN
    ALTER TABLE Users ADD MiddleName NVARCHAR(100) NULL;
END
GO
