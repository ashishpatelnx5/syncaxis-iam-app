/* =========================================================================
   Syncaxis IAM — add FirstName/LastName to Users

   Run this once against SYNCAXIS_AUTHCENTER using an account with ALTER
   rights on the table (db_owner/sysadmin, or whatever your DBA process
   uses) — NOT the syncaxisadmin service login, which is deliberately
   scoped to db_datareader/db_datawriter only (see
   03-syncaxis-iam-create-login.sql) and can't run DDL by design.

   Idempotent - safe to run again; only adds a column if it isn't already
   there.
   ========================================================================= */

USE SYNCAXIS_AUTHCENTER;
GO

IF COL_LENGTH('dbo.Users', 'FirstName') IS NULL
BEGIN
    ALTER TABLE Users ADD FirstName NVARCHAR(100) NULL;
END
GO

IF COL_LENGTH('dbo.Users', 'LastName') IS NULL
BEGIN
    ALTER TABLE Users ADD LastName NVARCHAR(100) NULL;
END
GO
