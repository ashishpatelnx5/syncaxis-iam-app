/* =========================================================================
   Syncaxis IAM — SQL login for the syncaxis-iam service

   Run after 01-syncaxis-iam-create-db.sql and 02-syncaxis-iam-schema.sql.

   Least-privilege by design (architecture doc §12): this login can read/
   write tables in SYNCAXIS_AUTHCENTER only — no db_owner, no access to
   SYNCAXIS (ERP) or any other app's database. This is the account the
   syncaxis-iam Node service itself connects with (DB_USER/DB_PASSWORD in
   its .env) — not a personal/human login.

   CHECK_POLICY/CHECK_EXPIRATION are off because this is a service account
   with its password held in the app's .env, not a human who'll be prompted
   to rotate it interactively — rotate it manually if you ever need to.

   SET A REAL PASSWORD BELOW before running this — the placeholder is not a
   usable credential. Never commit the real value; it belongs only in each
   environment's own .env (DB_PASSWORD), never in this file or git history.
   ========================================================================= */

-- Server-level login
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = N'syncaxisadmin')
BEGIN
    CREATE LOGIN syncaxisadmin
        WITH PASSWORD = N'CHANGE_ME_STRONG_PASSWORD',
             CHECK_POLICY = OFF,
             CHECK_EXPIRATION = OFF;
END
GO

USE SYNCAXIS_AUTHCENTER;
GO

-- Database user mapped to that login, scoped to this database only
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'syncaxisadmin')
BEGIN
    CREATE USER syncaxisadmin FOR LOGIN syncaxisadmin;
END
GO

ALTER ROLE db_datareader ADD MEMBER syncaxisadmin;
ALTER ROLE db_datawriter ADD MEMBER syncaxisadmin;
GO

-- Explicitly confirm no access to the ERP database from this login, in case
-- it was ever granted broader rights by an earlier ad-hoc script:
-- USE SYNCAXIS; DROP USER IF EXISTS syncaxisadmin;
