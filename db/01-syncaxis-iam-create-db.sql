/* =========================================================================
   Syncaxis IAM — create the AuthCenter database
   Run this first, once, then run 02-syncaxis-iam-schema.sql against it.

   Deliberately a separate database from SYNCAXIS (ERP) and from any
   consuming app's own database (portal, SyncaxisLeads, ...) — only
   syncaxis-iam itself ever reads/writes SYNCAXIS_AUTHCENTER.
   ========================================================================= */

IF DB_ID(N'SYNCAXIS_AUTHCENTER') IS NULL
BEGIN
    CREATE DATABASE SYNCAXIS_AUTHCENTER;
END
GO

ALTER DATABASE SYNCAXIS_AUTHCENTER SET RECOVERY SIMPLE;
GO

USE SYNCAXIS_AUTHCENTER;
GO
