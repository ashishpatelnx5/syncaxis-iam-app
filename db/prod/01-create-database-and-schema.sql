/* =========================================================================
   Syncaxis IAM — PRODUCTION: create the AuthCenter database + full schema

   Consolidates db/01 + db/02 and folds in migrations 04-07 (name columns,
   MustChangePassword, MobileNumber), so a fresh production server needs
   only this one script for the schema. Contains NO seed/sample data -
   real data arrives via the generated data-migration script (step 3).

   PRODUCTION RUN ORDER (run each with an account that has sysadmin/dbcreator
   rights - NOT the syncaxisadmin service login):
     1. db/prod/01-create-database-and-schema.sql   (this file)
     2. db/03-syncaxis-iam-create-login.sql         (set a REAL password first)
     3. migration-output/02-data-migration.sql      (generated from your local
        DB by `npm run export:prod-data` in service/ - see that script)

   Not safe to re-run against a database that already holds data: the CREATE
   TABLE statements will fail on an existing schema, by design, rather than
   silently doing nothing or dropping anything.

   Recovery model is left at the server default (FULL on a stock install) -
   set it deliberately per your backup policy; the dev-only SIMPLE setting
   from db/01 is intentionally not carried over.
   ========================================================================= */

IF DB_ID(N'SYNCAXIS_AUTHCENTER') IS NULL
BEGIN
    CREATE DATABASE SYNCAXIS_AUTHCENTER;
END
GO

USE SYNCAXIS_AUTHCENTER;
GO

-- ---------------------------------------------------------------------------
-- Users
-- ---------------------------------------------------------------------------
CREATE TABLE Users (
    UserId          INT IDENTITY(1,1) PRIMARY KEY,
    Username        NVARCHAR(100)   NOT NULL,
    Email           NVARCHAR(255)   NOT NULL,
    PasswordHash    NVARCHAR(255)   NOT NULL,   -- bcrypt hash, never plaintext
    FirstName       NVARCHAR(100)   NULL,
    MiddleName      NVARCHAR(100)   NULL,
    LastName        NVARCHAR(100)   NULL,
    DisplayName     NVARCHAR(200)   NULL,
    MobileNumber    NVARCHAR(20)    NULL,       -- "+<code><digits>", for future OTP delivery
    IsActive        BIT             NOT NULL DEFAULT (1),
    IsLocked        BIT             NOT NULL DEFAULT (0),
    FailedLoginCount INT            NOT NULL DEFAULT (0),
    -- Any access token issued before this timestamp is rejected by
    -- GET /auth/me (instant revocation without a session table).
    TokenValidAfter DATETIME2       NOT NULL DEFAULT (SYSUTCDATETIME()),
    CreatedAt       DATETIME2       NOT NULL DEFAULT (SYSUTCDATETIME()),
    LastLoginAt     DATETIME2       NULL,
    PasswordChangedAt DATETIME2     NULL,
    MustChangePassword BIT          NOT NULL DEFAULT (0),
    CONSTRAINT UQ_Users_Username UNIQUE (Username),
    CONSTRAINT UQ_Users_Email UNIQUE (Email)
);

-- ---------------------------------------------------------------------------
-- Roles
-- ---------------------------------------------------------------------------
CREATE TABLE Roles (
    RoleId          INT IDENTITY(1,1) PRIMARY KEY,
    Name            NVARCHAR(100)   NOT NULL,
    Description     NVARCHAR(400)   NULL,
    IsFullAccess    BIT             NOT NULL DEFAULT (0),
    CreatedAt       DATETIME2       NOT NULL DEFAULT (SYSUTCDATETIME()),
    CONSTRAINT UQ_Roles_Name UNIQUE (Name)
);

CREATE TABLE UserRoles (
    UserId          INT NOT NULL,
    RoleId          INT NOT NULL,
    AssignedAt      DATETIME2 NOT NULL DEFAULT (SYSUTCDATETIME()),
    CONSTRAINT PK_UserRoles PRIMARY KEY (UserId, RoleId),
    CONSTRAINT FK_UserRoles_User FOREIGN KEY (UserId) REFERENCES Users(UserId) ON DELETE CASCADE,
    CONSTRAINT FK_UserRoles_Role FOREIGN KEY (RoleId) REFERENCES Roles(RoleId) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------------
-- Groups
-- ---------------------------------------------------------------------------
CREATE TABLE UserGroups (
    GroupId         INT IDENTITY(1,1) PRIMARY KEY,
    Name            NVARCHAR(150)   NOT NULL,
    Description     NVARCHAR(400)   NULL,
    CreatedAt       DATETIME2       NOT NULL DEFAULT (SYSUTCDATETIME()),
    CONSTRAINT UQ_UserGroups_Name UNIQUE (Name)
);

CREATE TABLE UserGroupMembers (
    UserId          INT NOT NULL,
    GroupId         INT NOT NULL,
    AddedAt         DATETIME2 NOT NULL DEFAULT (SYSUTCDATETIME()),
    CONSTRAINT PK_UserGroupMembers PRIMARY KEY (UserId, GroupId),
    CONSTRAINT FK_UserGroupMembers_User FOREIGN KEY (UserId) REFERENCES Users(UserId) ON DELETE CASCADE,
    CONSTRAINT FK_UserGroupMembers_Group FOREIGN KEY (GroupId) REFERENCES UserGroups(GroupId) ON DELETE CASCADE
);

CREATE TABLE GroupRoles (
    GroupId         INT NOT NULL,
    RoleId          INT NOT NULL,
    GrantedAt       DATETIME2 NOT NULL DEFAULT (SYSUTCDATETIME()),
    CONSTRAINT PK_GroupRoles PRIMARY KEY (GroupId, RoleId),
    CONSTRAINT FK_GroupRoles_Group FOREIGN KEY (GroupId) REFERENCES UserGroups(GroupId) ON DELETE CASCADE,
    CONSTRAINT FK_GroupRoles_Role FOREIGN KEY (RoleId) REFERENCES Roles(RoleId) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------------
-- Apps + Permissions + RolePermissions
-- ---------------------------------------------------------------------------
CREATE TABLE Apps (
    AppId           INT IDENTITY(1,1) PRIMARY KEY,
    [Key]           NVARCHAR(50)    NOT NULL,
    Name            NVARCHAR(150)   NOT NULL,
    BaseUrl         NVARCHAR(300)   NULL,
    IsActive        BIT             NOT NULL DEFAULT (1),
    CreatedAt       DATETIME2       NOT NULL DEFAULT (SYSUTCDATETIME()),
    CONSTRAINT UQ_Apps_Key UNIQUE ([Key])
);

CREATE TABLE Permissions (
    PermissionId    INT IDENTITY(1,1) PRIMARY KEY,
    AppId           INT NOT NULL,
    [Key]           NVARCHAR(150)   NOT NULL,
    Description     NVARCHAR(400)   NULL,
    CreatedAt       DATETIME2       NOT NULL DEFAULT (SYSUTCDATETIME()),
    CONSTRAINT FK_Permissions_App FOREIGN KEY (AppId) REFERENCES Apps(AppId) ON DELETE CASCADE,
    CONSTRAINT UQ_Permissions_Key UNIQUE ([Key])
);

CREATE TABLE RolePermissions (
    RoleId          INT NOT NULL,
    PermissionId    INT NOT NULL,
    GrantedAt       DATETIME2 NOT NULL DEFAULT (SYSUTCDATETIME()),
    CONSTRAINT PK_RolePermissions PRIMARY KEY (RoleId, PermissionId),
    CONSTRAINT FK_RolePermissions_Role FOREIGN KEY (RoleId) REFERENCES Roles(RoleId) ON DELETE CASCADE,
    CONSTRAINT FK_RolePermissions_Permission FOREIGN KEY (PermissionId) REFERENCES Permissions(PermissionId) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------------
-- AuditLog
-- ---------------------------------------------------------------------------
CREATE TABLE AuditLog (
    AuditId         BIGINT IDENTITY(1,1) PRIMARY KEY,
    UserId          INT             NULL,
    EventType       NVARCHAR(50)    NOT NULL,
    AppKey          NVARCHAR(50)    NULL,
    Detail          NVARCHAR(1000)  NULL,
    IpAddress       VARCHAR(45)     NULL,
    CreatedAt       DATETIME2       NOT NULL DEFAULT (SYSUTCDATETIME()),
    CONSTRAINT FK_AuditLog_User FOREIGN KEY (UserId) REFERENCES Users(UserId) ON DELETE SET NULL
);
CREATE INDEX IX_AuditLog_CreatedAt ON AuditLog(CreatedAt);
CREATE INDEX IX_AuditLog_UserId ON AuditLog(UserId);
GO

PRINT 'SYNCAXIS_AUTHCENTER schema created. Next: db/03-syncaxis-iam-create-login.sql, then the generated data migration.';
GO
