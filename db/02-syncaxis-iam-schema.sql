/* =========================================================================
   Syncaxis IAM — AuthCenter database schema (SQL Server) — v2
   Companion to syncaxis-iam-architecture.md.

   Run 01-syncaxis-iam-create-db.sql first to create SYNCAXIS_AUTHCENTER,
   then run this script against it.

   Deliberately a SEPARATE database from SYNCAXIS (ERP) and from any
   consuming app's own database. Only syncaxis-iam itself reads/writes this.

   Changes from v1:
     - Users gains TokenValidAfter (instant revocation without a session/
       refresh-token table — see architecture doc §6.4).
     - Roles gains IsFullAccess (unconditional access, matches the pattern
       already in production for Portal's 'Admin' role).
     - Added UserGroups / UserGroupMembers / GroupRoles (roles can be granted
       to a group, not just directly to a user — already proven in Portal).
     - RefreshTokens table removed: no longer needed under the per-app-
       session + periodic re-verify model (architecture doc §4.3-4.4).
     - Permissions.Key is a free-form string per the "<app>.<module>.<action>"
       convention (architecture doc §6.1) rather than a fixed page/application
       ResourceType - no ResourceType column.

   ========================================================================= */

USE SYNCAXIS_AUTHCENTER;
GO

-- ---------------------------------------------------------------------------
-- Users
-- ---------------------------------------------------------------------------
CREATE TABLE Users (
    UserId          INT IDENTITY(1,1) PRIMARY KEY,
    Username        NVARCHAR(100)   NOT NULL,
    Email           NVARCHAR(255)   NOT NULL,
    PasswordHash    NVARCHAR(255)   NOT NULL,   -- bcrypt/argon2 hash, never plaintext
    FirstName       NVARCHAR(100)   NULL,
    MiddleName      NVARCHAR(100)   NULL,
    LastName        NVARCHAR(100)   NULL,
    DisplayName     NVARCHAR(200)   NULL,
    -- Collected for future OTP delivery (SMS/WhatsApp) - not yet used by any
    -- login or verification flow.
    MobileNumber    NVARCHAR(20)    NULL,
    IsActive        BIT             NOT NULL DEFAULT (1),
    IsLocked        BIT             NOT NULL DEFAULT (0),
    FailedLoginCount INT            NOT NULL DEFAULT (0),
    -- Any access token issued before this timestamp is rejected by
    -- GET /auth/me. Bumped on password change, deactivation, role change
    -- that must take effect immediately, or an admin "force logout" action -
    -- invalidates every session in every app within one re-verify cycle
    -- (<=5 min) without tracking individual sessions/tokens centrally.
    TokenValidAfter DATETIME2       NOT NULL DEFAULT (SYSUTCDATETIME()),
    CreatedAt       DATETIME2       NOT NULL DEFAULT (SYSUTCDATETIME()),
    LastLoginAt     DATETIME2       NULL,
    PasswordChangedAt DATETIME2     NULL,
    -- Set on account creation and on an admin's forced reset; cleared on the
    -- user's own next successful password change. Every login path (Portal,
    -- the admin console itself) must treat this as "let them in, but block
    -- everything else until it's cleared".
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
    -- Unconditional access to every permission in every app, bypassing
    -- RolePermissions entirely. Reserve for a single admin/owner role - not
    -- a pattern to lean on for ordinary roles.
    IsFullAccess    BIT             NOT NULL DEFAULT (0),
    CreatedAt       DATETIME2       NOT NULL DEFAULT (SYSUTCDATETIME()),
    CONSTRAINT UQ_Roles_Name UNIQUE (Name)
);

-- ---------------------------------------------------------------------------
-- UserRoles (many-to-many) — roles assigned directly to a user
-- ---------------------------------------------------------------------------
CREATE TABLE UserRoles (
    UserId          INT NOT NULL,
    RoleId          INT NOT NULL,
    AssignedAt      DATETIME2 NOT NULL DEFAULT (SYSUTCDATETIME()),
    CONSTRAINT PK_UserRoles PRIMARY KEY (UserId, RoleId),
    CONSTRAINT FK_UserRoles_User FOREIGN KEY (UserId) REFERENCES Users(UserId) ON DELETE CASCADE,
    CONSTRAINT FK_UserRoles_Role FOREIGN KEY (RoleId) REFERENCES Roles(RoleId) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------------
-- UserGroups — an optional grouping layer (department, team, ...) that
-- grants its member users every role assigned to the group, in addition to
-- whatever roles they hold directly.
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
-- Apps — each consuming application registers itself here (architecture
-- doc §8.2 POST /admin/apps)
-- ---------------------------------------------------------------------------
CREATE TABLE Apps (
    AppId           INT IDENTITY(1,1) PRIMARY KEY,
    [Key]           NVARCHAR(50)    NOT NULL,   -- e.g. 'portal', 'leads', 'erp'
    Name            NVARCHAR(150)   NOT NULL,   -- e.g. 'Leads Tracker'
    BaseUrl         NVARCHAR(300)   NULL,
    IsActive        BIT             NOT NULL DEFAULT (1),
    CreatedAt       DATETIME2       NOT NULL DEFAULT (SYSUTCDATETIME()),
    CONSTRAINT UQ_Apps_Key UNIQUE ([Key])
);

-- ---------------------------------------------------------------------------
-- Permissions — permission keys self-declared by each app, following the
-- "<app>.<module>[.<subpage>].<action>" convention (architecture doc §6.1),
-- e.g. 'leads.leads.view', 'leads.leads.update', 'erp.dashboard.finance.export'.
-- syncaxis-iam never interprets the string - only the declaring app does.
-- ---------------------------------------------------------------------------
CREATE TABLE Permissions (
    PermissionId    INT IDENTITY(1,1) PRIMARY KEY,
    AppId           INT NOT NULL,
    [Key]           NVARCHAR(150)   NOT NULL,
    Description     NVARCHAR(400)   NULL,
    CreatedAt       DATETIME2       NOT NULL DEFAULT (SYSUTCDATETIME()),
    CONSTRAINT FK_Permissions_App FOREIGN KEY (AppId) REFERENCES Apps(AppId) ON DELETE CASCADE,
    CONSTRAINT UQ_Permissions_Key UNIQUE ([Key])
);

-- ---------------------------------------------------------------------------
-- RolePermissions (many-to-many) — the actual access-control matrix
-- ---------------------------------------------------------------------------
CREATE TABLE RolePermissions (
    RoleId          INT NOT NULL,
    PermissionId    INT NOT NULL,
    GrantedAt       DATETIME2 NOT NULL DEFAULT (SYSUTCDATETIME()),
    CONSTRAINT PK_RolePermissions PRIMARY KEY (RoleId, PermissionId),
    CONSTRAINT FK_RolePermissions_Role FOREIGN KEY (RoleId) REFERENCES Roles(RoleId) ON DELETE CASCADE,
    CONSTRAINT FK_RolePermissions_Permission FOREIGN KEY (PermissionId) REFERENCES Permissions(PermissionId) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------------
-- AuditLog — login attempts, SSO issue/exchange, permission denials, admin
-- changes, forced logouts
-- ---------------------------------------------------------------------------
CREATE TABLE AuditLog (
    AuditId         BIGINT IDENTITY(1,1) PRIMARY KEY,
    UserId          INT             NULL,       -- NULL for failed logins with unknown username
    EventType       NVARCHAR(50)    NOT NULL,   -- e.g. 'LOGIN_SUCCESS', 'LOGIN_FAILURE', 'SSO_ISSUE',
                                                  -- 'SSO_EXCHANGE', 'PERMISSION_DENIED', 'ROLE_CHANGED',
                                                  -- 'FORCE_LOGOUT'
    AppKey          NVARCHAR(50)    NULL,       -- which app this event relates to, if any
    Detail          NVARCHAR(1000)  NULL,
    IpAddress       VARCHAR(45)     NULL,
    CreatedAt       DATETIME2       NOT NULL DEFAULT (SYSUTCDATETIME()),
    CONSTRAINT FK_AuditLog_User FOREIGN KEY (UserId) REFERENCES Users(UserId) ON DELETE SET NULL
);
CREATE INDEX IX_AuditLog_CreatedAt ON AuditLog(CreatedAt);
CREATE INDEX IX_AuditLog_UserId ON AuditLog(UserId);

-- ---------------------------------------------------------------------------
-- Seed data — starter roles/apps/permissions to adapt as needed. Permission
-- keys below mirror what Leads Tracker and the ERP Dashboard already gate
-- today (as coarse booleans); expanding them into per-action keys here is
-- part of the migration (architecture doc §12, step 2).
-- ---------------------------------------------------------------------------
INSERT INTO Roles (Name, Description, IsFullAccess) VALUES
    (N'Admin',        N'Full access to every app and the IAM admin console', 1),
    (N'SalesManager', N'Manages leads and sales reporting', 0),
    (N'SalesRep',     N'Front-line sales', 0),
    (N'Accounts',     N'Finance/AR-AP visibility', 0);

INSERT INTO Apps ([Key], Name, BaseUrl) VALUES
    (N'iam',    N'Syncaxis IAM Admin', N'https://iam.syncaxis.local'),
    (N'portal', N'Company Portal',     N'https://portal.syncaxis.local'),
    (N'leads',  N'Leads Tracker',      N'https://leads.syncaxis.local'),
    (N'erp',    N'ERP Dashboard',      N'http://192.168.3.9:8055');

INSERT INTO Permissions (AppId, [Key], Description)
SELECT AppId, N'iam.admin.manage', N'Manage users, roles, groups, apps, and permissions' FROM Apps WHERE [Key] = N'iam'
UNION ALL
SELECT AppId, N'leads.leads.view',   N'View the leads list/board' FROM Apps WHERE [Key] = N'leads'
UNION ALL
SELECT AppId, N'leads.leads.create', N'Add a lead' FROM Apps WHERE [Key] = N'leads'
UNION ALL
SELECT AppId, N'leads.leads.update', N'Edit a lead' FROM Apps WHERE [Key] = N'leads'
UNION ALL
SELECT AppId, N'leads.leads.delete', N'Delete a lead' FROM Apps WHERE [Key] = N'leads'
UNION ALL
SELECT AppId, N'leads.leads.export', N'Export leads to Excel' FROM Apps WHERE [Key] = N'leads'
UNION ALL
SELECT AppId, N'leads.customers.view',   N'View customers' FROM Apps WHERE [Key] = N'leads'
UNION ALL
SELECT AppId, N'leads.customers.create', N'Add a customer' FROM Apps WHERE [Key] = N'leads'
UNION ALL
SELECT AppId, N'leads.customers.update', N'Edit a customer' FROM Apps WHERE [Key] = N'leads'
UNION ALL
SELECT AppId, N'leads.customers.delete', N'Delete a customer' FROM Apps WHERE [Key] = N'leads'
UNION ALL
SELECT AppId, N'leads.admin.manage', N'Admin section of Leads Tracker' FROM Apps WHERE [Key] = N'leads'
UNION ALL
SELECT AppId, N'erp.dashboard.sales.view',   N'View Sales & Revenue tab' FROM Apps WHERE [Key] = N'erp'
UNION ALL
SELECT AppId, N'erp.dashboard.finance.view', N'View Finance (AR/AP) tab' FROM Apps WHERE [Key] = N'erp'
UNION ALL
SELECT AppId, N'erp.dashboard.finance.export', N'Export Finance data' FROM Apps WHERE [Key] = N'erp'
UNION ALL
SELECT AppId, N'portal.admin.users.manage', N'Manage portal user profiles' FROM Apps WHERE [Key] = N'portal';
