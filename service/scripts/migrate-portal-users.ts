// One-time migration: copies identity/RBAC data from Company Portal's own
// database into AuthCenter (architecture doc §13, step 2).
//
// STRICTLY READ-ONLY against Portal's database - this script only ever
// issues SELECT queries against SYNCAXIS_PORTAL. Every write goes to
// AuthCenter (this project's own database). Portal's code and database are
// never modified by this script, in line with "no changes to other
// applications" - the EmployeeId link Portal will eventually need
// (architecture doc §7's "AuthUserId on Portal's Employees table" note) is
// written out as a mapping file instead, for Portal's own team to apply
// when they're ready to touch that codebase.
//
// Idempotent and safe to re-run: existing users/roles/groups/permissions
// (matched by Username/Name/Key) are left alone, only missing rows are
// added.
import fs from 'fs';
import path from 'path';
import sql from 'mssql';
import { getPool as getAuthCenterPool, sql as authSql } from '../src/config/db';
import { isValidPermissionKey } from '../src/lib/permissions';

const PORTAL_APP_KEY = 'portal';

function requiredEnv(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`Missing required environment variable: ${name}`);
  return v;
}

function parseServer(raw: string): { server: string; instanceName?: string; port?: number } {
  const [server, instanceName] = raw.split('\\');
  const commaHost = server.split(',');
  if (commaHost.length === 2) return { server: commaHost[0], port: Number(commaHost[1]) };
  return instanceName ? { server, instanceName } : { server };
}

async function getPortalPoolReadOnly(): Promise<sql.ConnectionPool> {
  const { server, instanceName, port } = parseServer(requiredEnv('PORTAL_DB_SERVER'));
  const pool = new sql.ConnectionPool({
    server,
    ...(port ? { port } : {}),
    database: requiredEnv('PORTAL_DB_NAME'),
    user: requiredEnv('PORTAL_DB_USER'),
    password: requiredEnv('PORTAL_DB_PASSWORD'),
    options: {
      encrypt: process.env.PORTAL_DB_ENCRYPT === 'true',
      trustServerCertificate: process.env.PORTAL_DB_TRUST_SERVER_CERTIFICATE !== 'false',
      ...(instanceName ? { instanceName } : {}),
    },
  });
  return pool.connect();
}

// Portal's RolePermissions is (ResourceType: 'page'|'application', ResourceKey)
// - a coarse boolean flag, not an action-level key. Translate into the
// app.module.action convention (architecture doc §6.1) under the 'portal'
// namespace: a "page" grant becomes .view (or .manage for admin-* pages,
// naming only - Portal's own code makes no view/manage distinction today),
// an "application" grant (a tile on Portal's Applications page) becomes
// .access. This is the "expand existing flags into the new key convention"
// work the migration plan calls out as the one genuinely new modeling step.
function toPermissionKey(resourceType: string, resourceKey: string): { key: string; description: string } {
  if (resourceType === 'application') {
    return { key: `${PORTAL_APP_KEY}.${resourceKey}.access`, description: `Access the "${resourceKey}" tile on Portal's Applications page` };
  }
  const action = resourceKey.startsWith('admin-') ? 'manage' : 'view';
  return { key: `${PORTAL_APP_KEY}.${resourceKey}.${action}`, description: `${action === 'manage' ? 'Manage' : 'View'} Portal's "${resourceKey}" page` };
}

interface PortalUserRow {
  UserId: number;
  Username: string;
  PasswordHash: string;
  DisplayName: string | null;
  IsActive: boolean;
  IsLocked: boolean;
  FailedLoginCount: number;
  LastLoginAt: Date | null;
  PasswordChangedAt: Date | null;
  CreatedAt: Date;
  EmployeeId: number | null;
}

async function main() {
  console.log('Connecting to Portal (read-only) and AuthCenter...');
  const portalPool = await getPortalPoolReadOnly();
  const authPool = await getAuthCenterPool();

  const userIdMap = new Map<number, number>(); // Portal UserId -> AuthCenter UserId
  const roleIdMap = new Map<number, number>(); // Portal RoleId -> AuthCenter RoleId
  const groupIdMap = new Map<number, number>(); // Portal GroupId -> AuthCenter GroupId
  const mappingReport: { portalUserId: number; username: string; authCenterUserId: number; employeeId: number | null }[] = [];

  // --- Roles ---------------------------------------------------------------
  const portalRoles = await portalPool.request().query<{ RoleId: number; Name: string; Description: string | null; IsFullAccess: boolean }>(
    'SELECT RoleId, Name, Description, IsFullAccess FROM portal.Roles',
  );
  for (const role of portalRoles.recordset) {
    const existing = await authPool.request().input('name', authSql.NVarChar(100), role.Name).query('SELECT RoleId FROM Roles WHERE Name = @name');
    if (existing.recordset[0]) {
      roleIdMap.set(role.RoleId, existing.recordset[0].RoleId);
      console.log(`Role "${role.Name}" already exists in AuthCenter - reusing it.`);
      continue;
    }
    const inserted = await authPool
      .request()
      .input('name', authSql.NVarChar(100), role.Name)
      .input('description', authSql.NVarChar(400), role.Description)
      .input('isFullAccess', authSql.Bit, role.IsFullAccess)
      .query('INSERT INTO Roles (Name, Description, IsFullAccess) VALUES (@name, @description, @isFullAccess); SELECT CAST(SCOPE_IDENTITY() AS INT) AS RoleId;');
    roleIdMap.set(role.RoleId, inserted.recordset[0].RoleId);
    console.log(`Created role "${role.Name}".`);
  }

  // --- Users -----------------------------------------------------------------
  const portalUsers = await portalPool.request().query<PortalUserRow>(
    'SELECT UserId, Username, PasswordHash, DisplayName, IsActive, IsLocked, FailedLoginCount, LastLoginAt, PasswordChangedAt, CreatedAt, EmployeeId FROM portal.Users',
  );
  for (const u of portalUsers.recordset) {
    const existing = await authPool.request().input('username', authSql.NVarChar(100), u.Username).query('SELECT UserId FROM Users WHERE Username = @username');
    if (existing.recordset[0]) {
      userIdMap.set(u.UserId, existing.recordset[0].UserId);
      mappingReport.push({ portalUserId: u.UserId, username: u.Username, authCenterUserId: existing.recordset[0].UserId, employeeId: u.EmployeeId });
      console.log(`User "${u.Username}" already exists in AuthCenter - reusing it.`);
      continue;
    }

    // Portal never collects an email address, but AuthCenter.Users.Email is
    // NOT NULL UNIQUE - synthesized placeholder, flagged for follow-up.
    const email = `${u.Username}@syncaxis.com`;
    const inserted = await authPool
      .request()
      .input('username', authSql.NVarChar(100), u.Username)
      .input('email', authSql.NVarChar(255), email)
      .input('passwordHash', authSql.NVarChar(255), u.PasswordHash) // bcrypt hash carries over unchanged - no reset needed
      .input('displayName', authSql.NVarChar(200), u.DisplayName)
      .input('isActive', authSql.Bit, u.IsActive)
      .input('isLocked', authSql.Bit, u.IsLocked)
      .input('failedLoginCount', authSql.Int, u.FailedLoginCount)
      .input('lastLoginAt', authSql.DateTime2, u.LastLoginAt)
      .input('passwordChangedAt', authSql.DateTime2, u.PasswordChangedAt)
      .input('createdAt', authSql.DateTime2, u.CreatedAt)
      .query(`
        INSERT INTO Users (Username, Email, PasswordHash, DisplayName, IsActive, IsLocked, FailedLoginCount, LastLoginAt, PasswordChangedAt, CreatedAt)
        VALUES (@username, @email, @passwordHash, @displayName, @isActive, @isLocked, @failedLoginCount, @lastLoginAt, @passwordChangedAt, @createdAt);
        SELECT CAST(SCOPE_IDENTITY() AS INT) AS UserId;
      `);

    const newUserId = inserted.recordset[0].UserId;
    userIdMap.set(u.UserId, newUserId);
    mappingReport.push({ portalUserId: u.UserId, username: u.Username, authCenterUserId: newUserId, employeeId: u.EmployeeId });
    console.log(`Migrated user "${u.Username}" (placeholder email: ${email}).`);
  }

  // --- UserRoles ---------------------------------------------------------------
  const portalUserRoles = await portalPool.request().query<{ UserId: number; RoleId: number }>('SELECT UserId, RoleId FROM portal.UserRoles');
  for (const ur of portalUserRoles.recordset) {
    const newUserId = userIdMap.get(ur.UserId);
    const newRoleId = roleIdMap.get(ur.RoleId);
    if (!newUserId || !newRoleId) continue;
    await authPool
      .request()
      .input('userId', authSql.Int, newUserId)
      .input('roleId', authSql.Int, newRoleId)
      .query('IF NOT EXISTS (SELECT 1 FROM UserRoles WHERE UserId = @userId AND RoleId = @roleId) INSERT INTO UserRoles (UserId, RoleId) VALUES (@userId, @roleId)');
  }
  console.log(`Migrated ${portalUserRoles.recordset.length} user-role assignments.`);

  // --- UserGroups / UserGroupMembers / GroupRoles ---------------------------
  const portalGroups = await portalPool.request().query<{ GroupId: number; Name: string; Description: string | null }>('SELECT GroupId, Name, Description FROM portal.UserGroups');
  for (const g of portalGroups.recordset) {
    const existing = await authPool.request().input('name', authSql.NVarChar(150), g.Name).query('SELECT GroupId FROM UserGroups WHERE Name = @name');
    if (existing.recordset[0]) {
      groupIdMap.set(g.GroupId, existing.recordset[0].GroupId);
      continue;
    }
    const inserted = await authPool
      .request()
      .input('name', authSql.NVarChar(150), g.Name)
      .input('description', authSql.NVarChar(400), g.Description)
      .query('INSERT INTO UserGroups (Name, Description) VALUES (@name, @description); SELECT CAST(SCOPE_IDENTITY() AS INT) AS GroupId;');
    groupIdMap.set(g.GroupId, inserted.recordset[0].GroupId);
    console.log(`Created group "${g.Name}".`);
  }

  const portalGroupMembers = await portalPool.request().query<{ UserId: number; GroupId: number }>('SELECT UserId, GroupId FROM portal.UserGroupMembers');
  for (const gm of portalGroupMembers.recordset) {
    const newUserId = userIdMap.get(gm.UserId);
    const newGroupId = groupIdMap.get(gm.GroupId);
    if (!newUserId || !newGroupId) continue;
    await authPool
      .request()
      .input('userId', authSql.Int, newUserId)
      .input('groupId', authSql.Int, newGroupId)
      .query('IF NOT EXISTS (SELECT 1 FROM UserGroupMembers WHERE UserId = @userId AND GroupId = @groupId) INSERT INTO UserGroupMembers (UserId, GroupId) VALUES (@userId, @groupId)');
  }

  const portalGroupRoles = await portalPool.request().query<{ GroupId: number; RoleId: number }>('SELECT GroupId, RoleId FROM portal.GroupRoles');
  for (const gr of portalGroupRoles.recordset) {
    const newGroupId = groupIdMap.get(gr.GroupId);
    const newRoleId = roleIdMap.get(gr.RoleId);
    if (!newGroupId || !newRoleId) continue;
    await authPool
      .request()
      .input('groupId', authSql.Int, newGroupId)
      .input('roleId', authSql.Int, newRoleId)
      .query('IF NOT EXISTS (SELECT 1 FROM GroupRoles WHERE GroupId = @groupId AND RoleId = @roleId) INSERT INTO GroupRoles (GroupId, RoleId) VALUES (@groupId, @roleId)');
  }
  console.log(`Migrated ${portalGroups.recordset.length} groups, ${portalGroupMembers.recordset.length} memberships, ${portalGroupRoles.recordset.length} group-role grants.`);

  // --- RolePermissions -> Permissions + RolePermissions ------------------------
  const portalApp = await authPool.request().input('key', authSql.NVarChar(50), PORTAL_APP_KEY).query('SELECT AppId FROM Apps WHERE [Key] = @key');
  if (!portalApp.recordset[0]) throw new Error(`App "${PORTAL_APP_KEY}" is not registered in AuthCenter - run db/02-syncaxis-iam-schema.sql first.`);
  const portalAppId = portalApp.recordset[0].AppId;

  const portalRolePerms = await portalPool
    .request()
    .query<{ RoleId: number; ResourceType: string; ResourceKey: string }>('SELECT RoleId, ResourceType, ResourceKey FROM portal.RolePermissions');

  let permsCreated = 0;
  let grantsCreated = 0;
  for (const rp of portalRolePerms.recordset) {
    const newRoleId = roleIdMap.get(rp.RoleId);
    if (!newRoleId) continue;

    const { key, description } = toPermissionKey(rp.ResourceType, rp.ResourceKey);
    if (!isValidPermissionKey(PORTAL_APP_KEY, key)) {
      console.warn(`Skipping invalid permission key derived from (${rp.ResourceType}, ${rp.ResourceKey}): ${key}`);
      continue;
    }

    let permResult = await authPool.request().input('key', authSql.NVarChar(150), key).query('SELECT PermissionId FROM Permissions WHERE [Key] = @key');
    let permissionId: number;
    if (permResult.recordset[0]) {
      permissionId = permResult.recordset[0].PermissionId;
    } else {
      const inserted = await authPool
        .request()
        .input('appId', authSql.Int, portalAppId)
        .input('key', authSql.NVarChar(150), key)
        .input('description', authSql.NVarChar(400), description)
        .query('INSERT INTO Permissions (AppId, [Key], Description) VALUES (@appId, @key, @description); SELECT CAST(SCOPE_IDENTITY() AS INT) AS PermissionId;');
      permissionId = inserted.recordset[0].PermissionId;
      permsCreated += 1;
    }

    const grantResult = await authPool
      .request()
      .input('roleId', authSql.Int, newRoleId)
      .input('permissionId', authSql.Int, permissionId)
      .query(
        'IF NOT EXISTS (SELECT 1 FROM RolePermissions WHERE RoleId = @roleId AND PermissionId = @permissionId) BEGIN INSERT INTO RolePermissions (RoleId, PermissionId) VALUES (@roleId, @permissionId); SELECT 1 AS Inserted; END ELSE SELECT 0 AS Inserted;',
      );
    if (grantResult.recordset[0]?.Inserted) grantsCreated += 1;
  }
  console.log(`Translated ${portalRolePerms.recordset.length} legacy page/application grants -> ${permsCreated} new permission keys, ${grantsCreated} new role grants.`);

  // --- Mapping report for Portal's own team to apply later (§7 note) ----------
  const outDir = path.resolve(__dirname, '..', '..', 'migration-output');
  fs.mkdirSync(outDir, { recursive: true });
  const outFile = path.join(outDir, 'portal-user-employee-mapping.json');
  fs.writeFileSync(outFile, JSON.stringify(mappingReport, null, 2));
  console.log(`\nWrote ${mappingReport.length}-row mapping report to ${outFile}`);
  console.log('This is NOT applied to Portal automatically (no changes to Portal are made by this script).');
  console.log('When Portal is ready to migrate off its own Users table, add an AuthUserId column to');
  console.log('portal.Employees and backfill it from this file (architecture doc §7 / §13 step 2).');

  await portalPool.close();
  await authPool.close();
}

main().catch((err) => {
  console.error('Migration failed:', err);
  process.exit(1);
});
