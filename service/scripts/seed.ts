// Bootstrap/reset the first admin user (architecture doc §9.3 / §16.6) -
// ported from Company Portal's own scripts/seed.js pattern: idempotent, not
// part of normal app startup, driven entirely by env vars so it's safe to
// re-run any time (e.g. if you ever get locked out of the admin console).
import bcrypt from 'bcryptjs';
import { getPool, sql } from '../src/config/db';
import { env } from '../src/config/env';

const ADMIN_PERMISSION_KEY = 'iam.admin.manage';

async function main() {
  const username = env.seedAdminUsername;
  const password = env.seedAdminPassword;
  if (!username || !password) {
    console.log('SEED_ADMIN_USERNAME/SEED_ADMIN_PASSWORD not set — nothing to do.');
    return;
  }

  const pool = await getPool();
  const passwordHash = await bcrypt.hash(password, 12);

  const existing = await pool.request().input('username', sql.NVarChar(100), username).query('SELECT UserId FROM Users WHERE Username = @username');

  let userId: number;
  if (existing.recordset[0]) {
    userId = existing.recordset[0].UserId;
    await pool
      .request()
      .input('id', sql.Int, userId)
      .input('passwordHash', sql.NVarChar(255), passwordHash)
      .query(
        'UPDATE Users SET PasswordHash = @passwordHash, IsActive = 1, IsLocked = 0, FailedLoginCount = 0, TokenValidAfter = SYSUTCDATETIME() WHERE UserId = @id',
      );
    console.log(`Updated password for existing user "${username}".`);
  } else {
    const result = await pool
      .request()
      .input('username', sql.NVarChar(100), username)
      .input('email', sql.NVarChar(255), `${username}@syncaxis.com`)
      .input('displayName', sql.NVarChar(200), username)
      .input('passwordHash', sql.NVarChar(255), passwordHash)
      .query(
        'INSERT INTO Users (Username, Email, DisplayName, PasswordHash) VALUES (@username, @email, @displayName, @passwordHash); SELECT CAST(SCOPE_IDENTITY() AS INT) AS UserId;',
      );
    userId = result.recordset[0].UserId;
    console.log(`Created admin user "${username}".`);
  }

  // The seeded Admin role (IsFullAccess = 1) already exists from the schema
  // script's seed data - just make sure this user holds it.
  const adminRole = await pool.request().query("SELECT RoleId FROM Roles WHERE Name = N'Admin'");
  if (!adminRole.recordset[0]) {
    throw new Error('Seeded "Admin" role not found - did you run db/02-syncaxis-iam-schema.sql?');
  }
  const roleId = adminRole.recordset[0].RoleId;

  await pool
    .request()
    .input('userId', sql.Int, userId)
    .input('roleId', sql.Int, roleId)
    .query('IF NOT EXISTS (SELECT 1 FROM UserRoles WHERE UserId = @userId AND RoleId = @roleId) INSERT INTO UserRoles (UserId, RoleId) VALUES (@userId, @roleId)');

  // Admin role is IsFullAccess, so the iam.admin.manage permission row is
  // mostly documentation, but seed it anyway so it shows correctly in the
  // permission matrix rather than appearing ungranted.
  const iamApp = await pool.request().query("SELECT AppId FROM Apps WHERE [Key] = N'iam'");
  if (iamApp.recordset[0]) {
    const perm = await pool
      .request()
      .input('key', sql.NVarChar(150), ADMIN_PERMISSION_KEY)
      .query('SELECT PermissionId FROM Permissions WHERE [Key] = @key');
    if (perm.recordset[0]) {
      await pool
        .request()
        .input('roleId', sql.Int, roleId)
        .input('permissionId', sql.Int, perm.recordset[0].PermissionId)
        .query(
          'IF NOT EXISTS (SELECT 1 FROM RolePermissions WHERE RoleId = @roleId AND PermissionId = @permissionId) INSERT INTO RolePermissions (RoleId, PermissionId) VALUES (@roleId, @permissionId)',
        );
    }
  }

  console.log(`"${username}" now holds the Admin role. Sign in at /admin-ui/login.`);
  await pool.close();
}

main().catch((err) => {
  console.error('Seed failed:', err);
  process.exit(1);
});
