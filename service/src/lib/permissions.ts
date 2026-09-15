import { ConnectionPool } from 'mssql';
import { sql } from '../config/db';

export interface EffectiveAccess {
  isFullAccess: boolean;
  roles: { id: number; name: string }[];
  perms: Set<string>;
}

// A user's effective access is the union of every permission granted by
// every role assigned directly to them, plus every role assigned to any
// group they belong to. Any one of those roles having IsFullAccess grants
// unconditional access to everything - reserved for the Admin role, not a
// pattern to lean on for ordinary roles (architecture doc §6.3).
//
// Queried live (not cached beyond a single request) so a role/group change
// an admin just made is reflected the next time this is called - which is
// what GET /auth/me does on every app's periodic re-verify (§4.3).
export async function getEffectiveAccess(pool: ConnectionPool, userId: number): Promise<EffectiveAccess> {
  const result = await pool.request().input('userId', sql.Int, userId).query(`
    ;WITH MyRoleIds AS (
      SELECT RoleId FROM UserRoles WHERE UserId = @userId
      UNION
      SELECT gr.RoleId FROM UserGroupMembers m
        JOIN GroupRoles gr ON gr.GroupId = m.GroupId
        WHERE m.UserId = @userId
    )
    SELECT r.RoleId, r.Name, r.IsFullAccess, p.[Key] AS PermissionKey
    FROM MyRoleIds x
    JOIN Roles r ON r.RoleId = x.RoleId
    LEFT JOIN RolePermissions rp ON rp.RoleId = r.RoleId
    LEFT JOIN Permissions p ON p.PermissionId = rp.PermissionId
  `);

  const roles = new Map<number, string>();
  const perms = new Set<string>();
  let isFullAccess = false;

  for (const row of result.recordset as {
    RoleId: number;
    Name: string;
    IsFullAccess: boolean;
    PermissionKey: string | null;
  }[]) {
    roles.set(row.RoleId, row.Name);
    if (row.IsFullAccess) isFullAccess = true;
    if (row.PermissionKey) perms.add(row.PermissionKey);
  }

  return { isFullAccess, roles: [...roles].map(([id, name]) => ({ id, name })), perms };
}

// Permission key format + namespace enforcement (architecture doc §8.3):
// must look like "app.module.action" (dot-separated lowercase segments) and
// must start with the calling app's own Key, so one app can't self-register
// a key that reads as belonging to another app.
const KEY_FORMAT = /^[a-z][a-z0-9]*(\.[a-z][a-z0-9-]*)+$/;

export function isValidPermissionKey(appKey: string, key: string): boolean {
  return KEY_FORMAT.test(key) && key.startsWith(`${appKey}.`);
}
