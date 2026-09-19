// Reads the LOCAL SYNCAXIS_AUTHCENTER (read-only, via the normal .env
// connection) and writes migration-output/02-data-migration.sql: a
// self-contained script that loads that data into an EMPTY production
// database created by db/prod/01-create-database-and-schema.sql.
//
//   npm run export:prod-data
//   npm run export:prod-data -- --with-audit
//   npm run export:prod-data -- --app-url iam=https://iam.example.com --app-url portal=https://portal.example.com
//   npm run export:prod-data -- --exclude-user testuser --exclude-user claudeuser
//
// The output contains password hashes and personal data - it is written to
// migration-output/ (git-ignored). Never commit it or leave copies around.
import fs from 'fs';
import path from 'path';
import { getPool } from '../src/config/db';

const args = process.argv.slice(2);
const withAudit = args.includes('--with-audit');
const appUrlOverrides = new Map<string, string>();
args.forEach((a, i) => {
  if (a === '--app-url' && args[i + 1]) {
    const [key, ...rest] = args[i + 1].split('=');
    appUrlOverrides.set(key, rest.join('='));
  }
});

const excludedUsernames = new Set<string>();
args.forEach((a, i) => {
  if (a === '--exclude-user' && args[i + 1]) excludedUsernames.add(args[i + 1].toLowerCase());
});
const excludedUserIds = new Set<number>();

type Row = Record<string, unknown>;

function lit(v: unknown): string {
  if (v === null || v === undefined) return 'NULL';
  if (typeof v === 'boolean') return v ? '1' : '0';
  if (typeof v === 'number') return String(v);
  if (v instanceof Date) return `CAST('${v.toISOString().replace('Z', '')}' AS DATETIME2)`;
  return `N'${String(v).replace(/'/g, "''")}'`;
}

interface TableSpec {
  table: string;
  cols: string[];
  identity: boolean;
  orderBy: string;
}

// Parents before children so foreign keys are satisfied as rows go in.
const TABLES: TableSpec[] = [
  { table: 'Roles', cols: ['RoleId', 'Name', 'Description', 'IsFullAccess', 'CreatedAt'], identity: true, orderBy: 'RoleId' },
  { table: 'Apps', cols: ['AppId', 'Key', 'Name', 'BaseUrl', 'IsActive', 'CreatedAt'], identity: true, orderBy: 'AppId' },
  { table: 'Permissions', cols: ['PermissionId', 'AppId', 'Key', 'Description', 'CreatedAt'], identity: true, orderBy: 'PermissionId' },
  {
    table: 'Users',
    cols: [
      'UserId', 'Username', 'Email', 'PasswordHash', 'FirstName', 'MiddleName', 'LastName', 'DisplayName', 'MobileNumber',
      'IsActive', 'IsLocked', 'FailedLoginCount', 'TokenValidAfter', 'CreatedAt', 'LastLoginAt', 'PasswordChangedAt', 'MustChangePassword',
    ],
    identity: true,
    orderBy: 'UserId',
  },
  { table: 'UserGroups', cols: ['GroupId', 'Name', 'Description', 'CreatedAt'], identity: true, orderBy: 'GroupId' },
  { table: 'UserRoles', cols: ['UserId', 'RoleId', 'AssignedAt'], identity: false, orderBy: 'UserId, RoleId' },
  { table: 'UserGroupMembers', cols: ['UserId', 'GroupId', 'AddedAt'], identity: false, orderBy: 'UserId, GroupId' },
  { table: 'GroupRoles', cols: ['GroupId', 'RoleId', 'GrantedAt'], identity: false, orderBy: 'GroupId, RoleId' },
  { table: 'RolePermissions', cols: ['RoleId', 'PermissionId', 'GrantedAt'], identity: false, orderBy: 'RoleId, PermissionId' },
];
if (withAudit) {
  TABLES.push({ table: 'AuditLog', cols: ['AuditId', 'UserId', 'EventType', 'AppKey', 'Detail', 'IpAddress', 'CreatedAt'], identity: true, orderBy: 'AuditId' });
}

const q = (c: string) => `[${c}]`;

async function main() {
  const pool = await getPool();
  const out: string[] = [];
  const counts: Record<string, number> = {};

  out.push(`/* =========================================================================
   Syncaxis IAM - PRODUCTION data migration (GENERATED ${new Date().toISOString()})
   Source: local SYNCAXIS_AUTHCENTER. Target: EMPTY production database created
   by db/prod/01-create-database-and-schema.sql.

   CONTAINS PASSWORD HASHES AND PERSONAL DATA - do not commit or share.
   Run with sysadmin/db_owner rights, once. Safe by design: aborts without
   changing anything if the target already holds data, and runs as a single
   transaction (any error rolls the whole load back).
   ========================================================================= */

USE SYNCAXIS_AUTHCENTER;
GO
SET NOCOUNT ON;
SET XACT_ABORT ON;
GO

IF EXISTS (SELECT 1 FROM Users) OR EXISTS (SELECT 1 FROM Roles) OR EXISTS (SELECT 1 FROM Apps)
BEGIN
    RAISERROR('Target database is not empty - refusing to load. Nothing was changed.', 16, 1);
    SET NOEXEC ON;
END
GO

BEGIN TRANSACTION;
GO
`);

  for (const spec of TABLES) {
    const result = await pool.request().query(`SELECT ${spec.cols.map(q).join(', ')} FROM ${spec.table} ORDER BY ${spec.orderBy}`);
    let rows = result.recordset as Row[];
    if (spec.table === 'Users') {
      rows = rows.filter((r) => {
        const skip = excludedUsernames.has(String(r.Username).toLowerCase());
        if (skip) excludedUserIds.add(r.UserId as number);
        return !skip;
      });
    } else if (excludedUserIds.size > 0 && spec.cols.includes('UserId')) {
      rows = rows.filter((r) => !excludedUserIds.has(r.UserId as number));
    }
    if (spec.table === 'Apps' && appUrlOverrides.size > 0) {
      rows = rows.map((r) => (appUrlOverrides.has(r.Key as string) ? { ...r, BaseUrl: appUrlOverrides.get(r.Key as string) } : r));
    }
    counts[spec.table] = rows.length;
    // A failed statement rolls the transaction back (XACT_ABORT) but SSMS would
    // still run the remaining batches - skip them once the transaction is gone.
    out.push(`IF @@TRANCOUNT = 0 SET NOEXEC ON;
GO
-- ${spec.table}: ${rows.length} row(s)`);
    if (rows.length === 0) {
      out.push('GO\n');
      continue;
    }
    if (spec.identity) out.push(`SET IDENTITY_INSERT ${spec.table} ON;`);
    const colList = spec.cols.map(q).join(', ');
    for (const row of rows) {
      out.push(`INSERT INTO ${spec.table} (${colList}) VALUES (${spec.cols.map((c) => lit(row[c])).join(', ')});`);
    }
    if (spec.identity) out.push(`SET IDENTITY_INSERT ${spec.table} OFF;`);
    out.push('GO\n');
  }

  out.push(`-- Verification: row counts must match the source counts recorded below.
DECLARE @bad INT = 0;`);
  for (const spec of TABLES) {
    out.push(`IF (SELECT COUNT(*) FROM ${spec.table}) <> ${counts[spec.table]} BEGIN SET @bad += 1; PRINT 'COUNT MISMATCH: ${spec.table}'; END`);
  }
  out.push(`IF @bad > 0
BEGIN
    ROLLBACK TRANSACTION;
    RAISERROR('Verification failed - transaction rolled back, nothing was loaded.', 16, 1);
END
ELSE
BEGIN
    COMMIT TRANSACTION;
    PRINT 'Data migration committed successfully.';
END
GO
SET NOEXEC OFF;
GO
`);

  const dir = path.resolve(__dirname, '..', '..', 'migration-output');
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, '02-data-migration.sql');
  fs.writeFileSync(file, out.join('\n'), 'utf8');

  console.log(`Wrote ${file}`);
  console.table(counts);
  if (!withAudit) console.log('AuditLog NOT included (pass --with-audit to include it).');
  if (excludedUsernames.size > 0) console.log(`Excluded users: ${[...excludedUsernames].join(', ')} (${excludedUserIds.size} matched)`);
  console.log('Apps.BaseUrl values as written:');
  const apps = await pool.request().query('SELECT [Key], BaseUrl FROM Apps ORDER BY AppId');
  for (const a of apps.recordset as Row[]) console.log(`  ${a.Key}: ${appUrlOverrides.get(a.Key as string) ?? a.BaseUrl}${appUrlOverrides.has(a.Key as string) ? '  (overridden)' : ''}`);
  process.exit(0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
