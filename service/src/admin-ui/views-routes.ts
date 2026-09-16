import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import { NextFunction, Request, Response, Router } from 'express';
import jwt from 'jsonwebtoken';
import { getPool, sql } from '../config/db';
import { env } from '../config/env';
import { requireAuth, requirePermission } from '../middleware/auth';
import { attemptLogin } from '../lib/authenticate';
import { getEffectiveAccess } from '../lib/permissions';
import { clientIp, writeAuditLog } from '../lib/audit';

const MIN_PASSWORD_LENGTH = 8; // architecture doc §16.5

const router = Router();
const ADMIN_SESSION_COOKIE = 'iam_admin_session';
const ADMIN_PERMISSION = 'iam.admin.manage';

interface AdminSession {
  token: string;
  userId: number;
  username: string;
  expiresAt: number;
}
// Same tradeoff as every other app's own session store (architecture doc
// §4.3): in-memory only, an app restart just means admins sign back in.
const adminSessions = new Map<string, AdminSession>();

function signToken(userId: number, username: string): string {
  return jwt.sign({ sub: userId, username }, env.jwtSecret, { expiresIn: env.jwtExpiresIn } as jwt.SignOptions);
}

// Bridges the admin console's own browser cookie to the same requireAuth
// used by every JSON API route (architecture doc §10: iam treats its own
// admin console as just another registered app) - the token itself never
// reaches the browser, only this server-side session lookup does.
function requireUiAuth(req: Request, res: Response, next: NextFunction): void {
  const sessionId = req.cookies?.[ADMIN_SESSION_COOKIE];
  const session = sessionId ? adminSessions.get(sessionId) : undefined;
  if (!session || session.expiresAt < Date.now()) {
    res.redirect('/admin-ui/login');
    return;
  }
  req.headers.authorization = `Bearer ${session.token}`;
  next();
}

const requireUiAdmin = [requireUiAuth, requireAuth, requirePermission(ADMIN_PERMISSION)];

// --- Login / logout -------------------------------------------------------

router.get('/login', (req: Request, res: Response) => {
  const sessionId = req.cookies?.[ADMIN_SESSION_COOKIE];
  if (sessionId && adminSessions.has(sessionId)) {
    res.redirect('/admin-ui');
    return;
  }
  res.render('login', { error: null });
});

router.post('/login', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) {
      res.render('login', { error: 'Username and password are required.' });
      return;
    }

    const pool = await getPool();
    const outcome = await attemptLogin(pool, username, password, clientIp(req));
    if (!outcome.ok) {
      res.status(outcome.status).render('login', { error: outcome.error });
      return;
    }

    // Must hold iam.admin.manage to use the console at all (architecture doc
    // §10) - a valid login that lacks it is redirected away, not shown a
    // half-working console; the attempt is still visible via the login's own
    // LOGIN_SUCCESS audit row plus a PERMISSION_DENIED on the first page load.
    const access = await getEffectiveAccess(pool, outcome.userId!);
    if (!access.isFullAccess && !access.perms.has(ADMIN_PERMISSION)) {
      res.status(403).render('login', { error: 'This account does not have admin console access.' });
      return;
    }

    const sessionId = crypto.randomBytes(32).toString('hex');
    adminSessions.set(sessionId, {
      token: signToken(outcome.userId!, outcome.username!),
      userId: outcome.userId!,
      username: outcome.username!,
      expiresAt: Date.now() + env.sessionTtlHours * 60 * 60 * 1000,
    });

    res.cookie(ADMIN_SESSION_COOKIE, sessionId, {
      httpOnly: true,
      sameSite: 'strict',
      secure: req.protocol === 'https',
      maxAge: env.sessionTtlHours * 60 * 60 * 1000,
    });
    res.redirect('/admin-ui');
  } catch (err) {
    next(err);
  }
});

router.post('/logout', (req: Request, res: Response) => {
  const sessionId = req.cookies?.[ADMIN_SESSION_COOKIE];
  if (sessionId) adminSessions.delete(sessionId);
  res.clearCookie(ADMIN_SESSION_COOKIE);
  res.redirect('/admin-ui/login');
});

// --- My Account (self-service - profile + change own password) ------------

router.get('/account', ...requireUiAdmin, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const pool = await getPool();
    const result = await pool
      .request()
      .input('id', sql.Int, req.authUser!.id)
      .query('SELECT UserId, Username, Email, DisplayName, LastLoginAt, PasswordChangedAt FROM Users WHERE UserId = @id');
    res.render('account', { authUser: req.authUser, account: result.recordset[0], error: null, notice: null });
  } catch (err) {
    next(err);
  }
});

router.post('/account', ...requireUiAdmin, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { displayName, email } = req.body || {};
    if (!email) {
      const pool = await getPool();
      const result = await pool.request().input('id', sql.Int, req.authUser!.id).query('SELECT UserId, Username, Email, DisplayName, LastLoginAt, PasswordChangedAt FROM Users WHERE UserId = @id');
      res.status(400).render('account', { authUser: req.authUser, account: result.recordset[0], error: 'Email is required.', notice: null });
      return;
    }

    const pool = await getPool();
    await pool
      .request()
      .input('id', sql.Int, req.authUser!.id)
      .input('displayName', sql.NVarChar(200), displayName || null)
      .input('email', sql.NVarChar(255), email)
      .query('UPDATE Users SET DisplayName = @displayName, Email = @email WHERE UserId = @id');

    const result = await pool.request().input('id', sql.Int, req.authUser!.id).query('SELECT UserId, Username, Email, DisplayName, LastLoginAt, PasswordChangedAt FROM Users WHERE UserId = @id');
    res.render('account', { authUser: { ...req.authUser!, displayName: displayName || req.authUser!.username }, account: result.recordset[0], error: null, notice: 'Profile updated.' });
  } catch (err) {
    next(err);
  }
});

router.post('/account/change-password', ...requireUiAdmin, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { currentPassword, newPassword } = req.body || {};
    const pool = await getPool();
    const accountResult = await pool.request().input('id', sql.Int, req.authUser!.id).query('SELECT UserId, Username, Email, DisplayName, PasswordHash, LastLoginAt, PasswordChangedAt FROM Users WHERE UserId = @id');
    const account = accountResult.recordset[0];

    async function rerender(status: number, error: string) {
      res.status(status).render('account', { authUser: req.authUser, account, error, notice: null });
    }

    if (!currentPassword || !newPassword) {
      await rerender(400, 'Current and new password are required.');
      return;
    }
    if (String(newPassword).length < MIN_PASSWORD_LENGTH) {
      await rerender(400, `New password must be at least ${MIN_PASSWORD_LENGTH} characters.`);
      return;
    }
    const ok = await bcrypt.compare(currentPassword, account.PasswordHash);
    if (!ok) {
      await rerender(401, 'Current password is incorrect.');
      return;
    }

    const passwordHash = await bcrypt.hash(newPassword, 12);
    await pool
      .request()
      .input('id', sql.Int, req.authUser!.id)
      .input('passwordHash', sql.NVarChar(255), passwordHash)
      .query('UPDATE Users SET PasswordHash = @passwordHash, PasswordChangedAt = SYSUTCDATETIME(), TokenValidAfter = SYSUTCDATETIME() WHERE UserId = @id');

    await writeAuditLog({ userId: req.authUser!.id, eventType: 'PASSWORD_CHANGED', ipAddress: clientIp(req) });

    // TokenValidAfter just moved past this request's own token's iat, so the
    // bridged Bearer header on the *next* request would fail requireAuth -
    // mint a fresh admin-console session immediately rather than bouncing
    // the admin who just changed their own password straight to a login
    // page that would look like the change silently failed.
    const sessionId = req.cookies?.[ADMIN_SESSION_COOKIE] as string;
    adminSessions.set(sessionId, {
      token: signToken(req.authUser!.id, req.authUser!.username),
      userId: req.authUser!.id,
      username: req.authUser!.username,
      expiresAt: Date.now() + env.sessionTtlHours * 60 * 60 * 1000,
    });

    res.render('account', { authUser: req.authUser, account, error: null, notice: 'Password changed.' });
  } catch (err) {
    next(err);
  }
});

// --- Dashboard --------------------------------------------------------------

router.get('/', ...requireUiAdmin, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const pool = await getPool();
    const [activeUsers, roles, apps, recentAudit] = await Promise.all([
      pool.request().query('SELECT COUNT(*) AS n FROM Users WHERE IsActive = 1'),
      pool.request().query('SELECT COUNT(*) AS n FROM Roles'),
      pool.request().query('SELECT COUNT(*) AS n FROM Apps'),
      pool.request().query('SELECT TOP 10 a.AuditId, a.EventType, a.AppKey, a.Detail, a.CreatedAt, u.Username FROM AuditLog a LEFT JOIN Users u ON u.UserId = a.UserId ORDER BY a.CreatedAt DESC'),
    ]);

    res.render('dashboard', {
      authUser: req.authUser,
      counts: { activeUsers: activeUsers.recordset[0].n, roles: roles.recordset[0].n, apps: apps.recordset[0].n },
      recentAudit: recentAudit.recordset,
    });
  } catch (err) {
    next(err);
  }
});

// --- Users --------------------------------------------------------------

router.get('/users', ...requireUiAdmin, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { search, status } = req.query as { search?: string; status?: string };
    const pool = await getPool();
    const request = pool.request();
    let where = '1=1';
    if (search) {
      request.input('search', sql.NVarChar(100), `%${search}%`);
      where += ' AND (u.Username LIKE @search OR u.Email LIKE @search OR u.DisplayName LIKE @search)';
    }
    if (status === 'active') where += ' AND u.IsActive = 1 AND u.IsLocked = 0';
    else if (status === 'inactive') where += ' AND u.IsActive = 0';
    else if (status === 'locked') where += ' AND u.IsLocked = 1';

    const result = await request.query(`
      SELECT u.UserId, u.Username, u.Email, u.DisplayName, u.IsActive, u.IsLocked, u.LastLoginAt,
             STRING_AGG(r.Name, ', ') AS RoleNames
      FROM Users u
      LEFT JOIN UserRoles ur ON ur.UserId = u.UserId
      LEFT JOIN Roles r ON r.RoleId = ur.RoleId
      WHERE ${where}
      GROUP BY u.UserId, u.Username, u.Email, u.DisplayName, u.IsActive, u.IsLocked, u.LastLoginAt
      ORDER BY u.Username
    `);

    res.render('users', { authUser: req.authUser, users: result.recordset, filters: { search, status } });
  } catch (err) {
    next(err);
  }
});

router.get('/users/new', ...requireUiAdmin, (req: Request, res: Response) => {
  res.render('user-new', { authUser: req.authUser, error: null });
});

router.post('/users/new', ...requireUiAdmin, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { username, email, displayName, password } = req.body || {};
    if (!username || String(username).trim().length < 3 || !email || !password || String(password).length < 8) {
      res.status(400).render('user-new', { authUser: req.authUser, error: 'Username (3+ chars), email, and an 8+ character password are required.' });
      return;
    }

    const pool = await getPool();
    const existing = await pool
      .request()
      .input('username', sql.NVarChar(100), username)
      .input('email', sql.NVarChar(255), email)
      .query('SELECT UserId FROM Users WHERE Username = @username OR Email = @email');
    if (existing.recordset[0]) {
      res.status(409).render('user-new', { authUser: req.authUser, error: 'A user with that username or email already exists.' });
      return;
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const result = await pool
      .request()
      .input('username', sql.NVarChar(100), username)
      .input('email', sql.NVarChar(255), email)
      .input('displayName', sql.NVarChar(200), displayName || username)
      .input('passwordHash', sql.NVarChar(255), passwordHash)
      .query('INSERT INTO Users (Username, Email, DisplayName, PasswordHash) VALUES (@username, @email, @displayName, @passwordHash); SELECT CAST(SCOPE_IDENTITY() AS INT) AS UserId;');

    res.redirect(`/admin-ui/users/${result.recordset[0].UserId}`);
  } catch (err) {
    next(err);
  }
});

router.get('/users/:id', ...requireUiAdmin, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const userId = Number(req.params.id);
    const pool = await getPool();

    const userResult = await pool
      .request()
      .input('id', sql.Int, userId)
      .query('SELECT UserId, Username, Email, DisplayName, IsActive, IsLocked, FailedLoginCount, LastLoginAt, CreatedAt FROM Users WHERE UserId = @id');
    const user = userResult.recordset[0];
    if (!user) {
      res.status(404).send('User not found.');
      return;
    }

    const [allRoles, userRoles, allGroups, userGroups] = await Promise.all([
      pool.request().query('SELECT RoleId, Name, IsFullAccess FROM Roles ORDER BY Name'),
      pool.request().input('id', sql.Int, userId).query('SELECT RoleId FROM UserRoles WHERE UserId = @id'),
      pool.request().query('SELECT GroupId, Name FROM UserGroups ORDER BY Name'),
      pool.request().input('id', sql.Int, userId).query('SELECT GroupId FROM UserGroupMembers WHERE UserId = @id'),
    ]);

    res.render('user-detail', {
      authUser: req.authUser,
      user,
      allRoles: allRoles.recordset,
      roleIds: (userRoles.recordset as { RoleId: number }[]).map((r) => r.RoleId),
      allGroups: allGroups.recordset,
      groupIds: (userGroups.recordset as { GroupId: number }[]).map((g) => g.GroupId),
    });
  } catch (err) {
    next(err);
  }
});

router.post('/users/:id', ...requireUiAdmin, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const userId = Number(req.params.id);
    const { displayName, email, isActive, isLocked } = req.body || {};
    const pool = await getPool();
    await pool
      .request()
      .input('id', sql.Int, userId)
      .input('displayName', sql.NVarChar(200), displayName || null)
      .input('email', sql.NVarChar(255), email)
      .input('isActive', sql.Bit, isActive === 'true')
      .input('isLocked', sql.Bit, isLocked === 'true')
      .query(
        'UPDATE Users SET DisplayName = @displayName, Email = @email, IsActive = @isActive, IsLocked = @isLocked, FailedLoginCount = CASE WHEN @isLocked = 0 THEN 0 ELSE FailedLoginCount END WHERE UserId = @id',
      );
    res.redirect(`/admin-ui/users/${userId}`);
  } catch (err) {
    next(err);
  }
});

router.post('/users/:id/reset-password', ...requireUiAdmin, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const userId = Number(req.params.id);
    const { password } = req.body || {};
    if (!password || String(password).length < 8) {
      res.status(400).send('Password must be at least 8 characters.');
      return;
    }
    const passwordHash = await bcrypt.hash(password, 12);
    const pool = await getPool();
    await pool
      .request()
      .input('id', sql.Int, userId)
      .input('passwordHash', sql.NVarChar(255), passwordHash)
      .query('UPDATE Users SET PasswordHash = @passwordHash, PasswordChangedAt = SYSUTCDATETIME(), TokenValidAfter = SYSUTCDATETIME() WHERE UserId = @id');
    res.redirect(`/admin-ui/users/${userId}`);
  } catch (err) {
    next(err);
  }
});

router.post('/users/:id/roles', ...requireUiAdmin, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const userId = Number(req.params.id);
    const { roleId, action } = req.body || {};
    const pool = await getPool();
    if (action === 'add') {
      await pool
        .request()
        .input('userId', sql.Int, userId)
        .input('roleId', sql.Int, roleId)
        .query('IF NOT EXISTS (SELECT 1 FROM UserRoles WHERE UserId = @userId AND RoleId = @roleId) INSERT INTO UserRoles (UserId, RoleId) VALUES (@userId, @roleId)');
    } else {
      await pool.request().input('userId', sql.Int, userId).input('roleId', sql.Int, roleId).query('DELETE FROM UserRoles WHERE UserId = @userId AND RoleId = @roleId');
    }
    res.status(204).end();
  } catch (err) {
    next(err);
  }
});

router.post('/users/:id/groups', ...requireUiAdmin, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const userId = Number(req.params.id);
    const { groupId, action } = req.body || {};
    const pool = await getPool();
    if (action === 'add') {
      await pool
        .request()
        .input('userId', sql.Int, userId)
        .input('groupId', sql.Int, groupId)
        .query('IF NOT EXISTS (SELECT 1 FROM UserGroupMembers WHERE UserId = @userId AND GroupId = @groupId) INSERT INTO UserGroupMembers (UserId, GroupId) VALUES (@userId, @groupId)');
    } else {
      await pool.request().input('userId', sql.Int, userId).input('groupId', sql.Int, groupId).query('DELETE FROM UserGroupMembers WHERE UserId = @userId AND GroupId = @groupId');
    }
    res.status(204).end();
  } catch (err) {
    next(err);
  }
});

router.post('/users/:id/force-logout', ...requireUiAdmin, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const userId = Number(req.params.id);
    const pool = await getPool();
    await pool.request().input('id', sql.Int, userId).query('UPDATE Users SET TokenValidAfter = SYSUTCDATETIME() WHERE UserId = @id');
    res.redirect(`/admin-ui/users/${userId}`);
  } catch (err) {
    next(err);
  }
});

// --- Roles ----------------------------------------------------------------

router.get('/roles', ...requireUiAdmin, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const pool = await getPool();
    const result = await pool.request().query(`
      SELECT r.RoleId, r.Name, r.Description, r.IsFullAccess,
             (SELECT COUNT(*) FROM UserRoles ur WHERE ur.RoleId = r.RoleId) AS UserCount,
             (SELECT COUNT(*) FROM RolePermissions rp WHERE rp.RoleId = r.RoleId) AS PermissionCount
      FROM Roles r ORDER BY r.Name
    `);
    res.render('roles', { authUser: req.authUser, roles: result.recordset });
  } catch (err) {
    next(err);
  }
});

router.post('/roles', ...requireUiAdmin, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { name, description } = req.body || {};
    if (!name || String(name).trim().length < 2) {
      res.status(400).send('Role name must be at least 2 characters.');
      return;
    }
    const pool = await getPool();
    await pool
      .request()
      .input('name', sql.NVarChar(100), name)
      .input('description', sql.NVarChar(400), description || null)
      .query('INSERT INTO Roles (Name, Description) VALUES (@name, @description)');
    res.redirect('/admin-ui/roles');
  } catch (err) {
    next(err);
  }
});

// Splits "leads.leads.export" into module path "leads.leads" (everything but
// the last segment) and action "export" (the last segment) - purely a
// display grouping for the matrix screen; the stored Key stays one flat
// string (architecture doc §6.1) and this parsing lives only here.
function splitPermissionKey(key: string): { modulePath: string; action: string } {
  const lastDot = key.lastIndexOf('.');
  return { modulePath: key.slice(0, lastDot), action: key.slice(lastDot + 1) };
}

router.get('/roles/:id', ...requireUiAdmin, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const roleId = Number(req.params.id);
    const pool = await getPool();

    const role = await pool.request().input('id', sql.Int, roleId).query('SELECT RoleId, Name, Description, IsFullAccess FROM Roles WHERE RoleId = @id');
    if (!role.recordset[0]) {
      res.status(404).send('Role not found.');
      return;
    }

    const allPerms = await pool.request().query(`
      SELECT p.PermissionId, p.[Key], a.[Key] AS AppKey, a.Name AS AppName
      FROM Permissions p JOIN Apps a ON a.AppId = p.AppId
      ORDER BY a.Name, p.[Key]
    `);
    const granted = await pool.request().input('roleId', sql.Int, roleId).query('SELECT PermissionId FROM RolePermissions WHERE RoleId = @roleId');
    const grantedIds = new Set((granted.recordset as { PermissionId: number }[]).map((r) => r.PermissionId));

    type PermRow = { PermissionId: number; Key: string; AppKey: string; AppName: string };
    const byApp = new Map<string, { appKey: string; appName: string; actions: Set<string>; modules: Map<string, Record<string, { permissionId: number; granted: boolean }>> }>();

    for (const row of allPerms.recordset as PermRow[]) {
      if (!byApp.has(row.AppKey)) byApp.set(row.AppKey, { appKey: row.AppKey, appName: row.AppName, actions: new Set(), modules: new Map() });
      const app = byApp.get(row.AppKey)!;
      const { modulePath, action } = splitPermissionKey(row.Key);
      app.actions.add(action);
      if (!app.modules.has(modulePath)) app.modules.set(modulePath, {});
      app.modules.get(modulePath)![action] = { permissionId: row.PermissionId, granted: grantedIds.has(row.PermissionId) };
    }

    const appsGrouped = [...byApp.values()].map((app) => ({
      appKey: app.appKey,
      appName: app.appName,
      actions: [...app.actions].sort(),
      modules: [...app.modules.entries()].map(([modulePath, cells]) => ({ modulePath, cells })),
    }));

    res.render('role-permissions', { authUser: req.authUser, role: role.recordset[0], appsGrouped });
  } catch (err) {
    next(err);
  }
});

router.post('/roles/:id', ...requireUiAdmin, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const roleId = Number(req.params.id);
    const { name, description } = req.body || {};
    if (!name || String(name).trim().length < 2) {
      res.status(400).send('Role name must be at least 2 characters.');
      return;
    }
    const pool = await getPool();
    await pool
      .request()
      .input('id', sql.Int, roleId)
      .input('name', sql.NVarChar(100), name)
      .input('description', sql.NVarChar(400), description || null)
      .query('UPDATE Roles SET Name = @name, Description = @description WHERE RoleId = @id');
    res.redirect(`/admin-ui/roles/${roleId}`);
  } catch (err) {
    next(err);
  }
});

// A full-access role bypasses RolePermissions entirely (schema comment on
// Roles.IsFullAccess) - deleting the wrong one here could strip every admin
// of console access with no way back in through this same console, so it's
// blocked outright rather than just confirmed.
router.post('/roles/:id/delete', ...requireUiAdmin, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const roleId = Number(req.params.id);
    const pool = await getPool();
    const role = await pool.request().input('id', sql.Int, roleId).query('SELECT IsFullAccess FROM Roles WHERE RoleId = @id');
    if (!role.recordset[0]) {
      res.status(404).send('Role not found.');
      return;
    }
    if (role.recordset[0].IsFullAccess) {
      res.status(400).send('Full-access roles cannot be deleted.');
      return;
    }
    await pool.request().input('id', sql.Int, roleId).query('DELETE FROM Roles WHERE RoleId = @id');
    res.redirect('/admin-ui/roles');
  } catch (err) {
    next(err);
  }
});

router.post('/roles/:id/permissions', ...requireUiAdmin, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const roleId = Number(req.params.id);
    const { permissionId, action } = req.body || {};
    const pool = await getPool();
    if (action === 'add') {
      await pool
        .request()
        .input('roleId', sql.Int, roleId)
        .input('permissionId', sql.Int, permissionId)
        .query('IF NOT EXISTS (SELECT 1 FROM RolePermissions WHERE RoleId = @roleId AND PermissionId = @permissionId) INSERT INTO RolePermissions (RoleId, PermissionId) VALUES (@roleId, @permissionId)');
    } else {
      await pool.request().input('roleId', sql.Int, roleId).input('permissionId', sql.Int, permissionId).query('DELETE FROM RolePermissions WHERE RoleId = @roleId AND PermissionId = @permissionId');
    }
    res.status(204).end();
  } catch (err) {
    next(err);
  }
});

// --- Groups -----------------------------------------------------------------

router.get('/groups', ...requireUiAdmin, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const pool = await getPool();
    const result = await pool.request().query(`
      SELECT g.GroupId, g.Name, g.Description,
             (SELECT COUNT(*) FROM UserGroupMembers m WHERE m.GroupId = g.GroupId) AS MemberCount,
             (SELECT COUNT(*) FROM GroupRoles gr WHERE gr.GroupId = g.GroupId) AS RoleCount
      FROM UserGroups g ORDER BY g.Name
    `);
    res.render('groups', { authUser: req.authUser, groups: result.recordset });
  } catch (err) {
    next(err);
  }
});

router.post('/groups', ...requireUiAdmin, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { name, description } = req.body || {};
    if (!name || String(name).trim().length < 2) {
      res.status(400).send('Group name must be at least 2 characters.');
      return;
    }
    const pool = await getPool();
    await pool
      .request()
      .input('name', sql.NVarChar(150), name)
      .input('description', sql.NVarChar(400), description || null)
      .query('INSERT INTO UserGroups (Name, Description) VALUES (@name, @description)');
    res.redirect('/admin-ui/groups');
  } catch (err) {
    next(err);
  }
});

router.get('/groups/:id', ...requireUiAdmin, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const groupId = Number(req.params.id);
    const pool = await getPool();

    const group = await pool.request().input('id', sql.Int, groupId).query('SELECT GroupId, Name, Description FROM UserGroups WHERE GroupId = @id');
    if (!group.recordset[0]) {
      res.status(404).send('Group not found.');
      return;
    }

    const [members, allRoles, groupRoles] = await Promise.all([
      pool.request().input('id', sql.Int, groupId).query('SELECT u.UserId, u.Username, u.DisplayName FROM UserGroupMembers m JOIN Users u ON u.UserId = m.UserId WHERE m.GroupId = @id ORDER BY u.Username'),
      pool.request().query('SELECT RoleId, Name FROM Roles ORDER BY Name'),
      pool.request().input('id', sql.Int, groupId).query('SELECT RoleId FROM GroupRoles WHERE GroupId = @id'),
    ]);

    res.render('group-detail', {
      authUser: req.authUser,
      group: group.recordset[0],
      members: members.recordset,
      allRoles: allRoles.recordset,
      roleIds: (groupRoles.recordset as { RoleId: number }[]).map((r) => r.RoleId),
    });
  } catch (err) {
    next(err);
  }
});

router.post('/groups/:id', ...requireUiAdmin, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const groupId = Number(req.params.id);
    const { name, description } = req.body || {};
    if (!name || String(name).trim().length < 2) {
      res.status(400).send('Group name must be at least 2 characters.');
      return;
    }
    const pool = await getPool();
    await pool
      .request()
      .input('id', sql.Int, groupId)
      .input('name', sql.NVarChar(150), name)
      .input('description', sql.NVarChar(400), description || null)
      .query('UPDATE UserGroups SET Name = @name, Description = @description WHERE GroupId = @id');
    res.redirect(`/admin-ui/groups/${groupId}`);
  } catch (err) {
    next(err);
  }
});

router.post('/groups/:id/delete', ...requireUiAdmin, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const groupId = Number(req.params.id);
    const pool = await getPool();
    await pool.request().input('id', sql.Int, groupId).query('DELETE FROM UserGroups WHERE GroupId = @id');
    res.redirect('/admin-ui/groups');
  } catch (err) {
    next(err);
  }
});

router.post('/groups/:id/roles', ...requireUiAdmin, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const groupId = Number(req.params.id);
    const { roleId, action } = req.body || {};
    const pool = await getPool();
    if (action === 'add') {
      await pool
        .request()
        .input('groupId', sql.Int, groupId)
        .input('roleId', sql.Int, roleId)
        .query('IF NOT EXISTS (SELECT 1 FROM GroupRoles WHERE GroupId = @groupId AND RoleId = @roleId) INSERT INTO GroupRoles (GroupId, RoleId) VALUES (@groupId, @roleId)');
    } else {
      await pool.request().input('groupId', sql.Int, groupId).input('roleId', sql.Int, roleId).query('DELETE FROM GroupRoles WHERE GroupId = @groupId AND RoleId = @roleId');
    }
    res.status(204).end();
  } catch (err) {
    next(err);
  }
});

router.post('/groups/:id/members', ...requireUiAdmin, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const groupId = Number(req.params.id);
    const { userId, action } = req.body || {};
    const pool = await getPool();
    if (action === 'add') {
      await pool
        .request()
        .input('userId', sql.Int, userId)
        .input('groupId', sql.Int, groupId)
        .query('IF NOT EXISTS (SELECT 1 FROM UserGroupMembers WHERE UserId = @userId AND GroupId = @groupId) INSERT INTO UserGroupMembers (UserId, GroupId) VALUES (@userId, @groupId)');
    } else {
      await pool.request().input('userId', sql.Int, userId).input('groupId', sql.Int, groupId).query('DELETE FROM UserGroupMembers WHERE UserId = @userId AND GroupId = @groupId');
    }
    res.status(204).end();
  } catch (err) {
    next(err);
  }
});

// --- Apps -----------------------------------------------------------------

router.get('/apps', ...requireUiAdmin, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const pool = await getPool();
    const result = await pool.request().query(`
      SELECT a.AppId, a.[Key], a.Name, a.BaseUrl, a.IsActive,
             (SELECT COUNT(*) FROM Permissions p WHERE p.AppId = a.AppId) AS PermissionCount
      FROM Apps a ORDER BY a.Name
    `);
    res.render('apps', { authUser: req.authUser, apps: result.recordset });
  } catch (err) {
    next(err);
  }
});

router.post('/apps', ...requireUiAdmin, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { key, name, baseUrl } = req.body || {};
    if (!key || !name || !/^[a-z][a-z0-9-]*$/.test(key)) {
      res.status(400).send('A lowercase key (letters, digits, hyphens) and a name are required.');
      return;
    }
    const pool = await getPool();
    await pool
      .request()
      .input('key', sql.NVarChar(50), key)
      .input('name', sql.NVarChar(150), name)
      .input('baseUrl', sql.NVarChar(300), baseUrl || null)
      .query('INSERT INTO Apps ([Key], Name, BaseUrl) VALUES (@key, @name, @baseUrl)');
    res.redirect('/admin-ui/apps');
  } catch (err) {
    next(err);
  }
});

router.get('/apps/:key/edit', ...requireUiAdmin, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const pool = await getPool();
    const result = await pool
      .request()
      .input('key', sql.NVarChar(50), req.params.key)
      .query('SELECT AppId, [Key], Name, BaseUrl, IsActive FROM Apps WHERE [Key] = @key');
    const app = result.recordset[0];
    if (!app) {
      res.status(404).send('App not found.');
      return;
    }
    res.render('app-edit', { authUser: req.authUser, app, error: null });
  } catch (err) {
    next(err);
  }
});

// The Key itself is immutable here - it's the namespace prefix every one of
// this app's permission keys already carries (architecture doc §6.1/§8.3);
// renaming it would orphan every existing permission key. Register a new
// app instead if the key itself needs to change.
router.post('/apps/:key/edit', ...requireUiAdmin, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { name, baseUrl, isActive } = req.body || {};
    if (!name) {
      const pool = await getPool();
      const result = await pool.request().input('key', sql.NVarChar(50), req.params.key).query('SELECT AppId, [Key], Name, BaseUrl, IsActive FROM Apps WHERE [Key] = @key');
      res.status(400).render('app-edit', { authUser: req.authUser, app: result.recordset[0], error: 'Name is required.' });
      return;
    }

    const pool = await getPool();
    await pool
      .request()
      .input('key', sql.NVarChar(50), req.params.key)
      .input('name', sql.NVarChar(150), name)
      .input('baseUrl', sql.NVarChar(300), baseUrl || null)
      .input('isActive', sql.Bit, isActive === 'true')
      .query('UPDATE Apps SET Name = @name, BaseUrl = @baseUrl, IsActive = @isActive WHERE [Key] = @key');

    res.redirect('/admin-ui/apps');
  } catch (err) {
    next(err);
  }
});

// Cascades to this app's Permissions and, from there, to RolePermissions
// (schema FK_Permissions_App / FK_RolePermissions_Permission) - any role
// holding one of this app's permissions silently loses it, so the template
// confirms with the permission count before submitting.
router.post('/apps/:key/delete', ...requireUiAdmin, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const pool = await getPool();
    const result = await pool.request().input('key', sql.NVarChar(50), req.params.key).query('DELETE FROM Apps WHERE [Key] = @key');
    if (result.rowsAffected[0] === 0) {
      res.status(404).send('App not found.');
      return;
    }
    res.redirect('/admin-ui/apps');
  } catch (err) {
    next(err);
  }
});

// --- Audit ------------------------------------------------------------------

const AUDIT_PAGE_SIZE = 50;

router.get('/audit', ...requireUiAdmin, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { page = '1', eventType, appKey } = req.query as Record<string, string>;
    const pageNum = Math.max(1, Number(page) || 1);
    const pool = await getPool();
    const request = pool.request();
    let where = '1=1';
    if (eventType) {
      request.input('eventType', sql.NVarChar(50), eventType);
      where += ' AND a.EventType = @eventType';
    }
    if (appKey) {
      request.input('appKey', sql.NVarChar(50), appKey);
      where += ' AND a.AppKey = @appKey';
    }
    request.input('offset', sql.Int, (pageNum - 1) * AUDIT_PAGE_SIZE).input('pageSize', sql.Int, AUDIT_PAGE_SIZE);

    const result = await request.query(`
      SELECT a.AuditId, a.EventType, a.AppKey, a.Detail, a.IpAddress, a.CreatedAt, u.Username
      FROM AuditLog a LEFT JOIN Users u ON u.UserId = a.UserId
      WHERE ${where}
      ORDER BY a.CreatedAt DESC
      OFFSET @offset ROWS FETCH NEXT @pageSize ROWS ONLY
    `);

    res.render('audit', { authUser: req.authUser, entries: result.recordset, page: pageNum, pageSize: AUDIT_PAGE_SIZE, filters: { eventType, appKey } });
  } catch (err) {
    next(err);
  }
});

export default router;
