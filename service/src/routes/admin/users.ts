import bcrypt from 'bcryptjs';
import { Router } from 'express';
import { getPool, sql } from '../../config/db';
import { requireAuth, requireAdmin } from '../../middleware/auth';
import { writeAuditLog, clientIp } from '../../lib/audit';
import { getEffectiveAccess } from '../../lib/permissions';

const router = Router();
router.use(requireAuth, requireAdmin);

const MIN_PASSWORD_LENGTH = 8; // architecture doc §16.5

// GET /admin/users?search=&role=&status=active|locked|inactive
router.get('/', async (req, res, next) => {
  try {
    const { search, role, status } = req.query as { search?: string; role?: string; status?: string };
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
    if (role) {
      request.input('role', sql.NVarChar(100), role);
      where += ` AND u.UserId IN (
        SELECT ur.UserId FROM UserRoles ur JOIN Roles r ON r.RoleId = ur.RoleId WHERE r.Name = @role
      )`;
    }

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
    res.json({ users: result.recordset });
  } catch (err) {
    next(err);
  }
});

// POST /admin/users - onboard a new employee (architecture doc §10 "Users - create")
router.post('/', async (req, res, next) => {
  try {
    const { username, email, displayName, password } = req.body || {};
    if (!username || String(username).trim().length < 3) {
      res.status(400).json({ error: 'Username must be at least 3 characters.' });
      return;
    }
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      res.status(400).json({ error: 'A valid email is required.' });
      return;
    }
    if (!password || String(password).length < MIN_PASSWORD_LENGTH) {
      res.status(400).json({ error: `Password must be at least ${MIN_PASSWORD_LENGTH} characters.` });
      return;
    }

    const pool = await getPool();
    const existing = await pool
      .request()
      .input('username', sql.NVarChar(100), username)
      .input('email', sql.NVarChar(255), email)
      .query('SELECT UserId FROM Users WHERE Username = @username OR Email = @email');
    if (existing.recordset[0]) {
      res.status(409).json({ error: 'A user with that username or email already exists.' });
      return;
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const result = await pool
      .request()
      .input('username', sql.NVarChar(100), username)
      .input('email', sql.NVarChar(255), email)
      .input('displayName', sql.NVarChar(200), displayName || username)
      .input('passwordHash', sql.NVarChar(255), passwordHash)
      .query(
        'INSERT INTO Users (Username, Email, DisplayName, PasswordHash) VALUES (@username, @email, @displayName, @passwordHash); SELECT CAST(SCOPE_IDENTITY() AS INT) AS UserId;',
      );

    res.status(201).json({ userId: result.recordset[0].UserId });
  } catch (err) {
    next(err);
  }
});

// GET /admin/users/:id - detail screen: profile, roles, groups
router.get('/:id', async (req, res, next) => {
  try {
    const userId = Number(req.params.id);
    const pool = await getPool();
    const userResult = await pool
      .request()
      .input('id', sql.Int, userId)
      .query('SELECT UserId, Username, Email, DisplayName, IsActive, IsLocked, FailedLoginCount, LastLoginAt, PasswordChangedAt, CreatedAt FROM Users WHERE UserId = @id');

    const user = userResult.recordset[0];
    if (!user) {
      res.status(404).json({ error: 'User not found.' });
      return;
    }

    const roles = await pool
      .request()
      .input('id', sql.Int, userId)
      .query('SELECT r.RoleId, r.Name FROM UserRoles ur JOIN Roles r ON r.RoleId = ur.RoleId WHERE ur.UserId = @id ORDER BY r.Name');

    const groups = await pool
      .request()
      .input('id', sql.Int, userId)
      .query('SELECT g.GroupId, g.Name FROM UserGroupMembers m JOIN UserGroups g ON g.GroupId = m.GroupId WHERE m.UserId = @id ORDER BY g.Name');

    const access = await getEffectiveAccess(pool, userId);

    res.json({
      user,
      roles: roles.recordset,
      groups: groups.recordset,
      effectivePerms: [...access.perms],
      isFullAccess: access.isFullAccess,
    });
  } catch (err) {
    next(err);
  }
});

// POST /admin/users/:id - update profile / active-locked state / reset password
router.post('/:id', async (req, res, next) => {
  try {
    const userId = Number(req.params.id);
    const { displayName, email, isActive, isLocked, password } = req.body || {};
    const pool = await getPool();

    const existing = await pool.request().input('id', sql.Int, userId).query('SELECT UserId FROM Users WHERE UserId = @id');
    if (!existing.recordset[0]) {
      res.status(404).json({ error: 'User not found.' });
      return;
    }

    const sets: string[] = [];
    const request = pool.request().input('id', sql.Int, userId);

    if (displayName !== undefined) {
      sets.push('DisplayName = @displayName');
      request.input('displayName', sql.NVarChar(200), displayName);
    }
    if (email !== undefined) {
      sets.push('Email = @email');
      request.input('email', sql.NVarChar(255), email);
    }
    if (isActive !== undefined) {
      sets.push('IsActive = @isActive');
      request.input('isActive', sql.Bit, Boolean(isActive));
    }
    if (isLocked !== undefined) {
      sets.push('IsLocked = @isLocked', 'FailedLoginCount = 0');
      request.input('isLocked', sql.Bit, Boolean(isLocked));
    }
    if (password) {
      if (String(password).length < MIN_PASSWORD_LENGTH) {
        res.status(400).json({ error: `Password must be at least ${MIN_PASSWORD_LENGTH} characters.` });
        return;
      }
      const passwordHash = await bcrypt.hash(password, 12);
      sets.push('PasswordHash = @passwordHash', 'PasswordChangedAt = SYSUTCDATETIME()', 'TokenValidAfter = SYSUTCDATETIME()');
      request.input('passwordHash', sql.NVarChar(255), passwordHash);
    }

    if (sets.length === 0) {
      res.status(400).json({ error: 'Nothing to update.' });
      return;
    }

    await request.query(`UPDATE Users SET ${sets.join(', ')} WHERE UserId = @id`);
    res.status(204).end();
  } catch (err) {
    next(err);
  }
});

// POST /admin/users/:id/roles {roleId, action: 'add' | 'remove'}
router.post('/:id/roles', async (req, res, next) => {
  try {
    const userId = Number(req.params.id);
    const { roleId, action } = req.body || {};
    if (!roleId || !['add', 'remove'].includes(action)) {
      res.status(400).json({ error: 'roleId and action ("add" or "remove") are required.' });
      return;
    }

    const pool = await getPool();
    if (action === 'add') {
      await pool
        .request()
        .input('userId', sql.Int, userId)
        .input('roleId', sql.Int, roleId)
        .query(
          'IF NOT EXISTS (SELECT 1 FROM UserRoles WHERE UserId = @userId AND RoleId = @roleId) INSERT INTO UserRoles (UserId, RoleId) VALUES (@userId, @roleId)',
        );
    } else {
      await pool.request().input('userId', sql.Int, userId).input('roleId', sql.Int, roleId).query('DELETE FROM UserRoles WHERE UserId = @userId AND RoleId = @roleId');
    }

    await writeAuditLog({
      userId: req.authUser!.id,
      eventType: 'ROLE_CHANGED',
      detail: `target user ${userId}, role ${roleId}, ${action}ed`,
      ipAddress: clientIp(req),
    });
    res.status(204).end();
  } catch (err) {
    next(err);
  }
});

// POST /admin/users/:id/groups {groupId, action: 'add' | 'remove'}
router.post('/:id/groups', async (req, res, next) => {
  try {
    const userId = Number(req.params.id);
    const { groupId, action } = req.body || {};
    if (!groupId || !['add', 'remove'].includes(action)) {
      res.status(400).json({ error: 'groupId and action ("add" or "remove") are required.' });
      return;
    }

    const pool = await getPool();
    if (action === 'add') {
      await pool
        .request()
        .input('userId', sql.Int, userId)
        .input('groupId', sql.Int, groupId)
        .query(
          'IF NOT EXISTS (SELECT 1 FROM UserGroupMembers WHERE UserId = @userId AND GroupId = @groupId) INSERT INTO UserGroupMembers (UserId, GroupId) VALUES (@userId, @groupId)',
        );
    } else {
      await pool.request().input('userId', sql.Int, userId).input('groupId', sql.Int, groupId).query('DELETE FROM UserGroupMembers WHERE UserId = @userId AND GroupId = @groupId');
    }

    await writeAuditLog({
      userId: req.authUser!.id,
      eventType: 'GROUP_CHANGED',
      detail: `target user ${userId}, group ${groupId}, ${action}ed`,
      ipAddress: clientIp(req),
    });
    res.status(204).end();
  } catch (err) {
    next(err);
  }
});

// POST /admin/users/:id/force-logout - bumps TokenValidAfter (architecture
// doc §6.4): invalidates every session across every app within one
// re-verify cycle (<=5 min), with no per-session bookkeeping.
router.post('/:id/force-logout', async (req, res, next) => {
  try {
    const userId = Number(req.params.id);
    const pool = await getPool();
    await pool.request().input('id', sql.Int, userId).query('UPDATE Users SET TokenValidAfter = SYSUTCDATETIME() WHERE UserId = @id');

    await writeAuditLog({
      userId: req.authUser!.id,
      eventType: 'FORCE_LOGOUT',
      detail: `target user ${userId}`,
      ipAddress: clientIp(req),
    });
    res.status(204).end();
  } catch (err) {
    next(err);
  }
});

export default router;
