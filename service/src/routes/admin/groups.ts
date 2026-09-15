import { Router } from 'express';
import { getPool, sql } from '../../config/db';
import { requireAuth, requireAdmin } from '../../middleware/auth';
import { writeAuditLog, clientIp } from '../../lib/audit';

const router = Router();
router.use(requireAuth, requireAdmin);

// GET /admin/groups - optional grouping layer (department, team, ...) that
// grants member users every role assigned to the group (architecture doc §7).
router.get('/', async (_req, res, next) => {
  try {
    const pool = await getPool();
    const result = await pool.request().query(`
      SELECT g.GroupId, g.Name, g.Description,
             (SELECT COUNT(*) FROM UserGroupMembers m WHERE m.GroupId = g.GroupId) AS MemberCount,
             (SELECT COUNT(*) FROM GroupRoles gr WHERE gr.GroupId = g.GroupId) AS RoleCount
      FROM UserGroups g ORDER BY g.Name
    `);
    res.json({ groups: result.recordset });
  } catch (err) {
    next(err);
  }
});

router.post('/', async (req, res, next) => {
  try {
    const { name, description } = req.body || {};
    if (!name || String(name).trim().length < 2) {
      res.status(400).json({ error: 'Group name must be at least 2 characters.' });
      return;
    }

    const pool = await getPool();
    const existing = await pool.request().input('name', sql.NVarChar(150), name).query('SELECT GroupId FROM UserGroups WHERE Name = @name');
    if (existing.recordset[0]) {
      res.status(409).json({ error: `Group "${name}" already exists.` });
      return;
    }

    const result = await pool
      .request()
      .input('name', sql.NVarChar(150), name)
      .input('description', sql.NVarChar(400), description || null)
      .query('INSERT INTO UserGroups (Name, Description) VALUES (@name, @description); SELECT CAST(SCOPE_IDENTITY() AS INT) AS GroupId;');

    res.status(201).json({ groupId: result.recordset[0].GroupId });
  } catch (err) {
    next(err);
  }
});

// GET /admin/groups/:id - detail: profile, members, granted roles
router.get('/:id', async (req, res, next) => {
  try {
    const groupId = Number(req.params.id);
    const pool = await getPool();

    const group = await pool.request().input('id', sql.Int, groupId).query('SELECT GroupId, Name, Description FROM UserGroups WHERE GroupId = @id');
    if (!group.recordset[0]) {
      res.status(404).json({ error: 'Group not found.' });
      return;
    }

    const members = await pool
      .request()
      .input('id', sql.Int, groupId)
      .query('SELECT u.UserId, u.Username, u.DisplayName FROM UserGroupMembers m JOIN Users u ON u.UserId = m.UserId WHERE m.GroupId = @id ORDER BY u.Username');

    const roles = await pool
      .request()
      .input('id', sql.Int, groupId)
      .query('SELECT r.RoleId, r.Name FROM GroupRoles gr JOIN Roles r ON r.RoleId = gr.RoleId WHERE gr.GroupId = @id ORDER BY r.Name');

    res.json({ group: group.recordset[0], members: members.recordset, roles: roles.recordset });
  } catch (err) {
    next(err);
  }
});

// POST /admin/groups/:id - update name/description
router.post('/:id', async (req, res, next) => {
  try {
    const groupId = Number(req.params.id);
    const { name, description } = req.body || {};
    if (!name || String(name).trim().length < 2) {
      res.status(400).json({ error: 'Group name must be at least 2 characters.' });
      return;
    }

    const pool = await getPool();
    const existing = await pool.request().input('id', sql.Int, groupId).query('SELECT GroupId FROM UserGroups WHERE GroupId = @id');
    if (!existing.recordset[0]) {
      res.status(404).json({ error: 'Group not found.' });
      return;
    }

    const dupe = await pool.request().input('name', sql.NVarChar(150), name).input('id', sql.Int, groupId).query('SELECT GroupId FROM UserGroups WHERE Name = @name AND GroupId <> @id');
    if (dupe.recordset[0]) {
      res.status(409).json({ error: `Another group is already named "${name}".` });
      return;
    }

    await pool
      .request()
      .input('id', sql.Int, groupId)
      .input('name', sql.NVarChar(150), name)
      .input('description', sql.NVarChar(400), description || null)
      .query('UPDATE UserGroups SET Name = @name, Description = @description WHERE GroupId = @id');
    res.status(204).end();
  } catch (err) {
    next(err);
  }
});

// POST /admin/groups/:id/delete - members/role-grants cascade (FK ON DELETE
// CASCADE in the schema); users in the group keep any roles held directly,
// they only lose whatever this group itself granted them.
router.post('/:id/delete', async (req, res, next) => {
  try {
    const groupId = Number(req.params.id);
    const pool = await getPool();
    const existing = await pool.request().input('id', sql.Int, groupId).query('SELECT Name FROM UserGroups WHERE GroupId = @id');
    if (!existing.recordset[0]) {
      res.status(404).json({ error: 'Group not found.' });
      return;
    }

    await pool.request().input('id', sql.Int, groupId).query('DELETE FROM UserGroups WHERE GroupId = @id');
    await writeAuditLog({
      userId: req.authUser!.id,
      eventType: 'GROUP_CHANGED',
      detail: `deleted group "${existing.recordset[0].Name}" (id ${groupId})`,
      ipAddress: clientIp(req),
    });
    res.status(204).end();
  } catch (err) {
    next(err);
  }
});

// POST /admin/groups/:id/members {userId, action: 'add' | 'remove'}
router.post('/:id/members', async (req, res, next) => {
  try {
    const groupId = Number(req.params.id);
    const { userId, action } = req.body || {};
    if (!userId || !['add', 'remove'].includes(action)) {
      res.status(400).json({ error: 'userId and action ("add" or "remove") are required.' });
      return;
    }

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

// POST /admin/groups/:id/roles {roleId, action: 'add' | 'remove'}
router.post('/:id/roles', async (req, res, next) => {
  try {
    const groupId = Number(req.params.id);
    const { roleId, action } = req.body || {};
    if (!roleId || !['add', 'remove'].includes(action)) {
      res.status(400).json({ error: 'roleId and action ("add" or "remove") are required.' });
      return;
    }

    const pool = await getPool();
    if (action === 'add') {
      await pool
        .request()
        .input('groupId', sql.Int, groupId)
        .input('roleId', sql.Int, roleId)
        .query(
          'IF NOT EXISTS (SELECT 1 FROM GroupRoles WHERE GroupId = @groupId AND RoleId = @roleId) INSERT INTO GroupRoles (GroupId, RoleId) VALUES (@groupId, @roleId)',
        );
    } else {
      await pool.request().input('groupId', sql.Int, groupId).input('roleId', sql.Int, roleId).query('DELETE FROM GroupRoles WHERE GroupId = @groupId AND RoleId = @roleId');
    }
    res.status(204).end();
  } catch (err) {
    next(err);
  }
});

export default router;
