import { Router } from 'express';
import { getPool, sql } from '../../config/db';
import { requireAuth, requireAdmin } from '../../middleware/auth';
import { writeAuditLog, clientIp } from '../../lib/audit';

const router = Router();
router.use(requireAuth, requireAdmin);

// GET /admin/roles - list with counts (architecture doc §10 "Roles - list")
router.get('/', async (_req, res, next) => {
  try {
    const pool = await getPool();
    const result = await pool.request().query(`
      SELECT r.RoleId, r.Name, r.Description, r.IsFullAccess,
             (SELECT COUNT(*) FROM UserRoles ur WHERE ur.RoleId = r.RoleId) AS UserCount,
             (SELECT COUNT(*) FROM RolePermissions rp WHERE rp.RoleId = r.RoleId) AS PermissionCount
      FROM Roles r ORDER BY r.Name
    `);
    res.json({ roles: result.recordset });
  } catch (err) {
    next(err);
  }
});

// POST /admin/roles - create a role
router.post('/', async (req, res, next) => {
  try {
    const { name, description } = req.body || {};
    if (!name || String(name).trim().length < 2) {
      res.status(400).json({ error: 'Role name must be at least 2 characters.' });
      return;
    }

    const pool = await getPool();
    const existing = await pool.request().input('name', sql.NVarChar(100), name).query('SELECT RoleId FROM Roles WHERE Name = @name');
    if (existing.recordset[0]) {
      res.status(409).json({ error: `Role "${name}" already exists.` });
      return;
    }

    const result = await pool
      .request()
      .input('name', sql.NVarChar(100), name)
      .input('description', sql.NVarChar(400), description || null)
      .query('INSERT INTO Roles (Name, Description) VALUES (@name, @description); SELECT CAST(SCOPE_IDENTITY() AS INT) AS RoleId;');

    res.status(201).json({ roleId: result.recordset[0].RoleId });
  } catch (err) {
    next(err);
  }
});

// GET /admin/roles/:id/permissions - grouped by app, for the permission
// matrix screen (architecture doc §10)
router.get('/:id/permissions', async (req, res, next) => {
  try {
    const roleId = Number(req.params.id);
    const pool = await getPool();

    const role = await pool.request().input('id', sql.Int, roleId).query('SELECT RoleId, Name FROM Roles WHERE RoleId = @id');
    if (!role.recordset[0]) {
      res.status(404).json({ error: 'Role not found.' });
      return;
    }

    const allPerms = await pool.request().query(`
      SELECT p.PermissionId, p.[Key], p.Description, a.[Key] AS AppKey, a.Name AS AppName
      FROM Permissions p JOIN Apps a ON a.AppId = p.AppId
      ORDER BY a.Name, p.[Key]
    `);
    const granted = await pool
      .request()
      .input('roleId', sql.Int, roleId)
      .query('SELECT PermissionId FROM RolePermissions WHERE RoleId = @roleId');
    const grantedIds = new Set((granted.recordset as { PermissionId: number }[]).map((r) => r.PermissionId));

    res.json({
      role: role.recordset[0],
      permissions: (allPerms.recordset as { PermissionId: number }[]).map((p) => ({ ...p, granted: grantedIds.has(p.PermissionId) })),
    });
  } catch (err) {
    next(err);
  }
});

// POST /admin/roles/:id/permissions {permissionId, action: 'add' | 'remove'}
// - one call per checkbox toggle on the matrix screen.
router.post('/:id/permissions', async (req, res, next) => {
  try {
    const roleId = Number(req.params.id);
    const { permissionId, action } = req.body || {};
    if (!permissionId || !['add', 'remove'].includes(action)) {
      res.status(400).json({ error: 'permissionId and action ("add" or "remove") are required.' });
      return;
    }

    const pool = await getPool();
    if (action === 'add') {
      await pool
        .request()
        .input('roleId', sql.Int, roleId)
        .input('permissionId', sql.Int, permissionId)
        .query(
          'IF NOT EXISTS (SELECT 1 FROM RolePermissions WHERE RoleId = @roleId AND PermissionId = @permissionId) INSERT INTO RolePermissions (RoleId, PermissionId) VALUES (@roleId, @permissionId)',
        );
    } else {
      await pool
        .request()
        .input('roleId', sql.Int, roleId)
        .input('permissionId', sql.Int, permissionId)
        .query('DELETE FROM RolePermissions WHERE RoleId = @roleId AND PermissionId = @permissionId');
    }

    await writeAuditLog({
      userId: req.authUser!.id,
      eventType: 'ROLE_CHANGED',
      detail: `role ${roleId}, permission ${permissionId}, ${action}ed`,
      ipAddress: clientIp(req),
    });
    res.status(204).end();
  } catch (err) {
    next(err);
  }
});

export default router;
