import { Router } from 'express';
import { getPool, sql } from '../../config/db';
import { requireAuth, requireAdmin } from '../../middleware/auth';
import { writeAuditLog, clientIp } from '../../lib/audit';
import { isValidPermissionKey } from '../../lib/permissions';

const router = Router();
router.use(requireAuth, requireAdmin);

// GET /admin/apps - registry view (architecture doc §10 "Apps & Permissions" screen)
router.get('/', async (_req, res, next) => {
  try {
    const pool = await getPool();
    const result = await pool.request().query(`
      SELECT a.AppId, a.[Key], a.Name, a.BaseUrl, a.IsActive, a.CreatedAt,
             (SELECT COUNT(*) FROM Permissions p WHERE p.AppId = a.AppId) AS PermissionCount
      FROM Apps a ORDER BY a.Name
    `);
    res.json({ apps: result.recordset });
  } catch (err) {
    next(err);
  }
});

// POST /admin/apps - register an app {key, name, baseUrl}
router.post('/', async (req, res, next) => {
  try {
    const { key, name, baseUrl } = req.body || {};
    if (!key || !name || !/^[a-z][a-z0-9-]*$/.test(key)) {
      res.status(400).json({ error: 'A lowercase key (letters, digits, hyphens) and a name are required.' });
      return;
    }

    const pool = await getPool();
    const existing = await pool.request().input('key', sql.NVarChar(50), key).query('SELECT AppId FROM Apps WHERE [Key] = @key');
    if (existing.recordset[0]) {
      res.status(409).json({ error: `App "${key}" is already registered.` });
      return;
    }

    await pool
      .request()
      .input('key', sql.NVarChar(50), key)
      .input('name', sql.NVarChar(150), name)
      .input('baseUrl', sql.NVarChar(300), baseUrl || null)
      .query('INSERT INTO Apps ([Key], Name, BaseUrl) VALUES (@key, @name, @baseUrl)');

    await writeAuditLog({ userId: req.authUser!.id, eventType: 'APP_REGISTERED', appKey: key, ipAddress: clientIp(req) });
    res.status(201).json({ ok: true });
  } catch (err) {
    next(err);
  }
});

// GET /admin/apps/:key - one app's registry details (for an edit screen)
router.get('/:key', async (req, res, next) => {
  try {
    const pool = await getPool();
    const result = await pool
      .request()
      .input('key', sql.NVarChar(50), req.params.key)
      .query('SELECT AppId, [Key], Name, BaseUrl, IsActive, CreatedAt FROM Apps WHERE [Key] = @key');
    if (!result.recordset[0]) {
      res.status(404).json({ error: `App "${req.params.key}" is not registered.` });
      return;
    }
    res.json({ app: result.recordset[0] });
  } catch (err) {
    next(err);
  }
});

// POST /admin/apps/:key - update name/baseUrl/isActive. The Key itself is
// immutable here (it's the namespace prefix every one of this app's
// permission keys already carries, per architecture doc §6.1/§8.3 - renaming
// it would orphan every existing permission key) - register a new app
// instead if the key itself needs to change.
router.post('/:key', async (req, res, next) => {
  try {
    const { name, baseUrl, isActive } = req.body || {};
    const pool = await getPool();

    const existing = await pool.request().input('key', sql.NVarChar(50), req.params.key).query('SELECT AppId FROM Apps WHERE [Key] = @key');
    if (!existing.recordset[0]) {
      res.status(404).json({ error: `App "${req.params.key}" is not registered.` });
      return;
    }

    const sets: string[] = [];
    const request = pool.request().input('key', sql.NVarChar(50), req.params.key);
    if (name !== undefined) {
      if (!name) {
        res.status(400).json({ error: 'Name cannot be empty.' });
        return;
      }
      sets.push('Name = @name');
      request.input('name', sql.NVarChar(150), name);
    }
    if (baseUrl !== undefined) {
      sets.push('BaseUrl = @baseUrl');
      request.input('baseUrl', sql.NVarChar(300), baseUrl || null);
    }
    if (isActive !== undefined) {
      sets.push('IsActive = @isActive');
      request.input('isActive', sql.Bit, Boolean(isActive));
    }
    if (sets.length === 0) {
      res.status(400).json({ error: 'Nothing to update.' });
      return;
    }

    await request.query(`UPDATE Apps SET ${sets.join(', ')} WHERE [Key] = @key`);
    await writeAuditLog({ userId: req.authUser!.id, eventType: 'APP_REGISTERED', appKey: req.params.key, detail: 'updated', ipAddress: clientIp(req) });
    res.status(204).end();
  } catch (err) {
    next(err);
  }
});

// GET /admin/apps/:key/permissions - what this app has declared so far
router.get('/:key/permissions', async (req, res, next) => {
  try {
    const pool = await getPool();
    const app = await pool.request().input('key', sql.NVarChar(50), req.params.key).query('SELECT AppId FROM Apps WHERE [Key] = @key');
    if (!app.recordset[0]) {
      res.status(404).json({ error: `App "${req.params.key}" is not registered.` });
      return;
    }

    const perms = await pool
      .request()
      .input('appId', sql.Int, app.recordset[0].AppId)
      .query('SELECT PermissionId, [Key], Description FROM Permissions WHERE AppId = @appId ORDER BY [Key]');
    res.json({ permissions: perms.recordset });
  } catch (err) {
    next(err);
  }
});

// POST /admin/apps/:key/permissions - bulk-declare/update an app's
// permission keys (architecture doc §8.3). Idempotent: an app can call this
// on every startup with its full manifest; keys not present are left alone
// (declaring a manifest never deletes a key another admin action depends on).
router.post('/:key/permissions', async (req, res, next) => {
  try {
    const appKey = req.params.key;
    const { permissions } = req.body || {};
    if (!Array.isArray(permissions) || permissions.length === 0) {
      res.status(400).json({ error: 'permissions must be a non-empty array of {key, description}.' });
      return;
    }

    const pool = await getPool();
    const app = await pool.request().input('key', sql.NVarChar(50), appKey).query('SELECT AppId FROM Apps WHERE [Key] = @key');
    if (!app.recordset[0]) {
      res.status(404).json({ error: `App "${appKey}" is not registered - call POST /admin/apps first.` });
      return;
    }
    const appId = app.recordset[0].AppId;

    const invalid = permissions.filter((p: { key?: string }) => !p.key || !isValidPermissionKey(appKey, p.key));
    if (invalid.length > 0) {
      res.status(400).json({
        error: `Every key must match "${appKey}.<module>.<action>" format. Invalid: ${invalid.map((p: { key?: string }) => p.key).join(', ')}`,
      });
      return;
    }

    let created = 0;
    for (const perm of permissions as { key: string; description?: string }[]) {
      const existing = await pool
        .request()
        .input('key', sql.NVarChar(150), perm.key)
        .query('SELECT PermissionId FROM Permissions WHERE [Key] = @key');

      if (existing.recordset[0]) {
        await pool
          .request()
          .input('id', sql.Int, existing.recordset[0].PermissionId)
          .input('description', sql.NVarChar(400), perm.description || null)
          .query('UPDATE Permissions SET Description = @description WHERE PermissionId = @id');
      } else {
        await pool
          .request()
          .input('appId', sql.Int, appId)
          .input('key', sql.NVarChar(150), perm.key)
          .input('description', sql.NVarChar(400), perm.description || null)
          .query('INSERT INTO Permissions (AppId, [Key], Description) VALUES (@appId, @key, @description)');
        created += 1;
      }
    }

    await writeAuditLog({
      userId: req.authUser!.id,
      eventType: 'PERMISSIONS_UPDATED',
      appKey,
      detail: `${permissions.length} keys declared, ${created} newly created`,
      ipAddress: clientIp(req),
    });
    res.json({ ok: true, declared: permissions.length, created });
  } catch (err) {
    next(err);
  }
});

export default router;
