import { Router } from 'express';
import { getPool, sql } from '../../config/db';
import { requireAuth, requireAdmin } from '../../middleware/auth';

const router = Router();
router.use(requireAuth, requireAdmin);

const PAGE_SIZE = 50;

// GET /admin/audit?page=&eventType=&userId=&appKey=&from=&to=
router.get('/', async (req, res, next) => {
  try {
    const { page = '1', eventType, userId, appKey, from, to } = req.query as Record<string, string>;
    const pageNum = Math.max(1, Number(page) || 1);

    const pool = await getPool();
    const request = pool.request();
    let where = '1=1';

    if (eventType) {
      request.input('eventType', sql.NVarChar(50), eventType);
      where += ' AND a.EventType = @eventType';
    }
    if (userId) {
      request.input('userId', sql.Int, Number(userId));
      where += ' AND a.UserId = @userId';
    }
    if (appKey) {
      request.input('appKey', sql.NVarChar(50), appKey);
      where += ' AND a.AppKey = @appKey';
    }
    if (from) {
      request.input('from', sql.DateTime2, new Date(from));
      where += ' AND a.CreatedAt >= @from';
    }
    if (to) {
      request.input('to', sql.DateTime2, new Date(to));
      where += ' AND a.CreatedAt <= @to';
    }

    request.input('offset', sql.Int, (pageNum - 1) * PAGE_SIZE).input('pageSize', sql.Int, PAGE_SIZE);

    const result = await request.query(`
      SELECT a.AuditId, a.UserId, u.Username, a.EventType, a.AppKey, a.Detail, a.IpAddress, a.CreatedAt
      FROM AuditLog a
      LEFT JOIN Users u ON u.UserId = a.UserId
      WHERE ${where}
      ORDER BY a.CreatedAt DESC
      OFFSET @offset ROWS FETCH NEXT @pageSize ROWS ONLY
    `);

    res.json({ entries: result.recordset, page: pageNum, pageSize: PAGE_SIZE });
  } catch (err) {
    next(err);
  }
});

export default router;
