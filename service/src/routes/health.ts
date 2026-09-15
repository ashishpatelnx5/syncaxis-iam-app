import { Router } from 'express';
import { getPool } from '../config/db';

const router = Router();

// GET /health - liveness/readiness check (architecture doc §8.1, §9.4).
// This should be the first thing on your monitoring, ahead of any
// individual consuming app, since syncaxis-iam being down blocks new logins
// to every app at once.
router.get('/health', async (_req, res) => {
  try {
    const pool = await getPool();
    await pool.request().query('SELECT 1');
    res.json({ ok: true, db: 'connected' });
  } catch (err) {
    console.error('Health check failed:', err);
    res.status(503).json({ ok: false, db: 'unreachable' });
  }
});

export default router;
