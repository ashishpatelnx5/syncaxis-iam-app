import bcrypt from 'bcryptjs';
import { Router } from 'express';
import jwt from 'jsonwebtoken';
import { getPool, sql } from '../config/db';
import { env } from '../config/env';
import { requireAuth } from '../middleware/auth';
import { writeAuditLog, clientIp } from '../lib/audit';
import { getEffectiveAccess, EffectiveAccess } from '../lib/permissions';
import { attemptLogin } from '../lib/authenticate';
import { consumeSsoCode, issueSsoCode } from '../lib/ssoCodes';

const router = Router();
const MIN_PASSWORD_LENGTH = 8; // architecture doc §16.5

function signToken(userId: number, username: string): string {
  return jwt.sign({ sub: userId, username }, env.jwtSecret, { expiresIn: env.jwtExpiresIn } as jwt.SignOptions);
}

interface PublicUserRow {
  UserId: number;
  Username: string;
  DisplayName: string | null;
  IsActive: boolean;
  LastLoginAt: Date | null;
  PasswordChangedAt: Date | null;
  MustChangePassword: boolean;
}

function toUserSummary(user: PublicUserRow, access: EffectiveAccess) {
  return {
    id: user.UserId,
    username: user.Username,
    displayName: user.DisplayName || user.Username,
    isActive: user.IsActive,
    roles: access.roles,
    perms: [...access.perms],
    isFullAccess: access.isFullAccess,
    lastLoginAt: user.LastLoginAt ? new Date(user.LastLoginAt).toISOString() : null,
    passwordChangedAt: user.PasswordChangedAt ? new Date(user.PasswordChangedAt).toISOString() : null,
    mustChangePassword: Boolean(user.MustChangePassword),
  };
}

// POST /auth/login - architecture doc §16.4
router.post('/login', async (req, res, next) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) {
      res.status(400).json({ error: 'Username and password are required.' });
      return;
    }

    const pool = await getPool();
    const outcome = await attemptLogin(pool, username, password, clientIp(req));
    if (!outcome.ok) {
      res.status(outcome.status).json({ error: outcome.error });
      return;
    }

    const result = await pool
      .request()
      .input('id', sql.Int, outcome.userId)
      .query<PublicUserRow>('SELECT UserId, Username, DisplayName, IsActive, LastLoginAt, PasswordChangedAt, MustChangePassword FROM Users WHERE UserId = @id');
    const user = result.recordset[0];
    const access = await getEffectiveAccess(pool, user.UserId);

    res.json({
      token: signToken(user.UserId, user.Username),
      user: toUserSummary(user, access),
    });
  } catch (err) {
    next(err);
  }
});

// POST /auth/sso/issue - called by the *originating* app's backend (with the
// current user's own established token) right before redirecting the
// browser to another app's tile URL (architecture doc §4.2).
router.post('/sso/issue', requireAuth, async (req, res, next) => {
  try {
    const code = issueSsoCode(req.authUser!.id);
    await writeAuditLog({ userId: req.authUser!.id, eventType: 'SSO_ISSUE', ipAddress: clientIp(req) });
    res.json({ code });
  } catch (err) {
    next(err);
  }
});

// POST /auth/sso/exchange - called server-to-server by the *destination*
// app's backend (never from a browser) to trade a handoff code for a real
// session, single-use and short-lived (architecture doc §4.2).
router.post('/sso/exchange', async (req, res, next) => {
  try {
    const { code } = req.body || {};
    const userId = code ? consumeSsoCode(code) : null;

    if (!userId) {
      res.status(401).json({ error: 'This sign-in link has expired - please try again from the originating app.' });
      return;
    }

    const pool = await getPool();
    const result = await pool
      .request()
      .input('id', sql.Int, userId)
      .query<PublicUserRow>('SELECT UserId, Username, DisplayName, IsActive, LastLoginAt, PasswordChangedAt, MustChangePassword FROM Users WHERE UserId = @id');

    const user = result.recordset[0];
    if (!user || !user.IsActive) {
      res.status(401).json({ error: 'Account is no longer active.' });
      return;
    }

    const access = await getEffectiveAccess(pool, user.UserId);
    await writeAuditLog({ userId: user.UserId, eventType: 'SSO_EXCHANGE', ipAddress: clientIp(req) });

    res.json({
      token: signToken(user.UserId, user.Username),
      user: toUserSummary(user, access),
    });
  } catch (err) {
    next(err);
  }
});

// GET /auth/me - what powers each app's periodic re-verify (architecture
// doc §4.3). requireAuth already enforces IsActive + TokenValidAfter.
router.get('/me', requireAuth, async (req, res, next) => {
  try {
    const pool = await getPool();
    const result = await pool
      .request()
      .input('id', sql.Int, req.authUser!.id)
      .query<PublicUserRow>('SELECT UserId, Username, DisplayName, IsActive, LastLoginAt, PasswordChangedAt, MustChangePassword FROM Users WHERE UserId = @id');

    const user = result.recordset[0];
    const access = await getEffectiveAccess(pool, req.authUser!.id);
    res.json({ user: toUserSummary(user, access) });
  } catch (err) {
    next(err);
  }
});

// POST /auth/change-password - self-service, requires the current password
// (unlike an admin's forced reset via POST /admin/users/:id, which doesn't).
// Also bumps TokenValidAfter, same as an admin reset (architecture doc
// §6.4) - the user's other sessions end and they sign back in everywhere
// with the new password, rather than staying signed in on stale ones.
router.post('/change-password', requireAuth, async (req, res, next) => {
  try {
    const { currentPassword, newPassword } = req.body || {};
    if (!currentPassword || !newPassword) {
      res.status(400).json({ error: 'Current and new password are required.' });
      return;
    }
    if (String(newPassword).length < MIN_PASSWORD_LENGTH) {
      res.status(400).json({ error: `New password must be at least ${MIN_PASSWORD_LENGTH} characters.` });
      return;
    }

    const pool = await getPool();
    const result = await pool.request().input('id', sql.Int, req.authUser!.id).query('SELECT PasswordHash FROM Users WHERE UserId = @id');
    const row = result.recordset[0];
    if (!row) {
      res.status(401).json({ error: 'Session no longer valid.' });
      return;
    }

    const ok = await bcrypt.compare(currentPassword, row.PasswordHash);
    if (!ok) {
      res.status(401).json({ error: 'Current password is incorrect.' });
      return;
    }

    const sameAsCurrent = await bcrypt.compare(newPassword, row.PasswordHash);
    if (sameAsCurrent) {
      res.status(400).json({ error: 'New password must be different from your current password.' });
      return;
    }

    const passwordHash = await bcrypt.hash(newPassword, 12);
    await pool
      .request()
      .input('id', sql.Int, req.authUser!.id)
      .input('passwordHash', sql.NVarChar(255), passwordHash)
      .query(
        'UPDATE Users SET PasswordHash = @passwordHash, PasswordChangedAt = SYSUTCDATETIME(), TokenValidAfter = SYSUTCDATETIME(), MustChangePassword = 0 WHERE UserId = @id',
      );

    await writeAuditLog({ userId: req.authUser!.id, eventType: 'PASSWORD_CHANGED', ipAddress: clientIp(req) });
    res.status(204).end();
  } catch (err) {
    next(err);
  }
});

// POST /auth/logout - mainly for symmetry/audit; each app's own session
// destruction is what actually matters locally (architecture doc §8.1).
router.post('/logout', requireAuth, async (req, res, next) => {
  try {
    await writeAuditLog({ userId: req.authUser!.id, eventType: 'LOGOUT', ipAddress: clientIp(req) });
    res.status(204).end();
  } catch (err) {
    next(err);
  }
});

export default router;
