import { NextFunction, Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import { getPool, sql } from '../config/db';
import { env } from '../config/env';
import { writeAuditLog, clientIp } from '../lib/audit';
import { getEffectiveAccess } from '../lib/permissions';

export interface AuthTokenPayload {
  sub: number;
  username: string;
  iat: number;
  exp: number;
}

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      authUser?: {
        id: number;
        username: string;
        displayName: string;
        isActive: boolean;
        lastLoginAt: Date | null;
        mustChangePassword: boolean;
      };
    }
  }
}

// syncaxis-iam is the source of truth, not a consuming app - unlike the
// per-app periodic re-verify pattern (architecture doc §4.3), every request
// here checks current DB state (IsActive, TokenValidAfter) rather than
// trusting the JWT alone, since this service's own request volume never
// approaches the point where that matters for load (§9.4).
export async function requireAuth(req: Request, res: Response, next: NextFunction): Promise<void> {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) {
    res.status(401).json({ error: 'Not authenticated.' });
    return;
  }

  let payload: AuthTokenPayload;
  try {
    payload = jwt.verify(token, env.jwtSecret) as unknown as AuthTokenPayload;
  } catch {
    res.status(401).json({ error: 'Session expired or invalid — please sign in again.' });
    return;
  }

  try {
    const pool = await getPool();
    const result = await pool
      .request()
      .input('id', sql.Int, payload.sub)
      .query('SELECT UserId, Username, DisplayName, IsActive, TokenValidAfter, LastLoginAt, MustChangePassword FROM Users WHERE UserId = @id');

    const user = result.recordset[0];
    if (!user || !user.IsActive) {
      res.status(401).json({ error: 'Session expired or invalid — please sign in again.' });
      return;
    }

    // JWT `iat` has whole-second precision; TokenValidAfter has sub-second
    // precision (DATETIME2). Truncate to the second before comparing, or a
    // token issued in the same second as a password reset/force-logout can
    // spuriously fail even though it was minted after the cutoff.
    const tokenValidAfterMs = Math.floor(new Date(user.TokenValidAfter).getTime() / 1000) * 1000;
    if (payload.iat * 1000 < tokenValidAfterMs) {
      res.status(401).json({ error: 'Your session is no longer valid - please sign in again.' });
      return;
    }

    req.authUser = {
      id: user.UserId,
      username: user.Username,
      displayName: user.DisplayName || user.Username,
      isActive: user.IsActive,
      lastLoginAt: user.LastLoginAt,
      mustChangePassword: Boolean(user.MustChangePassword),
    };
    next();
  } catch (err) {
    next(err);
  }
}

// requirePermission('iam.admin.manage') - every admin endpoint uses this the
// same way a consuming app would (architecture doc §8.2): iam treats its own
// admin console as just another registered app.
export function requirePermission(key: string) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const pool = await getPool();
      const access = await getEffectiveAccess(pool, req.authUser!.id);
      if (access.isFullAccess || access.perms.has(key)) {
        next();
        return;
      }

      await writeAuditLog({
        userId: req.authUser!.id,
        eventType: 'PERMISSION_DENIED',
        detail: `Required permission: ${key}, route: ${req.method} ${req.originalUrl}`,
        ipAddress: clientIp(req),
      });
      res.status(403).json({ error: 'You do not have access to this.' });
    } catch (err) {
      next(err);
    }
  };
}

export const requireAdmin = requirePermission('iam.admin.manage');
