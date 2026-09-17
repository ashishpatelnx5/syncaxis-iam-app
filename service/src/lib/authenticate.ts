import bcrypt from 'bcryptjs';
import { ConnectionPool } from 'mssql';
import { sql } from '../config/db';
import { env } from '../config/env';
import { writeAuditLog } from './audit';

export interface LoginOutcome {
  ok: boolean;
  status: number;
  error?: string;
  userId?: number;
  username?: string;
  mustChangePassword?: boolean;
}

// Shared by POST /auth/login and the admin console's own login form
// (architecture doc §10 note: iam treats itself as just another app) - one
// place owns the lockout/audit logic so both paths stay consistent.
export async function attemptLogin(
  pool: ConnectionPool,
  username: string,
  password: string,
  ipAddress: string | null,
  appKey?: string,
): Promise<LoginOutcome> {
  const result = await pool
    .request()
    .input('username', sql.NVarChar(100), String(username).trim())
    .query('SELECT UserId, Username, PasswordHash, IsActive, IsLocked, FailedLoginCount, MustChangePassword FROM Users WHERE Username = @username');

  const user = result.recordset[0];
  const invalid: LoginOutcome = { ok: false, status: 401, error: 'Incorrect username or password.' };

  if (!user || !user.IsActive) {
    await writeAuditLog({ eventType: 'LOGIN_FAILURE', detail: `username: ${username}`, ipAddress, appKey });
    return invalid;
  }

  if (user.IsLocked) {
    return { ok: false, status: 423, error: 'This account is locked. Contact an administrator to unlock it.' };
  }

  const ok = await bcrypt.compare(password, user.PasswordHash);
  if (!ok) {
    const failedCount = user.FailedLoginCount + 1;
    const locksNow = failedCount >= env.maxFailedLogins;
    await pool
      .request()
      .input('id', sql.Int, user.UserId)
      .input('failedCount', sql.Int, failedCount)
      .input('isLocked', sql.Bit, locksNow)
      .query('UPDATE Users SET FailedLoginCount = @failedCount, IsLocked = @isLocked WHERE UserId = @id');

    await writeAuditLog({
      userId: user.UserId,
      eventType: locksNow ? 'ACCOUNT_LOCKED' : 'LOGIN_FAILURE',
      detail: `username: ${username}, failed attempt count: ${failedCount}`,
      ipAddress,
      appKey,
    });

    if (locksNow) {
      return { ok: false, status: 423, error: 'Too many failed attempts — this account is now locked. Contact an administrator to unlock it.' };
    }
    return invalid;
  }

  await pool
    .request()
    .input('id', sql.Int, user.UserId)
    .query('UPDATE Users SET FailedLoginCount = 0, LastLoginAt = SYSUTCDATETIME() WHERE UserId = @id');

  await writeAuditLog({ userId: user.UserId, eventType: 'LOGIN_SUCCESS', ipAddress, appKey });
  return { ok: true, status: 200, userId: user.UserId, username: user.Username, mustChangePassword: Boolean(user.MustChangePassword) };
}
