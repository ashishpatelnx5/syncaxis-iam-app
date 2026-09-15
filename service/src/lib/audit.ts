import { ConnectionPool } from 'mssql';
import { getPool, sql } from '../config/db';

// EventType values and what Detail carries for each - architecture doc §16.7.
export type AuditEventType =
  | 'LOGIN_SUCCESS'
  | 'LOGIN_FAILURE'
  | 'LOGOUT'
  | 'PASSWORD_CHANGED'
  | 'ACCOUNT_LOCKED'
  | 'SSO_ISSUE'
  | 'SSO_EXCHANGE'
  | 'PERMISSION_DENIED'
  | 'ROLE_CHANGED'
  | 'GROUP_CHANGED'
  | 'FORCE_LOGOUT'
  | 'APP_REGISTERED'
  | 'PERMISSIONS_UPDATED';

interface AuditEntry {
  userId?: number | null;
  eventType: AuditEventType;
  appKey?: string | null;
  detail?: string | null;
  ipAddress?: string | null;
}

// Fire-and-forget by design - a failure to write an audit row should never
// fail the request that triggered it. Errors are logged, not thrown.
export async function writeAuditLog(entry: AuditEntry, pool?: ConnectionPool): Promise<void> {
  try {
    const p = pool ?? (await getPool());
    await p
      .request()
      .input('userId', sql.Int, entry.userId ?? null)
      .input('eventType', sql.NVarChar(50), entry.eventType)
      .input('appKey', sql.NVarChar(50), entry.appKey ?? null)
      .input('detail', sql.NVarChar(1000), entry.detail ?? null)
      .input('ipAddress', sql.VarChar(45), entry.ipAddress ?? null)
      .query(
        'INSERT INTO AuditLog (UserId, EventType, AppKey, Detail, IpAddress) VALUES (@userId, @eventType, @appKey, @detail, @ipAddress)',
      );
  } catch (err) {
    console.error('Failed to write audit log entry:', entry.eventType, err);
  }
}

export function clientIp(req: { headers: Record<string, unknown>; socket: { remoteAddress?: string } }): string | null {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string' && forwarded.length > 0) return forwarded.split(',')[0].trim();
  return req.socket.remoteAddress ?? null;
}
