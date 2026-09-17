import crypto from 'crypto';
import { env } from '../config/env';

// Short-lived, single-use SSO handoff codes (architecture doc §4.2) - shared
// between POST /auth/sso/issue + POST /auth/sso/exchange (called by a
// satellite app's backend, server-to-server) and the admin console's own
// login (a tile click from Portal, consumed in-process here instead of over
// HTTP - see admin-ui/views-routes.ts). In-memory only: an app restart just
// means anyone mid-handoff clicks the tile again (§9.4).
const ssoCodes = new Map<string, { userId: number; expiresAt: number }>();

function sweepExpired(): void {
  const now = Date.now();
  for (const [code, entry] of ssoCodes) {
    if (entry.expiresAt < now) ssoCodes.delete(code);
  }
}

export function issueSsoCode(userId: number): string {
  sweepExpired();
  const code = crypto.randomBytes(32).toString('hex');
  ssoCodes.set(code, { userId, expiresAt: Date.now() + env.ssoCodeTtlSeconds * 1000 });
  return code;
}

// Single-use - deletes the code whether or not it's still valid, so a code
// can't be replayed after either a successful exchange or an expiry check.
export function consumeSsoCode(code: string): number | null {
  const entry = ssoCodes.get(code);
  ssoCodes.delete(code);
  if (!entry || entry.expiresAt < Date.now()) return null;
  return entry.userId;
}
