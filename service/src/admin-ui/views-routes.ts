import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import { NextFunction, Request, Response, Router } from 'express';
import jwt from 'jsonwebtoken';
import { getPool, sql } from '../config/db';
import { env } from '../config/env';
import { requireAuth, requirePermission } from '../middleware/auth';
import { attemptLogin } from '../lib/authenticate';
import { getEffectiveAccess } from '../lib/permissions';
import { clientIp, writeAuditLog } from '../lib/audit';
import { consumeSsoCode } from '../lib/ssoCodes';

const MIN_PASSWORD_LENGTH = 8; // architecture doc §16.5

// MobileNumber is stored as a single "+<code><digits>" string - collected
// for future OTP delivery. India-only for now (every current user is based
// in India); add more entries here once OTP delivery actually needs them.
const COUNTRY_CODES = [{ code: '+91', label: '+91 (IN)' }];
const DEFAULT_COUNTRY_CODE = '+91';

function splitMobileNumber(mobile: string | null | undefined): { countryCode: string; number: string } {
  if (!mobile) return { countryCode: DEFAULT_COUNTRY_CODE, number: '' };
  const match = [...COUNTRY_CODES].sort((a, b) => b.code.length - a.code.length).find((c) => mobile.startsWith(c.code));
  return match ? { countryCode: match.code, number: mobile.slice(match.code.length) } : { countryCode: DEFAULT_COUNTRY_CODE, number: mobile };
}

// Renders what actually changed between two snapshots of the same row for
// an audit Detail string - e.g. "email: 'a@x.com' -> 'b@x.com'" - rather
// than just "updated", so the log answers *what* an admin did, not just
// that they did something.
function diffFields(before: Record<string, unknown>, after: Record<string, unknown>, labels: Record<string, string>): string {
  const parts: string[] = [];
  for (const key of Object.keys(labels)) {
    const b = before[key] ?? '';
    const a = after[key] ?? '';
    if (String(b) !== String(a)) parts.push(`${labels[key]}: '${b || '(empty)'}' -> '${a || '(empty)'}'`);
  }
  return parts.length ? parts.join('; ') : '(no changes)';
}

const router = Router();
const ADMIN_SESSION_COOKIE = 'iam_admin_session';
const ADMIN_PERMISSION = 'iam.admin.manage';

interface AdminSession {
  token: string;
  userId: number;
  username: string;
  expiresAt: number;
}
// Same tradeoff as every other app's own session store (architecture doc
// §4.3): in-memory only, an app restart just means admins sign back in.
const adminSessions = new Map<string, AdminSession>();

function signToken(userId: number, username: string): string {
  return jwt.sign({ sub: userId, username }, env.jwtSecret, { expiresIn: env.jwtExpiresIn } as jwt.SignOptions);
}

// Bridges the admin console's own browser cookie to the same requireAuth
// used by every JSON API route (architecture doc §10: iam treats its own
// admin console as just another registered app) - the token itself never
// reaches the browser, only this server-side session lookup does.
function requireUiAuth(req: Request, res: Response, next: NextFunction): void {
  const sessionId = req.cookies?.[ADMIN_SESSION_COOKIE];
  const session = sessionId ? adminSessions.get(sessionId) : undefined;
  if (!session || session.expiresAt < Date.now()) {
    res.redirect('/admin-ui/login');
    return;
  }
  req.headers.authorization = `Bearer ${session.token}`;

  // requireAuth below speaks JSON and returns a bare 401 if this bridged
  // token has gone stale server-side since the cookie was minted - most
  // commonly a password change (here or from another app like Company
  // Portal) bumping TokenValidAfter past this token's iat. The admin
  // console renders pages, not JSON, so intercept that one response and
  // bounce back to login instead of leaking raw JSON to the browser.
  const originalJson = res.json.bind(res);
  res.json = ((body: unknown) => {
    if (res.statusCode === 401) {
      adminSessions.delete(sessionId!);
      res.clearCookie(ADMIN_SESSION_COOKIE);
      return res.redirect('/admin-ui/login');
    }
    return originalJson(body);
  }) as typeof res.json;

  next();
}

// My Account is reachable even with a pending mandatory change (it's the
// only way out of one) - every other admin-console page is not.
function blockIfMustChangePassword(req: Request, res: Response, next: NextFunction): void {
  if (req.authUser!.mustChangePassword) {
    res.redirect('/admin-ui/account');
    return;
  }
  next();
}

const requireUiAccount = [requireUiAuth, requireAuth, requirePermission(ADMIN_PERMISSION)];
const requireUiAdmin = [...requireUiAccount, blockIfMustChangePassword];

// Shared by the password form and the SSO handoff below - both end up
// needing the same cookie + in-memory session record once a userId/username
// pair has been established some other way.
function startAdminSession(req: Request, res: Response, userId: number, username: string): void {
  const sessionId = crypto.randomBytes(32).toString('hex');
  adminSessions.set(sessionId, {
    token: signToken(userId, username),
    userId,
    username,
    expiresAt: Date.now() + env.sessionTtlHours * 60 * 60 * 1000,
  });
  res.cookie(ADMIN_SESSION_COOKIE, sessionId, {
    httpOnly: true,
    sameSite: 'strict',
    secure: req.protocol === 'https',
    maxAge: env.sessionTtlHours * 60 * 60 * 1000,
  });
}

// --- Login / logout -------------------------------------------------------

router.get('/login', async (req: Request, res: Response, next: NextFunction) => {
  try {
    // Tile-click handoff from another app (e.g. Company Portal) that already
    // holds a signed-in user - same single-use code a satellite app's
    // backend would exchange over HTTP, consumed in-process here instead
    // since the admin console *is* this service. Checked *before* the
    // existing-cookie shortcut below: arriving with a fresh code means "sign
    // this identity in now", not "resume whatever's cached" - and a stale
    // cached session here would otherwise swallow the code (redirecting to
    // /admin-ui) only to bounce back to a bare login page once that stale
    // token gets caught downstream (see requireUiAuth), burning the
    // single-use code for nothing on the first click.
    const ssoCode = typeof req.query.ssoCode === 'string' ? req.query.ssoCode : null;

    if (!ssoCode) {
      const sessionId = req.cookies?.[ADMIN_SESSION_COOKIE];
      if (sessionId && adminSessions.has(sessionId)) {
        res.redirect('/admin-ui');
        return;
      }
      res.render('login', { error: null });
      return;
    }

    const userId = consumeSsoCode(ssoCode);
    if (!userId) {
      res.status(401).render('login', { error: 'This sign-in link has expired — please try again from the Portal.' });
      return;
    }

    const pool = await getPool();
    const result = await pool
      .request()
      .input('id', sql.Int, userId)
      .query('SELECT UserId, Username, IsActive FROM Users WHERE UserId = @id');
    const user = result.recordset[0];
    if (!user || !user.IsActive) {
      res.status(401).render('login', { error: 'Account is no longer active.' });
      return;
    }

    // Same admin-console-access gate as the password branch below (architecture
    // doc §10) - holding a valid Portal/iam session isn't enough on its own.
    const access = await getEffectiveAccess(pool, user.UserId);
    if (!access.isFullAccess && !access.perms.has(ADMIN_PERMISSION)) {
      res.status(403).render('login', { error: 'This account does not have admin console access.' });
      return;
    }

    startAdminSession(req, res, user.UserId, user.Username);
    await writeAuditLog({ userId: user.UserId, eventType: 'SSO_EXCHANGE', appKey: 'iam', ipAddress: clientIp(req) });
    res.redirect('/admin-ui');
  } catch (err) {
    next(err);
  }
});

router.post('/login', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) {
      res.render('login', { error: 'Username and password are required.' });
      return;
    }

    const pool = await getPool();
    const outcome = await attemptLogin(pool, username, password, clientIp(req), 'iam');
    if (!outcome.ok) {
      res.status(outcome.status).render('login', { error: outcome.error });
      return;
    }

    // Must hold iam.admin.manage to use the console at all (architecture doc
    // §10) - a valid login that lacks it is redirected away, not shown a
    // half-working console; the attempt is still visible via the login's own
    // LOGIN_SUCCESS audit row plus a PERMISSION_DENIED on the first page load.
    const access = await getEffectiveAccess(pool, outcome.userId!);
    if (!access.isFullAccess && !access.perms.has(ADMIN_PERMISSION)) {
      res.status(403).render('login', { error: 'This account does not have admin console access.' });
      return;
    }

    startAdminSession(req, res, outcome.userId!, outcome.username!);
    res.redirect('/admin-ui');
  } catch (err) {
    next(err);
  }
});

router.post('/logout', (req: Request, res: Response) => {
  const sessionId = req.cookies?.[ADMIN_SESSION_COOKIE];
  const session = sessionId ? adminSessions.get(sessionId) : undefined;
  if (sessionId) adminSessions.delete(sessionId);
  res.clearCookie(ADMIN_SESSION_COOKIE);
  if (session) void writeAuditLog({ userId: session.userId, eventType: 'LOGOUT', ipAddress: clientIp(req) });
  res.redirect('/admin-ui/login');
});

// --- My Account (self-service - profile + change own password) ------------

router.get('/account', ...requireUiAccount, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const pool = await getPool();
    const result = await pool
      .request()
      .input('id', sql.Int, req.authUser!.id)
      .query('SELECT UserId, Username, Email, DisplayName, LastLoginAt, PasswordChangedAt FROM Users WHERE UserId = @id');
    res.render('account', {
      authUser: req.authUser,
      account: result.recordset[0],
      error: null,
      notice: null,
      mustChangePassword: req.authUser!.mustChangePassword,
    });
  } catch (err) {
    next(err);
  }
});

router.post('/account', ...requireUiAccount, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { displayName, email } = req.body || {};
    if (!email) {
      const pool = await getPool();
      const result = await pool.request().input('id', sql.Int, req.authUser!.id).query('SELECT UserId, Username, Email, DisplayName, LastLoginAt, PasswordChangedAt FROM Users WHERE UserId = @id');
      res.status(400).render('account', {
        authUser: req.authUser,
        account: result.recordset[0],
        error: 'Email is required.',
        notice: null,
        mustChangePassword: req.authUser!.mustChangePassword,
      });
      return;
    }

    const pool = await getPool();
    const before = await pool.request().input('id', sql.Int, req.authUser!.id).query('SELECT DisplayName, Email FROM Users WHERE UserId = @id');
    await pool
      .request()
      .input('id', sql.Int, req.authUser!.id)
      .input('displayName', sql.NVarChar(200), displayName || null)
      .input('email', sql.NVarChar(255), email)
      .query('UPDATE Users SET DisplayName = @displayName, Email = @email WHERE UserId = @id');

    await writeAuditLog({
      userId: req.authUser!.id,
      eventType: 'ACCOUNT_UPDATED',
      detail: diffFields(before.recordset[0], { DisplayName: displayName || null, Email: email }, { DisplayName: 'display name', Email: 'email' }),
      ipAddress: clientIp(req),
    });

    const result = await pool.request().input('id', sql.Int, req.authUser!.id).query('SELECT UserId, Username, Email, DisplayName, LastLoginAt, PasswordChangedAt FROM Users WHERE UserId = @id');
    res.render('account', {
      authUser: { ...req.authUser!, displayName: displayName || req.authUser!.username },
      account: result.recordset[0],
      error: null,
      notice: 'Profile updated.',
      mustChangePassword: req.authUser!.mustChangePassword,
    });
  } catch (err) {
    next(err);
  }
});

router.post('/account/change-password', ...requireUiAccount, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { currentPassword, newPassword } = req.body || {};
    const pool = await getPool();
    const accountResult = await pool.request().input('id', sql.Int, req.authUser!.id).query('SELECT UserId, Username, Email, DisplayName, PasswordHash, LastLoginAt, PasswordChangedAt FROM Users WHERE UserId = @id');
    const account = accountResult.recordset[0];

    async function rerender(status: number, error: string) {
      res.status(status).render('account', { authUser: req.authUser, account, error, notice: null, mustChangePassword: req.authUser!.mustChangePassword });
    }

    if (!currentPassword || !newPassword) {
      await rerender(400, 'Current and new password are required.');
      return;
    }
    if (String(newPassword).length < MIN_PASSWORD_LENGTH) {
      await rerender(400, `New password must be at least ${MIN_PASSWORD_LENGTH} characters.`);
      return;
    }
    const ok = await bcrypt.compare(currentPassword, account.PasswordHash);
    if (!ok) {
      await rerender(401, 'Current password is incorrect.');
      return;
    }

    const sameAsCurrent = await bcrypt.compare(newPassword, account.PasswordHash);
    if (sameAsCurrent) {
      await rerender(400, 'New password must be different from your current password.');
      return;
    }

    const passwordHash = await bcrypt.hash(newPassword, 12);
    await pool
      .request()
      .input('id', sql.Int, req.authUser!.id)
      .input('passwordHash', sql.NVarChar(255), passwordHash)
      .query('UPDATE Users SET PasswordHash = @passwordHash, PasswordChangedAt = SYSUTCDATETIME(), TokenValidAfter = SYSUTCDATETIME(), MustChangePassword = 0 WHERE UserId = @id');

    await writeAuditLog({ userId: req.authUser!.id, eventType: 'PASSWORD_CHANGED', ipAddress: clientIp(req) });

    // TokenValidAfter just moved past this request's own token's iat, so the
    // bridged Bearer header on the *next* request would fail requireAuth -
    // mint a fresh admin-console session immediately rather than bouncing
    // the admin who just changed their own password straight to a login
    // page that would look like the change silently failed.
    const sessionId = req.cookies?.[ADMIN_SESSION_COOKIE] as string;
    adminSessions.set(sessionId, {
      token: signToken(req.authUser!.id, req.authUser!.username),
      userId: req.authUser!.id,
      username: req.authUser!.username,
      expiresAt: Date.now() + env.sessionTtlHours * 60 * 60 * 1000,
    });

    res.render('account', { authUser: req.authUser, account, error: null, notice: 'Password changed.', mustChangePassword: false });
  } catch (err) {
    next(err);
  }
});

// --- Dashboard --------------------------------------------------------------

router.get('/', ...requireUiAdmin, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const pool = await getPool();
    const [activeUsers, roles, apps, recentAudit] = await Promise.all([
      pool.request().query('SELECT COUNT(*) AS n FROM Users WHERE IsActive = 1'),
      pool.request().query('SELECT COUNT(*) AS n FROM Roles'),
      pool.request().query('SELECT COUNT(*) AS n FROM Apps'),
      pool.request().query('SELECT TOP 10 a.AuditId, a.EventType, a.AppKey, a.Detail, a.CreatedAt, u.Username FROM AuditLog a LEFT JOIN Users u ON u.UserId = a.UserId ORDER BY a.CreatedAt DESC'),
    ]);

    res.render('dashboard', {
      authUser: req.authUser,
      counts: { activeUsers: activeUsers.recordset[0].n, roles: roles.recordset[0].n, apps: apps.recordset[0].n },
      recentAudit: recentAudit.recordset,
    });
  } catch (err) {
    next(err);
  }
});

// --- Users --------------------------------------------------------------

router.get('/users', ...requireUiAdmin, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { search, status } = req.query as { search?: string; status?: string };
    const pool = await getPool();
    const request = pool.request();
    let where = '1=1';
    if (search) {
      request.input('search', sql.NVarChar(100), `%${search}%`);
      where += ' AND (u.Username LIKE @search OR u.Email LIKE @search OR u.DisplayName LIKE @search)';
    }
    if (status === 'active') where += ' AND u.IsActive = 1 AND u.IsLocked = 0';
    else if (status === 'inactive') where += ' AND u.IsActive = 0';
    else if (status === 'locked') where += ' AND u.IsLocked = 1';

    const result = await request.query(`
      SELECT u.UserId, u.Username, u.Email, u.DisplayName, u.FirstName, u.MiddleName, u.LastName, u.IsActive, u.IsLocked, u.LastLoginAt,
             STRING_AGG(r.Name, ', ') AS RoleNames
      FROM Users u
      LEFT JOIN UserRoles ur ON ur.UserId = u.UserId
      LEFT JOIN Roles r ON r.RoleId = ur.RoleId
      WHERE ${where}
      GROUP BY u.UserId, u.Username, u.Email, u.DisplayName, u.FirstName, u.MiddleName, u.LastName, u.IsActive, u.IsLocked, u.LastLoginAt
      ORDER BY u.Username
    `);

    res.render('users', { authUser: req.authUser, users: result.recordset, filters: { search, status } });
  } catch (err) {
    next(err);
  }
});

router.get('/users/new', ...requireUiAdmin, (req: Request, res: Response) => {
  res.render('user-new', { authUser: req.authUser, error: null, countryCodes: COUNTRY_CODES, defaultCountryCode: DEFAULT_COUNTRY_CODE });
});

router.post('/users/new', ...requireUiAdmin, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { username, email, firstName, middleName, lastName, displayName, countryCode, mobileNumber, password, confirmPassword } = req.body || {};
    const renderError = (status: number, error: string) =>
      res.status(status).render('user-new', { authUser: req.authUser, error, countryCodes: COUNTRY_CODES, defaultCountryCode: DEFAULT_COUNTRY_CODE });

    const mobileDigits = String(mobileNumber || '').replace(/\D/g, '');
    if (
      !username ||
      String(username).trim().length < 3 ||
      !firstName ||
      !lastName ||
      !displayName ||
      !password ||
      String(password).length < 8
    ) {
      renderError(400, 'Username (3+ chars), first name, last name, display name, mobile number, and an 8+ character password are required.');
      return;
    }
    if (mobileDigits.length !== 10) {
      renderError(400, 'Mobile number must be exactly 10 digits.');
      return;
    }
    if (password !== confirmPassword) {
      renderError(400, 'Password and confirm password do not match.');
      return;
    }

    // Same placeholder convention already used for accounts with no real
    // address (see portal-integration-instructions.md) - Email is NOT NULL
    // + UNIQUE at the DB level, so a blank form field still needs some value.
    const resolvedEmail = email || `${username}@syncaxis.com`;
    const resolvedMobile = `${countryCode || DEFAULT_COUNTRY_CODE}${mobileDigits}`;

    const pool = await getPool();
    const existing = await pool
      .request()
      .input('username', sql.NVarChar(100), username)
      .input('email', sql.NVarChar(255), resolvedEmail)
      .query('SELECT UserId FROM Users WHERE Username = @username OR Email = @email');
    if (existing.recordset[0]) {
      renderError(409, 'A user with that username or email already exists.');
      return;
    }

    // Falls back to first name before the username, so a name-only entry
    // still gets a readable DisplayName instead of the raw username.
    const passwordHash = await bcrypt.hash(password, 12);
    const result = await pool
      .request()
      .input('username', sql.NVarChar(100), username)
      .input('email', sql.NVarChar(255), resolvedEmail)
      .input('firstName', sql.NVarChar(100), firstName || null)
      .input('middleName', sql.NVarChar(100), middleName || null)
      .input('lastName', sql.NVarChar(100), lastName || null)
      .input('displayName', sql.NVarChar(200), displayName || firstName || username)
      .input('mobileNumber', sql.NVarChar(20), resolvedMobile)
      .input('passwordHash', sql.NVarChar(255), passwordHash)
      .query(
        // MustChangePassword defaults to 1 - a password set by an admin at
        // creation time is treated as temporary, same as an admin reset
        // below (architecture doc §10).
        'INSERT INTO Users (Username, Email, FirstName, MiddleName, LastName, DisplayName, MobileNumber, PasswordHash, MustChangePassword) VALUES (@username, @email, @firstName, @middleName, @lastName, @displayName, @mobileNumber, @passwordHash, 1); SELECT CAST(SCOPE_IDENTITY() AS INT) AS UserId;',
      );
    const newUserId = result.recordset[0].UserId;

    await writeAuditLog({
      userId: req.authUser!.id,
      eventType: 'USER_CREATED',
      detail: `created user '${username}' (id ${newUserId}, email ${resolvedEmail})`,
      ipAddress: clientIp(req),
    });

    res.redirect(`/admin-ui/users/${newUserId}`);
  } catch (err) {
    next(err);
  }
});

router.get('/users/:id', ...requireUiAdmin, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const userId = Number(req.params.id);
    const pool = await getPool();

    const userResult = await pool
      .request()
      .input('id', sql.Int, userId)
      .query('SELECT UserId, Username, Email, FirstName, MiddleName, LastName, DisplayName, MobileNumber, IsActive, IsLocked, MustChangePassword, FailedLoginCount, LastLoginAt, CreatedAt FROM Users WHERE UserId = @id');
    const user = userResult.recordset[0];
    if (!user) {
      res.status(404).send('User not found.');
      return;
    }

    const [allRoles, userRoles, allGroups, userGroups] = await Promise.all([
      pool.request().query('SELECT RoleId, Name, IsFullAccess FROM Roles ORDER BY Name'),
      pool.request().input('id', sql.Int, userId).query('SELECT RoleId FROM UserRoles WHERE UserId = @id'),
      pool.request().query('SELECT GroupId, Name FROM UserGroups ORDER BY Name'),
      pool.request().input('id', sql.Int, userId).query('SELECT GroupId FROM UserGroupMembers WHERE UserId = @id'),
    ]);

    res.render('user-detail', {
      authUser: req.authUser,
      user,
      mobile: splitMobileNumber(user.MobileNumber),
      countryCodes: COUNTRY_CODES,
      allRoles: allRoles.recordset,
      roleIds: (userRoles.recordset as { RoleId: number }[]).map((r) => r.RoleId),
      allGroups: allGroups.recordset,
      groupIds: (userGroups.recordset as { GroupId: number }[]).map((g) => g.GroupId),
    });
  } catch (err) {
    next(err);
  }
});

router.post('/users/:id', ...requireUiAdmin, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const userId = Number(req.params.id);
    const { firstName, middleName, lastName, displayName, email, countryCode, mobileNumber, isActive, isLocked, mustChangePassword } = req.body || {};
    const mobileDigits = String(mobileNumber || '').replace(/\D/g, '');
    if (mobileDigits.length !== 10) {
      res.status(400).send('Mobile number must be exactly 10 digits.');
      return;
    }
    const resolvedMobile = `${countryCode || DEFAULT_COUNTRY_CODE}${mobileDigits}`;
    const pool = await getPool();
    const before = await pool
      .request()
      .input('id', sql.Int, userId)
      .query('SELECT Username, FirstName, MiddleName, LastName, DisplayName, Email, MobileNumber, IsActive, IsLocked, MustChangePassword FROM Users WHERE UserId = @id');
    await pool
      .request()
      .input('id', sql.Int, userId)
      .input('firstName', sql.NVarChar(100), firstName || null)
      .input('middleName', sql.NVarChar(100), middleName || null)
      .input('lastName', sql.NVarChar(100), lastName || null)
      .input('displayName', sql.NVarChar(200), displayName || null)
      .input('email', sql.NVarChar(255), email)
      .input('mobileNumber', sql.NVarChar(20), resolvedMobile)
      .input('isActive', sql.Bit, isActive === 'true')
      .input('isLocked', sql.Bit, isLocked === 'true')
      .input('mustChangePassword', sql.Bit, mustChangePassword === 'true')
      .query(
        'UPDATE Users SET FirstName = @firstName, MiddleName = @middleName, LastName = @lastName, DisplayName = @displayName, Email = @email, MobileNumber = @mobileNumber, IsActive = @isActive, IsLocked = @isLocked, MustChangePassword = @mustChangePassword, FailedLoginCount = CASE WHEN @isLocked = 0 THEN 0 ELSE FailedLoginCount END WHERE UserId = @id',
      );

    const diff = diffFields(
      before.recordset[0],
      { FirstName: firstName || null, MiddleName: middleName || null, LastName: lastName || null, DisplayName: displayName || null, Email: email, MobileNumber: resolvedMobile, IsActive: isActive === 'true', IsLocked: isLocked === 'true', MustChangePassword: mustChangePassword === 'true' },
      { FirstName: 'first name', MiddleName: 'middle name', LastName: 'last name', DisplayName: 'display name', Email: 'email', MobileNumber: 'mobile', IsActive: 'active', IsLocked: 'locked', MustChangePassword: 'must change password' },
    );
    await writeAuditLog({
      userId: req.authUser!.id,
      eventType: 'USER_UPDATED',
      detail: `target user '${before.recordset[0]?.Username}' (id ${userId}): ${diff}`,
      ipAddress: clientIp(req),
    });

    res.redirect(`/admin-ui/users/${userId}`);
  } catch (err) {
    next(err);
  }
});

router.post('/users/:id/reset-password', ...requireUiAdmin, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const userId = Number(req.params.id);
    const { password, confirmPassword } = req.body || {};
    if (!password || String(password).length < 8) {
      res.status(400).send('Password must be at least 8 characters.');
      return;
    }
    if (password !== confirmPassword) {
      res.status(400).send('Password and confirm password do not match.');
      return;
    }
    const passwordHash = await bcrypt.hash(password, 12);
    const pool = await getPool();
    const result = await pool
      .request()
      .input('id', sql.Int, userId)
      .input('passwordHash', sql.NVarChar(255), passwordHash)
      // An admin-set password is always treated as temporary - the user
      // must change it themselves on their next login, same as a brand-new
      // account (architecture doc §10).
      .query('UPDATE Users SET PasswordHash = @passwordHash, PasswordChangedAt = SYSUTCDATETIME(), TokenValidAfter = SYSUTCDATETIME(), MustChangePassword = 1 OUTPUT INSERTED.Username WHERE UserId = @id');

    await writeAuditLog({
      userId: req.authUser!.id,
      eventType: 'PASSWORD_RESET',
      detail: `target user '${result.recordset[0]?.Username}' (id ${userId})`,
      ipAddress: clientIp(req),
    });

    res.redirect(`/admin-ui/users/${userId}`);
  } catch (err) {
    next(err);
  }
});

router.post('/users/:id/roles', ...requireUiAdmin, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const userId = Number(req.params.id);
    const { roleId, action } = req.body || {};
    const pool = await getPool();
    if (action === 'add') {
      await pool
        .request()
        .input('userId', sql.Int, userId)
        .input('roleId', sql.Int, roleId)
        .query('IF NOT EXISTS (SELECT 1 FROM UserRoles WHERE UserId = @userId AND RoleId = @roleId) INSERT INTO UserRoles (UserId, RoleId) VALUES (@userId, @roleId)');
    } else {
      await pool.request().input('userId', sql.Int, userId).input('roleId', sql.Int, roleId).query('DELETE FROM UserRoles WHERE UserId = @userId AND RoleId = @roleId');
    }

    const [userRow, roleRow] = await Promise.all([
      pool.request().input('id', sql.Int, userId).query('SELECT Username FROM Users WHERE UserId = @id'),
      pool.request().input('id', sql.Int, roleId).query('SELECT Name FROM Roles WHERE RoleId = @id'),
    ]);
    await writeAuditLog({
      userId: req.authUser!.id,
      eventType: 'ROLE_CHANGED',
      detail: `${action === 'add' ? 'granted' : 'revoked'} role '${roleRow.recordset[0]?.Name ?? roleId}' ${action === 'add' ? 'to' : 'from'} user '${userRow.recordset[0]?.Username ?? userId}'`,
      ipAddress: clientIp(req),
    });

    res.status(204).end();
  } catch (err) {
    next(err);
  }
});

router.post('/users/:id/groups', ...requireUiAdmin, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const userId = Number(req.params.id);
    const { groupId, action } = req.body || {};
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

    const [userRow, groupRow] = await Promise.all([
      pool.request().input('id', sql.Int, userId).query('SELECT Username FROM Users WHERE UserId = @id'),
      pool.request().input('id', sql.Int, groupId).query('SELECT Name FROM UserGroups WHERE GroupId = @id'),
    ]);
    await writeAuditLog({
      userId: req.authUser!.id,
      eventType: 'GROUP_CHANGED',
      detail: `${action === 'add' ? 'added' : 'removed'} user '${userRow.recordset[0]?.Username ?? userId}' ${action === 'add' ? 'to' : 'from'} group '${groupRow.recordset[0]?.Name ?? groupId}'`,
      ipAddress: clientIp(req),
    });

    res.status(204).end();
  } catch (err) {
    next(err);
  }
});

router.post('/users/:id/force-logout', ...requireUiAdmin, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const userId = Number(req.params.id);
    const pool = await getPool();
    const result = await pool.request().input('id', sql.Int, userId).query('UPDATE Users SET TokenValidAfter = SYSUTCDATETIME() OUTPUT INSERTED.Username WHERE UserId = @id');

    await writeAuditLog({
      userId: req.authUser!.id,
      eventType: 'FORCE_LOGOUT',
      detail: `target user '${result.recordset[0]?.Username}' (id ${userId})`,
      ipAddress: clientIp(req),
    });

    res.redirect(`/admin-ui/users/${userId}`);
  } catch (err) {
    next(err);
  }
});

// Hard delete (unlike the Active/Locked toggles above, which are the normal
// way to disable an account) - cascades UserRoles/UserGroupMembers, and
// AuditLog rows for this user keep their history with UserId set to NULL
// (schema FK_AuditLog_User ON DELETE SET NULL). Blocked against the
// currently signed-in admin deleting their own account, which would end
// their own session mid-request with no way back into the console as
// themselves.
router.post('/users/:id/delete', ...requireUiAdmin, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const userId = Number(req.params.id);
    if (userId === req.authUser!.id) {
      res.status(400).send('You cannot delete your own account.');
      return;
    }
    const pool = await getPool();
    const result = await pool.request().input('id', sql.Int, userId).query('DELETE FROM Users OUTPUT DELETED.Username WHERE UserId = @id');
    if (result.rowsAffected[0] === 0) {
      res.status(404).send('User not found.');
      return;
    }

    await writeAuditLog({
      userId: req.authUser!.id,
      eventType: 'USER_DELETED',
      detail: `deleted user '${result.recordset[0].Username}' (id ${userId})`,
      ipAddress: clientIp(req),
    });

    res.redirect('/admin-ui/users');
  } catch (err) {
    next(err);
  }
});

// --- Roles ----------------------------------------------------------------

router.get('/roles', ...requireUiAdmin, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const pool = await getPool();
    const result = await pool.request().query(`
      SELECT r.RoleId, r.Name, r.Description, r.IsFullAccess,
             (SELECT COUNT(*) FROM UserRoles ur WHERE ur.RoleId = r.RoleId) AS UserCount,
             (SELECT COUNT(*) FROM RolePermissions rp WHERE rp.RoleId = r.RoleId) AS PermissionCount
      FROM Roles r ORDER BY r.Name
    `);
    res.render('roles', { authUser: req.authUser, roles: result.recordset });
  } catch (err) {
    next(err);
  }
});

router.post('/roles', ...requireUiAdmin, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { name, description } = req.body || {};
    if (!name || String(name).trim().length < 2) {
      res.status(400).send('Role name must be at least 2 characters.');
      return;
    }
    const pool = await getPool();
    await pool
      .request()
      .input('name', sql.NVarChar(100), name)
      .input('description', sql.NVarChar(400), description || null)
      .query('INSERT INTO Roles (Name, Description) VALUES (@name, @description)');

    await writeAuditLog({ userId: req.authUser!.id, eventType: 'ROLE_CREATED', detail: `created role '${name}'`, ipAddress: clientIp(req) });

    res.redirect('/admin-ui/roles');
  } catch (err) {
    next(err);
  }
});

// Splits "leads.leads.export" into module path "leads.leads" (everything but
// the last segment) and action "export" (the last segment) - purely a
// display grouping for the matrix screen; the stored Key stays one flat
// string (architecture doc §6.1) and this parsing lives only here.
function splitPermissionKey(key: string): { modulePath: string; action: string } {
  const lastDot = key.lastIndexOf('.');
  return { modulePath: key.slice(0, lastDot), action: key.slice(lastDot + 1) };
}

router.get('/roles/:id', ...requireUiAdmin, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const roleId = Number(req.params.id);
    const pool = await getPool();

    const role = await pool.request().input('id', sql.Int, roleId).query('SELECT RoleId, Name, Description, IsFullAccess FROM Roles WHERE RoleId = @id');
    if (!role.recordset[0]) {
      res.status(404).send('Role not found.');
      return;
    }

    const allPerms = await pool.request().query(`
      SELECT p.PermissionId, p.[Key], a.[Key] AS AppKey, a.Name AS AppName
      FROM Permissions p JOIN Apps a ON a.AppId = p.AppId
      ORDER BY a.Name, p.[Key]
    `);
    const granted = await pool.request().input('roleId', sql.Int, roleId).query('SELECT PermissionId FROM RolePermissions WHERE RoleId = @roleId');
    const grantedIds = new Set((granted.recordset as { PermissionId: number }[]).map((r) => r.PermissionId));

    type PermRow = { PermissionId: number; Key: string; AppKey: string; AppName: string };
    const byApp = new Map<string, { appKey: string; appName: string; actions: Set<string>; modules: Map<string, Record<string, { permissionId: number; granted: boolean }>> }>();

    for (const row of allPerms.recordset as PermRow[]) {
      if (!byApp.has(row.AppKey)) byApp.set(row.AppKey, { appKey: row.AppKey, appName: row.AppName, actions: new Set(), modules: new Map() });
      const app = byApp.get(row.AppKey)!;
      const { modulePath, action } = splitPermissionKey(row.Key);
      app.actions.add(action);
      if (!app.modules.has(modulePath)) app.modules.set(modulePath, {});
      app.modules.get(modulePath)![action] = { permissionId: row.PermissionId, granted: grantedIds.has(row.PermissionId) };
    }

    const appsGrouped = [...byApp.values()].map((app) => ({
      appKey: app.appKey,
      appName: app.appName,
      actions: [...app.actions].sort(),
      modules: [...app.modules.entries()].map(([modulePath, cells]) => ({ modulePath, cells })),
    }));

    res.render('role-permissions', { authUser: req.authUser, role: role.recordset[0], appsGrouped });
  } catch (err) {
    next(err);
  }
});

router.post('/roles/:id', ...requireUiAdmin, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const roleId = Number(req.params.id);
    const { name, description } = req.body || {};
    if (!name || String(name).trim().length < 2) {
      res.status(400).send('Role name must be at least 2 characters.');
      return;
    }
    const pool = await getPool();
    const before = await pool.request().input('id', sql.Int, roleId).query('SELECT Name, Description FROM Roles WHERE RoleId = @id');
    await pool
      .request()
      .input('id', sql.Int, roleId)
      .input('name', sql.NVarChar(100), name)
      .input('description', sql.NVarChar(400), description || null)
      .query('UPDATE Roles SET Name = @name, Description = @description WHERE RoleId = @id');

    await writeAuditLog({
      userId: req.authUser!.id,
      eventType: 'ROLE_UPDATED',
      detail: `target role id ${roleId}: ${diffFields(before.recordset[0], { Name: name, Description: description || null }, { Name: 'name', Description: 'description' })}`,
      ipAddress: clientIp(req),
    });

    res.redirect(`/admin-ui/roles/${roleId}`);
  } catch (err) {
    next(err);
  }
});

// A full-access role bypasses RolePermissions entirely (schema comment on
// Roles.IsFullAccess) - deleting the wrong one here could strip every admin
// of console access with no way back in through this same console, so it's
// blocked outright rather than just confirmed.
router.post('/roles/:id/delete', ...requireUiAdmin, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const roleId = Number(req.params.id);
    const pool = await getPool();
    const role = await pool.request().input('id', sql.Int, roleId).query('SELECT Name, IsFullAccess FROM Roles WHERE RoleId = @id');
    if (!role.recordset[0]) {
      res.status(404).send('Role not found.');
      return;
    }
    if (role.recordset[0].IsFullAccess) {
      res.status(400).send('Full-access roles cannot be deleted.');
      return;
    }
    await pool.request().input('id', sql.Int, roleId).query('DELETE FROM Roles WHERE RoleId = @id');

    await writeAuditLog({
      userId: req.authUser!.id,
      eventType: 'ROLE_DELETED',
      detail: `deleted role '${role.recordset[0].Name}' (id ${roleId})`,
      ipAddress: clientIp(req),
    });

    res.redirect('/admin-ui/roles');
  } catch (err) {
    next(err);
  }
});

router.post('/roles/:id/permissions', ...requireUiAdmin, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const roleId = Number(req.params.id);
    const { permissionId, action } = req.body || {};
    const pool = await getPool();
    if (action === 'add') {
      await pool
        .request()
        .input('roleId', sql.Int, roleId)
        .input('permissionId', sql.Int, permissionId)
        .query('IF NOT EXISTS (SELECT 1 FROM RolePermissions WHERE RoleId = @roleId AND PermissionId = @permissionId) INSERT INTO RolePermissions (RoleId, PermissionId) VALUES (@roleId, @permissionId)');
    } else {
      await pool.request().input('roleId', sql.Int, roleId).input('permissionId', sql.Int, permissionId).query('DELETE FROM RolePermissions WHERE RoleId = @roleId AND PermissionId = @permissionId');
    }

    const [roleRow, permRow] = await Promise.all([
      pool.request().input('id', sql.Int, roleId).query('SELECT Name FROM Roles WHERE RoleId = @id'),
      pool.request().input('id', sql.Int, permissionId).query('SELECT p.[Key] AS PermKey, a.[Key] AS AppKey FROM Permissions p JOIN Apps a ON a.AppId = p.AppId WHERE p.PermissionId = @id'),
    ]);
    await writeAuditLog({
      userId: req.authUser!.id,
      eventType: 'PERMISSIONS_UPDATED',
      appKey: permRow.recordset[0]?.AppKey ?? null,
      detail: `${action === 'add' ? 'granted' : 'revoked'} permission '${permRow.recordset[0]?.PermKey ?? permissionId}' ${action === 'add' ? 'to' : 'from'} role '${roleRow.recordset[0]?.Name ?? roleId}'`,
      ipAddress: clientIp(req),
    });

    res.status(204).end();
  } catch (err) {
    next(err);
  }
});

// --- Groups -----------------------------------------------------------------

router.get('/groups', ...requireUiAdmin, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const pool = await getPool();
    const result = await pool.request().query(`
      SELECT g.GroupId, g.Name, g.Description,
             (SELECT COUNT(*) FROM UserGroupMembers m WHERE m.GroupId = g.GroupId) AS MemberCount,
             (SELECT COUNT(*) FROM GroupRoles gr WHERE gr.GroupId = g.GroupId) AS RoleCount
      FROM UserGroups g ORDER BY g.Name
    `);
    res.render('groups', { authUser: req.authUser, groups: result.recordset });
  } catch (err) {
    next(err);
  }
});

router.post('/groups', ...requireUiAdmin, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { name, description } = req.body || {};
    if (!name || String(name).trim().length < 2) {
      res.status(400).send('Group name must be at least 2 characters.');
      return;
    }
    const pool = await getPool();
    await pool
      .request()
      .input('name', sql.NVarChar(150), name)
      .input('description', sql.NVarChar(400), description || null)
      .query('INSERT INTO UserGroups (Name, Description) VALUES (@name, @description)');

    await writeAuditLog({ userId: req.authUser!.id, eventType: 'GROUP_CREATED', detail: `created group '${name}'`, ipAddress: clientIp(req) });

    res.redirect('/admin-ui/groups');
  } catch (err) {
    next(err);
  }
});

router.get('/groups/:id', ...requireUiAdmin, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const groupId = Number(req.params.id);
    const pool = await getPool();

    const group = await pool.request().input('id', sql.Int, groupId).query('SELECT GroupId, Name, Description FROM UserGroups WHERE GroupId = @id');
    if (!group.recordset[0]) {
      res.status(404).send('Group not found.');
      return;
    }

    const [members, allRoles, groupRoles] = await Promise.all([
      pool.request().input('id', sql.Int, groupId).query('SELECT u.UserId, u.Username, u.DisplayName FROM UserGroupMembers m JOIN Users u ON u.UserId = m.UserId WHERE m.GroupId = @id ORDER BY u.Username'),
      pool.request().query('SELECT RoleId, Name FROM Roles ORDER BY Name'),
      pool.request().input('id', sql.Int, groupId).query('SELECT RoleId FROM GroupRoles WHERE GroupId = @id'),
    ]);

    res.render('group-detail', {
      authUser: req.authUser,
      group: group.recordset[0],
      members: members.recordset,
      allRoles: allRoles.recordset,
      roleIds: (groupRoles.recordset as { RoleId: number }[]).map((r) => r.RoleId),
    });
  } catch (err) {
    next(err);
  }
});

router.post('/groups/:id', ...requireUiAdmin, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const groupId = Number(req.params.id);
    const { name, description } = req.body || {};
    if (!name || String(name).trim().length < 2) {
      res.status(400).send('Group name must be at least 2 characters.');
      return;
    }
    const pool = await getPool();
    const before = await pool.request().input('id', sql.Int, groupId).query('SELECT Name, Description FROM UserGroups WHERE GroupId = @id');
    await pool
      .request()
      .input('id', sql.Int, groupId)
      .input('name', sql.NVarChar(150), name)
      .input('description', sql.NVarChar(400), description || null)
      .query('UPDATE UserGroups SET Name = @name, Description = @description WHERE GroupId = @id');

    await writeAuditLog({
      userId: req.authUser!.id,
      eventType: 'GROUP_UPDATED',
      detail: `target group id ${groupId}: ${diffFields(before.recordset[0], { Name: name, Description: description || null }, { Name: 'name', Description: 'description' })}`,
      ipAddress: clientIp(req),
    });

    res.redirect(`/admin-ui/groups/${groupId}`);
  } catch (err) {
    next(err);
  }
});

router.post('/groups/:id/delete', ...requireUiAdmin, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const groupId = Number(req.params.id);
    const pool = await getPool();
    const result = await pool.request().input('id', sql.Int, groupId).query('DELETE FROM UserGroups OUTPUT DELETED.Name WHERE GroupId = @id');

    await writeAuditLog({
      userId: req.authUser!.id,
      eventType: 'GROUP_DELETED',
      detail: `deleted group '${result.recordset[0]?.Name}' (id ${groupId})`,
      ipAddress: clientIp(req),
    });

    res.redirect('/admin-ui/groups');
  } catch (err) {
    next(err);
  }
});

router.post('/groups/:id/roles', ...requireUiAdmin, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const groupId = Number(req.params.id);
    const { roleId, action } = req.body || {};
    const pool = await getPool();
    if (action === 'add') {
      await pool
        .request()
        .input('groupId', sql.Int, groupId)
        .input('roleId', sql.Int, roleId)
        .query('IF NOT EXISTS (SELECT 1 FROM GroupRoles WHERE GroupId = @groupId AND RoleId = @roleId) INSERT INTO GroupRoles (GroupId, RoleId) VALUES (@groupId, @roleId)');
    } else {
      await pool.request().input('groupId', sql.Int, groupId).input('roleId', sql.Int, roleId).query('DELETE FROM GroupRoles WHERE GroupId = @groupId AND RoleId = @roleId');
    }

    const [groupRow, roleRow] = await Promise.all([
      pool.request().input('id', sql.Int, groupId).query('SELECT Name FROM UserGroups WHERE GroupId = @id'),
      pool.request().input('id', sql.Int, roleId).query('SELECT Name FROM Roles WHERE RoleId = @id'),
    ]);
    await writeAuditLog({
      userId: req.authUser!.id,
      eventType: 'GROUP_ROLE_CHANGED',
      detail: `${action === 'add' ? 'granted' : 'revoked'} role '${roleRow.recordset[0]?.Name ?? roleId}' ${action === 'add' ? 'to' : 'from'} group '${groupRow.recordset[0]?.Name ?? groupId}'`,
      ipAddress: clientIp(req),
    });

    res.status(204).end();
  } catch (err) {
    next(err);
  }
});

router.post('/groups/:id/members', ...requireUiAdmin, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const groupId = Number(req.params.id);
    const { userId, action } = req.body || {};
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

    const [userRow, groupRow] = await Promise.all([
      pool.request().input('id', sql.Int, userId).query('SELECT Username FROM Users WHERE UserId = @id'),
      pool.request().input('id', sql.Int, groupId).query('SELECT Name FROM UserGroups WHERE GroupId = @id'),
    ]);
    await writeAuditLog({
      userId: req.authUser!.id,
      eventType: 'GROUP_CHANGED',
      detail: `${action === 'add' ? 'added' : 'removed'} user '${userRow.recordset[0]?.Username ?? userId}' ${action === 'add' ? 'to' : 'from'} group '${groupRow.recordset[0]?.Name ?? groupId}'`,
      ipAddress: clientIp(req),
    });

    res.status(204).end();
  } catch (err) {
    next(err);
  }
});

// --- Apps -----------------------------------------------------------------

router.get('/apps', ...requireUiAdmin, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const pool = await getPool();
    const result = await pool.request().query(`
      SELECT a.AppId, a.[Key], a.Name, a.BaseUrl, a.IsActive,
             (SELECT COUNT(*) FROM Permissions p WHERE p.AppId = a.AppId) AS PermissionCount
      FROM Apps a ORDER BY a.Name
    `);
    res.render('apps', { authUser: req.authUser, apps: result.recordset });
  } catch (err) {
    next(err);
  }
});

router.post('/apps', ...requireUiAdmin, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { key, name, baseUrl } = req.body || {};
    if (!key || !name || !/^[a-z][a-z0-9-]*$/.test(key)) {
      res.status(400).send('A lowercase key (letters, digits, hyphens) and a name are required.');
      return;
    }
    const pool = await getPool();
    await pool
      .request()
      .input('key', sql.NVarChar(50), key)
      .input('name', sql.NVarChar(150), name)
      .input('baseUrl', sql.NVarChar(300), baseUrl || null)
      .query('INSERT INTO Apps ([Key], Name, BaseUrl) VALUES (@key, @name, @baseUrl)');

    await writeAuditLog({ userId: req.authUser!.id, eventType: 'APP_REGISTERED', appKey: key, detail: `registered app '${name}' (key: ${key})`, ipAddress: clientIp(req) });

    res.redirect('/admin-ui/apps');
  } catch (err) {
    next(err);
  }
});

router.get('/apps/:key/edit', ...requireUiAdmin, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const pool = await getPool();
    const result = await pool
      .request()
      .input('key', sql.NVarChar(50), req.params.key)
      .query('SELECT AppId, [Key], Name, BaseUrl, IsActive FROM Apps WHERE [Key] = @key');
    const app = result.recordset[0];
    if (!app) {
      res.status(404).send('App not found.');
      return;
    }
    res.render('app-edit', { authUser: req.authUser, app, error: null });
  } catch (err) {
    next(err);
  }
});

// The Key itself is immutable here - it's the namespace prefix every one of
// this app's permission keys already carries (architecture doc §6.1/§8.3);
// renaming it would orphan every existing permission key. Register a new
// app instead if the key itself needs to change.
router.post('/apps/:key/edit', ...requireUiAdmin, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { name, baseUrl, isActive } = req.body || {};
    if (!name) {
      const pool = await getPool();
      const result = await pool.request().input('key', sql.NVarChar(50), req.params.key).query('SELECT AppId, [Key], Name, BaseUrl, IsActive FROM Apps WHERE [Key] = @key');
      res.status(400).render('app-edit', { authUser: req.authUser, app: result.recordset[0], error: 'Name is required.' });
      return;
    }

    const pool = await getPool();
    const before = await pool.request().input('key', sql.NVarChar(50), req.params.key).query('SELECT Name, BaseUrl, IsActive FROM Apps WHERE [Key] = @key');
    await pool
      .request()
      .input('key', sql.NVarChar(50), req.params.key)
      .input('name', sql.NVarChar(150), name)
      .input('baseUrl', sql.NVarChar(300), baseUrl || null)
      .input('isActive', sql.Bit, isActive === 'true')
      .query('UPDATE Apps SET Name = @name, BaseUrl = @baseUrl, IsActive = @isActive WHERE [Key] = @key');

    await writeAuditLog({
      userId: req.authUser!.id,
      eventType: 'APP_REGISTERED',
      appKey: req.params.key,
      detail: `updated app (key: ${req.params.key}): ${diffFields(before.recordset[0], { Name: name, BaseUrl: baseUrl || null, IsActive: isActive === 'true' }, { Name: 'name', BaseUrl: 'base URL', IsActive: 'active' })}`,
      ipAddress: clientIp(req),
    });

    res.redirect('/admin-ui/apps');
  } catch (err) {
    next(err);
  }
});

// Cascades to this app's Permissions and, from there, to RolePermissions
// (schema FK_Permissions_App / FK_RolePermissions_Permission) - any role
// holding one of this app's permissions silently loses it, so the template
// confirms with the permission count before submitting. This is the exact
// action that wiped Company Portal's app + permission catalog with zero
// audit trail before this logging existed - log generously here.
router.post('/apps/:key/delete', ...requireUiAdmin, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const pool = await getPool();
    const permCount = await pool.request().input('key', sql.NVarChar(50), req.params.key).query('SELECT COUNT(*) AS n FROM Permissions p JOIN Apps a ON a.AppId = p.AppId WHERE a.[Key] = @key');
    const result = await pool.request().input('key', sql.NVarChar(50), req.params.key).query('DELETE FROM Apps OUTPUT DELETED.Name WHERE [Key] = @key');
    if (result.rowsAffected[0] === 0) {
      res.status(404).send('App not found.');
      return;
    }

    await writeAuditLog({
      userId: req.authUser!.id,
      eventType: 'APP_DELETED',
      appKey: req.params.key,
      detail: `deleted app '${result.recordset[0].Name}' (key: ${req.params.key}) and its ${permCount.recordset[0].n} permission key(s), cascading to any role that granted them`,
      ipAddress: clientIp(req),
    });

    res.redirect('/admin-ui/apps');
  } catch (err) {
    next(err);
  }
});

// --- Audit ------------------------------------------------------------------

const AUDIT_PAGE_SIZE = 50;

router.get('/audit', ...requireUiAdmin, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { page = '1', search } = req.query as Record<string, string>;
    const pageNum = Math.max(1, Number(page) || 1);
    const pool = await getPool();
    const request = pool.request();
    let where = '1=1';
    const term = search ? search.trim() : '';
    if (term) {
      // One field, wildcard across everything a row could plausibly be
      // searched by - event type, app (key or name), username, IP, detail -
      // rather than separate exact-match dropdowns per column.
      request.input('search', sql.NVarChar(200), `%${term}%`);
      where += ` AND (
        a.EventType LIKE @search
        OR a.AppKey LIKE @search
        OR ap.Name LIKE @search
        OR u.Username LIKE @search
        OR a.IpAddress LIKE @search
        OR a.Detail LIKE @search
      )`;
    }
    request.input('offset', sql.Int, (pageNum - 1) * AUDIT_PAGE_SIZE).input('pageSize', sql.Int, AUDIT_PAGE_SIZE);

    const result = await request.query(`
      SELECT a.AuditId, a.EventType, a.AppKey, ap.Name AS AppName, a.Detail, a.IpAddress, a.CreatedAt, u.Username
      FROM AuditLog a
      LEFT JOIN Users u ON u.UserId = a.UserId
      LEFT JOIN Apps ap ON ap.[Key] = a.AppKey
      WHERE ${where}
      ORDER BY a.CreatedAt DESC
      OFFSET @offset ROWS FETCH NEXT @pageSize ROWS ONLY
    `);

    res.render('audit', { authUser: req.authUser, entries: result.recordset, page: pageNum, pageSize: AUDIT_PAGE_SIZE, filters: { search } });
  } catch (err) {
    next(err);
  }
});

export default router;
