import cookieParser from 'cookie-parser';
import crypto from 'crypto';
import express from 'express';
import rateLimit from 'express-rate-limit';
import helmet, { contentSecurityPolicy } from 'helmet';
import path from 'path';
import { env } from './config/env';
import authRoutes from './routes/auth';
import healthRoutes from './routes/health';
import adminAppsRoutes from './routes/admin/apps';
import adminUsersRoutes from './routes/admin/users';
import adminRolesRoutes from './routes/admin/roles';
import adminGroupsRoutes from './routes/admin/groups';
import adminAuditRoutes from './routes/admin/audit';
import adminUiRoutes from './admin-ui/views-routes';

// Helmet's defaults minus upgrade-insecure-requests unless HTTPS_ONLY is on
// (see env.httpsOnly). Built explicitly with useDefaults:false because Helmet
// treats a null override as "keep the default", not "remove it".
const { 'upgrade-insecure-requests': upgradeInsecure, ...cspDefaultsWithoutUpgrade } = contentSecurityPolicy.getDefaultDirectives();
const cspDefaults = env.httpsOnly ? { ...cspDefaultsWithoutUpgrade, 'upgrade-insecure-requests': upgradeInsecure } : cspDefaultsWithoutUpgrade;

export function createApp() {
  const app = express();

  // No CORS middleware anywhere: /auth/* and /admin/* are server-to-server
  // only (architecture doc §8.1), and the admin console is server-rendered
  // by this same process, so nothing ever calls this API cross-origin.

  // Per-request nonce for the admin console's inline <script> blocks - must
  // be set before helmet() runs so its CSP header can reference it, and
  // before any res.render() call since EJS reads it off res.locals.
  app.use((_req, res, next) => {
    res.locals.cspNonce = crypto.randomBytes(16).toString('base64');
    next();
  });

  app.use(
    helmet({
      contentSecurityPolicy: {
        useDefaults: false,
        directives: {
          ...cspDefaults,
          // admin-ui's checkbox auto-save/delete-confirm scripts are inline
          // (server-rendered alongside their data, e.g. role/group ids) -
          // nonce them individually rather than allowing 'unsafe-inline'.
          'script-src': ["'self'", (_req, res) => `'nonce-${(res as express.Response).locals.cspNonce}'`],
        },
      },
    }),
  );
  app.use(express.json({ limit: '1mb' }));
  app.use(express.urlencoded({ extended: false })); // admin-ui <form> posts
  app.use(cookieParser());

  app.set('view engine', 'ejs');
  app.set('views', path.join(__dirname, 'admin-ui', 'views'));
  // Logo/favicon - served unauthenticated since the login page itself needs
  // the logo before any session exists. img-src 'self' (Helmet's default)
  // already covers same-origin static assets, no CSP change needed.
  app.use('/admin-ui/assets', express.static(path.join(__dirname, 'admin-ui', 'public')));

  // Login throttling (architecture doc §12) - per-IP on top of the
  // per-username lockout already enforced in lib/authenticate.ts.
  const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: true, legacyHeaders: false });
  app.use('/auth/login', loginLimiter);
  app.use('/admin-ui/login', loginLimiter);

  // Root maps to the admin console - the only human-facing surface this
  // service has; every other route is a server-to-server JSON API.
  app.get('/', (_req, res) => res.redirect('/admin-ui'));

  app.use(healthRoutes); // defines GET /health itself
  app.use('/auth', authRoutes);
  app.use('/admin/apps', adminAppsRoutes);
  app.use('/admin/users', adminUsersRoutes);
  app.use('/admin/roles', adminRolesRoutes);
  app.use('/admin/groups', adminGroupsRoutes);
  app.use('/admin/audit', adminAuditRoutes);
  app.use('/admin-ui', adminUiRoutes);

  app.use((req, res) => res.status(404).json({ error: 'Not found.' }));

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    console.error(err);
    res.status(500).json({ error: 'Something went wrong on the server.' });
  });

  return app;
}
