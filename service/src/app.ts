import cookieParser from 'cookie-parser';
import express from 'express';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import path from 'path';
import authRoutes from './routes/auth';
import healthRoutes from './routes/health';
import adminAppsRoutes from './routes/admin/apps';
import adminUsersRoutes from './routes/admin/users';
import adminRolesRoutes from './routes/admin/roles';
import adminGroupsRoutes from './routes/admin/groups';
import adminAuditRoutes from './routes/admin/audit';
import adminUiRoutes from './admin-ui/views-routes';

export function createApp() {
  const app = express();

  // No CORS middleware anywhere: /auth/* and /admin/* are server-to-server
  // only (architecture doc §8.1), and the admin console is server-rendered
  // by this same process, so nothing ever calls this API cross-origin.
  app.use(helmet());
  app.use(express.json({ limit: '1mb' }));
  app.use(express.urlencoded({ extended: false })); // admin-ui <form> posts
  app.use(cookieParser());

  app.set('view engine', 'ejs');
  app.set('views', path.join(__dirname, 'admin-ui', 'views'));

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
