import 'dotenv/config';

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Missing required environment variable: ${name}`);
  return value;
}

// DB_SERVER may be a plain host ("localhost", "SYNCAXIS-SERVER") or a named
// instance in "HOST\INSTANCE" form (e.g. "SYNCAXIS-SERVER\SQLEXPRESS"). Named
// instances are resolved via the SQL Server Browser service (UDP 1434)
// instead of a fixed port, so `port` and `instanceName` are mutually
// exclusive - same convention Leads Tracker's config.ts already uses.
function parseServer(raw: string): { server: string; instanceName?: string } {
  const [server, instanceName] = raw.split('\\');
  return instanceName ? { server, instanceName } : { server };
}

const { server, instanceName } = parseServer(required('DB_SERVER'));

export const env = {
  port: Number(process.env.PORT) || 4100,
  // Only set true once the service is actually served over HTTPS. Its CSP
  // "upgrade-insecure-requests" makes browsers rewrite the page's logo/CSS/
  // form posts to https:// - on a plain-http server (except localhost, which
  // browsers exempt) that breaks images and login for every remote user.
  httpsOnly: process.env.HTTPS_ONLY === 'true',
  db: {
    server,
    instanceName,
    port: instanceName ? undefined : Number(process.env.DB_PORT) || 1433,
    database: process.env.DB_NAME || 'SYNCAXIS_AUTHCENTER',
    user: required('DB_USER'),
    password: required('DB_PASSWORD'),
    encrypt: process.env.DB_ENCRYPT === 'true',
    trustServerCertificate: process.env.DB_TRUST_SERVER_CERTIFICATE !== 'false',
  },
  jwtSecret: required('JWT_SECRET'),
  jwtExpiresIn: process.env.JWT_EXPIRES_IN || '8h',
  sessionTtlHours: Number(process.env.SESSION_TTL_HOURS) || 8,
  ssoCodeTtlSeconds: Number(process.env.SSO_CODE_TTL_SECONDS) || 60,
  maxFailedLogins: Number(process.env.MAX_FAILED_LOGINS) || 3,
  // Bootstrap script only (scripts/seed.ts) - intentionally not required here
  // so the app itself never depends on these being set.
  seedAdminUsername: process.env.SEED_ADMIN_USERNAME,
  seedAdminPassword: process.env.SEED_ADMIN_PASSWORD,
};
