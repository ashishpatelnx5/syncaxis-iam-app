import sql from 'mssql';
import { env } from './env';

let poolPromise: Promise<sql.ConnectionPool> | null = null;

export function getPool(): Promise<sql.ConnectionPool> {
  if (!poolPromise) {
    poolPromise = new sql.ConnectionPool({
      server: env.db.server,
      ...(env.db.port ? { port: env.db.port } : {}),
      database: env.db.database,
      user: env.db.user,
      password: env.db.password,
      options: {
        encrypt: env.db.encrypt,
        trustServerCertificate: env.db.trustServerCertificate,
        ...(env.db.instanceName ? { instanceName: env.db.instanceName } : {}),
      },
      pool: {
        max: 10,
        min: 0,
        idleTimeoutMillis: 30000,
      },
    })
      .connect()
      .catch((err) => {
        poolPromise = null;
        throw err;
      });
  }
  return poolPromise;
}

export { sql };
