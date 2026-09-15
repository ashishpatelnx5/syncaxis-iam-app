import { createApp } from './app';
import { env } from './config/env';
import { getPool } from './config/db';

async function main() {
  await getPool();
  console.log('Connected to SQL Server:', env.db.server, '/', env.db.database);

  const app = createApp();
  app.listen(env.port, () => {
    console.log(`syncaxis-iam listening on port ${env.port}`);
  });
}

main().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
