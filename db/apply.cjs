// Applies db/schema.sql and (if the schools table is empty) db/seed_schools.sql
// to the database configured in the backend's .env (DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD).
//
// Usage (from the backend root):
//   npm install --prefix ~/.cache/gradquest-db pg
//   NODE_PATH=~/.cache/gradquest-db/node_modules node db/apply.cjs
const fs = require("fs");
const path = require("path");
const { Client } = require("pg");

const root = path.join(__dirname, "..");

function loadEnv(file) {
  const env = {};
  for (const line of fs.readFileSync(file, "utf8").split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#") || !trimmed.includes("=")) continue;
    const idx = trimmed.indexOf("=");
    env[trimmed.slice(0, idx).trim()] = trimmed.slice(idx + 1).trim();
  }
  return env;
}

async function main() {
  const env = loadEnv(path.join(root, ".env"));
  const missing = ["DB_HOST", "DB_PORT", "DB_NAME", "DB_USER", "DB_PASSWORD"].filter((k) => !env[k]);
  if (missing.length) throw new Error(`Missing in .env: ${missing.join(", ")}`);

  const client = new Client({
    host: env.DB_HOST,
    port: Number(env.DB_PORT),
    database: env.DB_NAME,
    user: env.DB_USER,
    password: env.DB_PASSWORD,
    ssl: { rejectUnauthorized: false },
  });
  await client.connect();
  console.log("Connected.");

  try {
    await client.query(fs.readFileSync(path.join(__dirname, "schema.sql"), "utf8"));
    console.log("Schema applied.");

    const { rows } = await client.query("SELECT count(*)::int AS n FROM public.schools");
    if (rows[0].n === 0) {
      await client.query(fs.readFileSync(path.join(__dirname, "seed_schools.sql"), "utf8"));
      console.log("Schools seeded.");
    } else {
      console.log(`Schools table already has ${rows[0].n} rows; seed skipped.`);
    }

    const counts = await client.query(`
      SELECT c.relname AS table, c.relrowsecurity AS rls,
             (xpath('/row/n/text()', query_to_xml(format('SELECT count(*) AS n FROM public.%I', c.relname), false, true, '')))[1]::text::int AS rows
      FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'public' AND c.relkind = 'r'
      ORDER BY c.relname`);
    console.table(counts.rows);
  } finally {
    await client.end();
  }
}

main().catch((err) => {
  console.error("Failed:", err.message);
  process.exit(1);
});
