const { Pool } = require("pg");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === "true" ? { rejectUnauthorized: false } : undefined,
  max: Number(process.env.PGPOOL_MAX || 10),
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 10_000,
});

pool.on("error", (error) => console.error("Unexpected idle PostgreSQL error", error));

async function initDatabase() {
  if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required");
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      full_name VARCHAR(120) NOT NULL,
      username VARCHAR(30) NOT NULL,
      email VARCHAR(254) NOT NULL,
      password_hash TEXT NOT NULL,
      role VARCHAR(10) NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
      status VARCHAR(12) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
      bio VARCHAR(240) NOT NULL DEFAULT '',
      progress JSONB NOT NULL DEFAULT '{}'::jsonb,
      email_verified_at TIMESTAMPTZ,
      email_verification_token_hash TEXT,
      email_verification_expires_at TIMESTAMPTZ,
      password_reset_token_hash TEXT,
      password_reset_expires_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_login_at TIMESTAMPTZ
    );
    ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified_at TIMESTAMPTZ;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verification_token_hash TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verification_expires_at TIMESTAMPTZ;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS password_reset_token_hash TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS password_reset_expires_at TIMESTAMPTZ;
    UPDATE users SET email_verified_at = created_at
      WHERE email_verified_at IS NULL AND email_verification_token_hash IS NULL;
    CREATE UNIQUE INDEX IF NOT EXISTS users_email_lower_unique ON users (LOWER(email));
    CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower_unique ON users (LOWER(username));

    CREATE TABLE IF NOT EXISTS resources (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      uploader_id UUID REFERENCES users(id) ON DELETE SET NULL,
      title VARCHAR(160) NOT NULL,
      category VARCHAR(80) NOT NULL,
      description VARCHAR(500) NOT NULL,
      file_name VARCHAR(255) NOT NULL,
      file_data BYTEA NOT NULL,
      status VARCHAR(12) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
      reviewer_id UUID REFERENCES users(id) ON DELETE SET NULL,
      review_note VARCHAR(500) NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      reviewed_at TIMESTAMPTZ
    );
    CREATE INDEX IF NOT EXISTS resources_status_created_idx ON resources (status, created_at DESC);
  `);
}

module.exports = { pool, initDatabase };
