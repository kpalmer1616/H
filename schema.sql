CREATE TABLE IF NOT EXISTS users (
 id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, salt TEXT NOT NULL,
 created_at TEXT NOT NULL DEFAULT (datetime('now')),
 plan TEXT NOT NULL DEFAULT 'none' CHECK(plan IN ('none','pro','business')),
 subscription_id TEXT, stripe_customer_id TEXT, subscription_status TEXT NOT NULL DEFAULT 'inactive',
 monthly_limit INTEGER NOT NULL DEFAULT 0, monthly_used INTEGER NOT NULL DEFAULT 0,
 credits INTEGER NOT NULL DEFAULT 0, reset_at TEXT
);
CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), expires_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS quotes (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), customer_name TEXT NOT NULL,
 service TEXT NOT NULL, hours REAL NOT NULL, hourly_rate REAL NOT NULL, materials REAL NOT NULL,
 overhead REAL NOT NULL, margin REAL NOT NULL, cost REAL NOT NULL, price REAL NOT NULL,
 credit_source TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS stripe_events (id TEXT PRIMARY KEY, received_at TEXT NOT NULL DEFAULT (datetime('now')));
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_quotes_user ON quotes(user_id,created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_subscription ON users(subscription_id) WHERE subscription_id IS NOT NULL;
