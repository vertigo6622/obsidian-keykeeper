const Database = require('better-sqlite3');
const path = require('path');

const dbPath = path.join(__dirname, 'data', 'obsidian.db');
const db = new Database(dbPath);

db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    password_hash TEXT NOT NULL,
    account_number TEXT UNIQUE NOT NULL,
    hwid TEXT,
    speck_key TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME,
    locked_at DATETIME,
    suspended INTEGER DEFAULT 0,
    CHECK (LENGTH(account_number) = 12)
  );

  CREATE TABLE IF NOT EXISTS licenses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    license_id TEXT UNIQUE NOT NULL,
    user_id INTEGER REFERENCES users(id),
    type TEXT NOT NULL,
    hwid TEXT,
    stub_mac TEXT,
    integrity TEXT,
    download_filename TEXT,
    expires_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_relink_at DATETIME,
    CHECK (expires_at IS NULL OR expires_at > created_at)
  );

  CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER REFERENCES users(id),
    license_id TEXT,
    type TEXT NOT NULL,
    currency TEXT NOT NULL,
    amount REAL NOT NULL,
    address TEXT NOT NULL,
    signed_address TEXT,
    tx_hash TEXT,
    status TEXT DEFAULT 'pending',
    checkout_id TEXT,
    metadata TEXT,
    license_type TEXT,
    hwid TEXT,
    stub_mac TEXT,
    detected_at DATETIME,
    confirmations INTEGER DEFAULT 0,
    expires_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    usd_amount REAL,
    CHECK (amount > 0),
    CHECK (confirmations >= 0),
    CHECK (status IN ('pending', 'detected', 'completing', 'completed', 'expired', 'failed')),
    CHECK (type IN ('purchase', 'deposit', 'withdraw'))
  );

  CREATE TABLE IF NOT EXISTS register_rate_limit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    attempted_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS login_rate_limit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    attempted_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS login_failures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    ip TEXT NOT NULL,
    attempted_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS relink_rate_limit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    attempted_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS auth_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER REFERENCES users(id),
    token TEXT UNIQUE NOT NULL,
    expires_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS tx_create_rate_limit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    ip TEXT NOT NULL,
    attempted_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS sessions (
    sid TEXT PRIMARY KEY,
    sess TEXT NOT NULL,
    expired DATETIME NOT NULL,
    user_id INTEGER,
    ip TEXT,
    user_agent TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS product_verifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    license_id TEXT NOT NULL,
    ip TEXT,
    success INTEGER DEFAULT 0,
    verified_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT UNIQUE NOT NULL,
    user_id INTEGER REFERENCES users(id),
    label TEXT,
    active INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_used_at DATETIME
  );

  CREATE TABLE IF NOT EXISTS hwid_verify_rate_limit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    ip TEXT NOT NULL,
    attempted_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS withdraw_rate_limit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    ip TEXT NOT NULL,
    currency TEXT NOT NULL,
    attempted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    CHECK (currency IN ('XMR', 'LTC'))
  );
`);

db.exec(`
  CREATE INDEX IF NOT EXISTS idx_transactions_user_id ON transactions(user_id);
  CREATE INDEX IF NOT EXISTS idx_transactions_status ON transactions(status);
  CREATE INDEX IF NOT EXISTS idx_transactions_type ON transactions(type);
  CREATE INDEX IF NOT EXISTS idx_transactions_user_status_type ON transactions(user_id, status, type);
  CREATE INDEX IF NOT EXISTS idx_transactions_expires ON transactions(expires_at);
  CREATE INDEX IF NOT EXISTS idx_licenses_user_id ON licenses(user_id);
  CREATE INDEX IF NOT EXISTS idx_licenses_license_id ON licenses(license_id);
  CREATE INDEX IF NOT EXISTS idx_register_rate_limit_ip_time ON register_rate_limit(ip, attempted_at);
  CREATE INDEX IF NOT EXISTS idx_tx_create_rate_limit_user_time ON tx_create_rate_limit(user_id, attempted_at);
  CREATE INDEX IF NOT EXISTS idx_login_rate_limit_ip_time ON login_rate_limit(ip, attempted_at);
  CREATE INDEX IF NOT EXISTS idx_login_failures_user_time ON login_failures(user_id, attempted_at);
  CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
  CREATE INDEX IF NOT EXISTS idx_sessions_expired ON sessions(expired);
  CREATE INDEX IF NOT EXISTS idx_product_verifications_license_id ON product_verifications(license_id);
  CREATE INDEX IF NOT EXISTS idx_hwid_verify_rate_limit_user_time ON hwid_verify_rate_limit(user_id, attempted_at);
  CREATE INDEX IF NOT EXISTS idx_relink_rate_limit_ip_time ON relink_rate_limit(ip, attempted_at);
  CREATE INDEX IF NOT EXISTS idx_auth_tokens_user_id ON auth_tokens(user_id);
  CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);
  CREATE INDEX IF NOT EXISTS idx_withdraw_rate_limit_user_time ON withdraw_rate_limit(user_id, attempted_at);
  CREATE INDEX IF NOT EXISTS idx_transactions_tx_hash ON transactions(tx_hash);
`);

module.exports = db;
