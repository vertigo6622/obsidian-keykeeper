const Database = require('better-sqlite3-multiple-ciphers');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');

const dbPath = 'data/tor.db';
let dbKey = process.env.DATABASE_KEY;

if (!fs.existsSync(dbPath)) {
  dbKey = crypto.randomBytes(32).toString('hex');
  console.log('[database] no database found! creating new one with key:', dbKey);
}

if (!dbKey) {
  throw new Error('DATABASE_KEY environment variable is required');
}

if (!/^[0-9a-fA-F]{64}$/.test(dbKey)) {
  throw new Error('DATABASE_KEY must be a 64-character hex string');
}

const db = new Database(dbPath);

db.pragma("key = '" + dbKey + "'");
db.pragma('cipher = sqlcipher');
db.pragma('kdf_iter = 256000');
db.pragma('busy_timeout = 5000');

try {
  db.prepare('SELECT COUNT(*) FROM sqlite_master').get();
} catch (e) {
  throw new Error('Cannot decrypt database. DATABASE_KEY may be incorrect or database is corrupted.');
}

db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    password_hash TEXT NOT NULL,
    account_number TEXT UNIQUE NOT NULL,
    hwid TEXT,
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
    speck_key TEXT,
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
    subindex INTEGER,
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
    CHECK (status IN ('pending', 'detected', 'activating', 'confirmed', 'completed', 'expired', 'failed')),
    CHECK (type IN ('purchase', 'deposit', 'withdraw'))
  );

  CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sid TEXT UNIQUE NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users(id),
    ip TEXT,
    user_agent TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expired DATETIME NOT NULL
  );

  CREATE TABLE IF NOT EXISTS register_rate_limit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    attempted_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS login_rate_limit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    attempted_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS login_failures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    session_id TEXT,
    attempted_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS relink_rate_limit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    attempted_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS tx_create_rate_limit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    attempted_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS product_verifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    license_id TEXT NOT NULL,
    ip TEXT,
    success INTEGER DEFAULT 0,
    verified_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS hwid_verify_rate_limit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    session_id TEXT,
    attempted_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS withdraw_rate_limit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    currency TEXT NOT NULL,
    attempted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    CHECK (currency IN ('XMR', 'LTC'))
  );

  CREATE TABLE IF NOT EXISTS admin_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action_type TEXT NOT NULL,
    target_type TEXT,
    target_id TEXT,
    details TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
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
  CREATE INDEX IF NOT EXISTS idx_register_rate_limit_session_time ON register_rate_limit(session_id, attempted_at);
  CREATE INDEX IF NOT EXISTS idx_tx_create_rate_limit_user_time ON tx_create_rate_limit(user_id, attempted_at);
  CREATE INDEX IF NOT EXISTS idx_login_rate_limit_session_time ON login_rate_limit(session_id, attempted_at);
  CREATE INDEX IF NOT EXISTS idx_login_failures_user_time ON login_failures(user_id, attempted_at);
  CREATE INDEX IF NOT EXISTS idx_product_verifications_license_id ON product_verifications(license_id);
  CREATE INDEX IF NOT EXISTS idx_hwid_verify_rate_limit_user_time ON hwid_verify_rate_limit(user_id, attempted_at);
  CREATE INDEX IF NOT EXISTS idx_relink_rate_limit_user_time ON relink_rate_limit(user_id, attempted_at);
  CREATE INDEX IF NOT EXISTS idx_withdraw_rate_limit_user_time ON withdraw_rate_limit(user_id, attempted_at);
  CREATE INDEX IF NOT EXISTS idx_transactions_tx_hash ON transactions(tx_hash);
  CREATE INDEX IF NOT EXISTS idx_admin_audit_created ON admin_audit(created_at);
  CREATE INDEX IF NOT EXISTS idx_admin_audit_action ON admin_audit(action_type);
  CREATE INDEX IF NOT EXISTS idx_admin_audit_target ON admin_audit(target_type, target_id);
`);

db.prepare(`DELETE FROM admin_audit WHERE created_at < datetime('now', '-14 days')`).run();

module.exports = db;
