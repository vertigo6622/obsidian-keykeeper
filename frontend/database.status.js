const Database = require('better-sqlite3');
const path = require('path');

const dbPath = '/srv/db/status.db';
const db = new Database(dbPath);

db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS status_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    up INTEGER NOT NULL,
    uptime INTEGER DEFAULT 0,
    database_status TEXT NOT NULL,
    xmr_wallet_status TEXT NOT NULL,
    ltc_wallet_status TEXT NOT NULL,
    capacity TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_status_logs_timestamp ON status_logs(timestamp);
`);

function logStatus(status) {
  const stmt = db.prepare(`
    INSERT INTO status_logs (up, uptime, database_status, xmr_wallet_status, ltc_wallet_status, capacity)
    VALUES (?, ?, ?, ?, ?, ?)
  `);
  stmt.run(status.up ? 1 : 0, status.uptime || 0, status.database, status.xmr_wallet, status.ltc_wallet, status.capacity);
}

function getRecentStatus(minutes) {
  const stmt = db.prepare(`
    SELECT * FROM status_logs 
    WHERE timestamp > datetime('now', '-${minutes} minutes')
    ORDER BY timestamp ASC
  `);
  return stmt.all();
}

function getWeeklyStatus() {
  const stmt = db.prepare(`
    SELECT 
      datetime(timestamp) as ts,
      up,
      database_status,
      xmr_wallet_status,
      ltc_wallet_status,
      capacity
    FROM status_logs 
    WHERE timestamp > datetime('now', '-7 days')
    ORDER BY timestamp ASC
  `);
  return stmt.all();
}

function getLatestStatus() {
  const stmt = db.prepare(`
    SELECT * FROM status_logs ORDER BY timestamp DESC LIMIT 1
  `);
  return stmt.get();
}

function cleanupOldLogs() {
  const result = db.prepare(`
    DELETE FROM status_logs WHERE timestamp < datetime('now', '-7 days')
  `).run();
  return result.changes;
}

function getUptimeStats() {
  const total = db.prepare(`
    SELECT COUNT(*) as total FROM status_logs WHERE timestamp > datetime('now', '-7 days')
  `).get();
  
  const up = db.prepare(`
    SELECT COUNT(*) as up FROM status_logs WHERE up = 1 AND timestamp > datetime('now', '-7 days')
  `).get();
  
  if (total.total === 0) return { uptime_percent: 0, total_checks: 0 };
  
  return {
    uptime_percent: ((up.up / total.total) * 100).toFixed(2),
    total_checks: total.total
  };
}

module.exports = {
  logStatus,
  getRecentStatus,
  getWeeklyStatus,
  getLatestStatus,
  cleanupOldLogs,
  getUptimeStats
};
