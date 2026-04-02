const express = require('express');
const statusDb = require('./database.status');
const fetch = global.fetch || require('node-fetch');

const app = express();
const PORT = parseInt(process.env.STATUS_PORT || '4444');
const PROXY_PORT = '8888';
const PING_INTERVAL = 60000;
const REQUEST_TIMEOUT = 30000;

app.get('/', (req, res) => {
  const latest = statusDb.getLatestStatus();
  const weekly = statusDb.getWeeklyStatus();
  const stats = statusDb.getUptimeStats();
  res.json({ current: latest, weekly, stats });
});

async function pingBackend() {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT);

    const response = await fetch('http://127.0.0.1:' + PROXY_PORT + '/keykeeper/status', {
      signal: controller.signal
    });
    clearTimeout(timer);

    const parsed = await response.json();
    return {
      up: parsed.up || false,
      database: parsed.database || 'down',
      xmr_wallet: parsed.xmr_wallet || 'down',
      ltc_wallet: parsed.ltc_wallet || 'down',
      capacity: parsed.capacity || 'down',
      uptime: parsed.uptime || 0
    };
  } catch (e) {
    console.error('error:', e);
    return { up: false, database: 'down', xmr_wallet: 'down', ltc_wallet: 'down', capacity: 'down', uptime: 0 };
  }
}

async function checkAndLog() {
  const status = await pingBackend();
  statusDb.logStatus(status);
  console.log('[status]', new Date().toISOString(), status.up ? 'UP' : 'DOWN');
}

app.listen(PORT, '127.0.0.1', () => {
  console.log('Status monitor running on 127.0.0.1:' + PORT);
  checkAndLog();
  setInterval(checkAndLog, PING_INTERVAL);
  setInterval(() => {
    const cleaned = statusDb.cleanupOldLogs();
    if (cleaned > 0) console.log('Cleaned up', cleaned, 'old status logs');
  }, 24 * 60 * 60 * 1000);
});
