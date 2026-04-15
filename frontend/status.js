const express = require('express');
const statusDb = require('./database.status');
const fetch = global.fetch || require('node-fetch');
const https = require('https');
const { SocksProxyAgent } = require('socks-proxy-agent');
const helmet = require('helmet');

const app = express();
app.disable('x-powered-by');
app.disable('etag');
app.use(helmet());

const TOR_SOCKS = 'socks5h://127.0.0.1:9050';
const torAgent = new SocksProxyAgent(TOR_SOCKS);
const TOR_TIMEOUT = 30000;

const PORT = parseInt(process.env.STATUS_PORT || '4444');
const PROXY_PORT = '8888';
const PING_INTERVAL = 60000;
const REQUEST_TIMEOUT = 45000;
const DOWN_THRESHOLD = 5;

let torUp = false;

app.get('/', (req, res) => {
  const latest = statusDb.getLatestStatus();
  const weekly = statusDb.getWeeklyStatus();
  const stats = statusDb.getUptimeStats();
  res.json({ current: latest, weekly, stats, tor_status: torUp ? 'up' : 'down' });
});

async function checkTor() {
  return new Promise((resolve) => {
    const req = https.request({
      hostname: 'check.torproject.org',
      path: '/api/ip',
      method: 'GET',
      agent: torAgent,
      timeout: TOR_TIMEOUT
    }, (res) => {
      let body = '';
      res.on('data', (chunk) => body += chunk);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(body);
          resolve(parsed.IsTor === true);
        } catch (e) {
          resolve(false);
        }
      });
    });
    req.on('error', () => resolve(false));
    req.on('timeout', () => { req.destroy(); resolve(false); });
    req.end();
  });
}

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

let consecutiveDowns = 0;

async function checkAndLog() {
  torUp = await checkTor();
  if (!torUp) {
    console.log('[status]', new Date().toISOString(), 'TOR DOWN');
    return;
  }
  const status = await pingBackend();
  if (status.up) {
    consecutiveDowns = 0;
    statusDb.logStatus(status);
    console.log('[status]', new Date().toISOString(), 'UP');
  } else {
    consecutiveDowns++;
    if (consecutiveDowns >= DOWN_THRESHOLD) {
      statusDb.logStatus(status);
      console.log('[status]', new Date().toISOString(), 'DOWN');
      consecutiveDowns = 0;
    } else {
      console.log('[status]', new Date().toISOString(), 'DOWN');
    }
  }
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
