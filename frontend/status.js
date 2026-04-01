const express = require('express');
const { SocksClient } = require('socks');
const statusDb = require('./database.status');
const http = require('http');

const app = express();
const PORT = 4444;
const ONION_ADDRESS = process.env.ONION_ADDRESS || '127.0.0.1';
const ONION_PORT = parseInt(process.env.ONION_PORT || '3000');
const SOCKS_PROXY = process.env.SOCKS_PROXY || '127.0.0.1:9050';
const PING_INTERVAL = 60000;
const REQUEST_TIMEOUT = 10000;

app.get('/', (req, res) => {
  const latest = statusDb.getLatestStatus();
  const weekly = statusDb.getWeeklyStatus();
  const stats = statusDb.getUptimeStats();
  res.json({ current: latest, weekly, stats });
});

async function pingBackend() {
  const [socksHost, socksPort] = SOCKS_PROXY.split(':');
  
  try {
    const socket = await SocksClient.createConnection({
      proxy: { host: socksHost, port: parseInt(socksPort), type: 5 },
      destination: { host: ONION_ADDRESS, port: ONION_PORT },
      timeout: REQUEST_TIMEOUT
    });

    return new Promise((resolve) => {
      let responseData = '';
      const timer = setTimeout(() => {
        socket.socket.destroy();
        resolve({ up: false, database: 'down', xmr_wallet: 'down', ltc_wallet: 'down', capacity: 'down', uptime: 0 });
      }, REQUEST_TIMEOUT);

      const request = `GET /keykeeper/status HTTP/1.1\r\nHost: ${ONION_ADDRESS}\r\nConnection: close\r\n\r\n`;
      socket.socket.write(request);

      socket.socket.on('data', (data) => {
        responseData += data.toString();
      });

      socket.socket.on('end', () => {
        clearTimeout(timer);
        try {
          const bodyStart = responseData.indexOf('\r\n\r\n');
          if (bodyStart === -1) {
            resolve({ up: false, database: 'down', xmr_wallet: 'down', ltc_wallet: 'down', capacity: 'down', uptime: 0 });
            return;
          }
          const body = responseData.substring(bodyStart + 4);
          const parsed = JSON.parse(body);
          resolve({
            up: parsed.up || false,
            database: parsed.database || 'down',
            xmr_wallet: parsed.xmr_wallet || 'down',
            ltc_wallet: parsed.ltc_wallet || 'down',
            capacity: parsed.capacity || 'down',
            uptime: parsed.uptime || 0
          });
        } catch (e) {
          resolve({ up: false, database: 'down', xmr_wallet: 'down', ltc_wallet: 'down', capacity: 'down', uptime: 0 });
        }
      });

      socket.socket.on('error', () => {
        clearTimeout(timer);
        resolve({ up: false, database: 'down', xmr_wallet: 'down', ltc_wallet: 'down', capacity: 'down', uptime: 0 });
      });
    });
  } catch (e) {
    return { up: false, database: 'down', xmr_wallet: 'down', ltc_wallet: 'down', capacity: 'down', uptime: 0 };
  }
}

async function pingBackendLocal() {
  try {
    return new Promise((resolve) => {
      const options = {
        host: ONION_ADDRESS,
        port: ONION_PORT,
        path: '/keykeeper/status',
        timeout: REQUEST_TIMEOUT
      };
      const req = http.get(options, (res) => {
        let data = '';
        res.on('data', (chunk) => data += chunk);
        res.on('end', () => {
          try {
            const parsed = JSON.parse(data);
            resolve({
              up: parsed.up || false,
              database: parsed.database || 'down',
              xmr_wallet: parsed.xmr_wallet || 'down',
              ltc_wallet: parsed.ltc_wallet || 'down',
              capacity: parsed.capacity || 'down',
              uptime: parsed.uptime || 0
            });
          } catch (e) {
            resolve({ up: false, database: 'down', xmr_wallet: 'down', ltc_wallet: 'down', capacity: 'down', uptime: 0 });
          }
        });
      });
      req.on('error', () => {
        resolve({ up: false, database: 'down', xmr_wallet: 'down', ltc_wallet: 'down', capacity: 'down', uptime: 0 });
      });
      req.on('timeout', () => {
        req.destroy();
        resolve({ up: false, database: 'down', xmr_wallet: 'down', ltc_wallet: 'down', capacity: 'down', uptime: 0 });
      });
    });
  } catch (e) {
    return { up: false, database: 'down', xmr_wallet: 'down', ltc_wallet: 'down', capacity: 'down', uptime: 0 };
  }
}

async function checkAndLog() {
  const status = await pingBackendLocal();
  statusDb.logStatus(status);
  console.log('[status]', new Date().toISOString(), status.up ? 'UP' : 'DOWN');
}

if (!ONION_ADDRESS) {
  console.error('ONION_ADDRESS env var required');
  process.exit(1);
}

app.listen(PORT, () => {
  console.log('Status monitor running on port', PORT);
  checkAndLog();
  setInterval(checkAndLog, PING_INTERVAL);
  setInterval(() => {
    const cleaned = statusDb.cleanupOldLogs();
    if (cleaned > 0) console.log('Cleaned up', cleaned, 'old status logs');
  }, 24 * 60 * 60 * 1000);
});