const express = require('express');
const statusDb = require('./database.status');
const fetch = global.fetch || require('node-fetch');
const https = require('https');
const { SocksProxyAgent } = require('socks-proxy-agent');
const http = require('http');
const net = require('net');

const app = express();
app.disable('x-powered-by');
app.disable('etag');

const TOR_SOCKS = 'socks5h://127.0.0.1:9050';
const torAgent = new SocksProxyAgent(TOR_SOCKS);
const TOR_TIMEOUT = 30000;

const I2P_PROXY = '10.0.0.1';
const I2P_PROXY_PORT = 8080;
const I2P_TIMEOUT = 30000;
const ONION_ADDRESS = process.env.ONION_ADDRESS;
const ONION_TIMEOUT = 30000;

const TOR_CONTROL_HOST = process.env.TOR_CONTROL_HOST || '10.0.0.1';
const TOR_CONTROL_PORT = parseInt(process.env.TOR_CONTROL_PORT || '29051');
const TOR_CONTROL_PASS = process.env.TOR_CONTROL_PASS;
const TOR_CONTROL_TIMEOUT = 45000;
const TOR_FINGERPRINT = process.env.TOR_FINGERPRINT || '';

const PORT = parseInt(process.env.STATUS_PORT || '4444');
const PROXY_PORT = '8888';
const PING_INTERVAL = 60000;
const SITE_PING = 300000;
const REQUEST_TIMEOUT = 45000;
const DOWN_THRESHOLD = 5;

let torUp = false;
let i2pUp = true;
let onionUp = true;
let torNodeInfo = { up: true };


app.get('/', (req, res) => {
  const latest = statusDb.getLatestStatus();
  const stats = statusDb.getUptimeStats();
  res.json({ current: latest, stats, tor_status: torUp ? 'up' : 'down', i2p_status: i2pUp ? 'up' : 'down', onion_status: onionUp ? 'up' : 'down', tor_node: torNodeInfo });
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

async function checkI2P() {
  return new Promise((resolve) => {
    const req = http.request({
      host: I2P_PROXY,
      port: I2P_PROXY_PORT,
      method: 'GET',
      path: 'http://zzz.i2p/',
      timeout: I2P_TIMEOUT
    }, (res) => {
      resolve(res.statusCode >= 200 && res.statusCode < 500);
    });
    req.on('error', (e) => { console.error('[i2p] error:', e.message); resolve(false); });
    req.on('timeout', () => { console.error('[i2p] timeout'); req.destroy(); resolve(false); });
    req.end();
  });
}

async function checkOnion() {
  if (!ONION_ADDRESS) return false;
  return new Promise((resolve) => {
    const req = http.request({
      hostname: ONION_ADDRESS,
      path: '/home',
      method: 'GET',
      agent: torAgent,
      timeout: ONION_TIMEOUT
    }, (res) => {
      resolve(res.statusCode >= 200 && res.statusCode < 500);
    });
    req.on('error', (e) => { console.error('[onion] error:', e.message); resolve(false); });
    req.on('timeout', () => { console.error('[onion] timeout'); req.destroy(); resolve(false); });
    req.end();
  });
}

function torControlCommand(cmds) {
  return new Promise((resolve, reject) => {
    let data = '';
    const socket = net.createConnection({ host: TOR_CONTROL_HOST, port: TOR_CONTROL_PORT }, () => {
      let payload = 'AUTHENTICATE "' + TOR_CONTROL_PASS + '"\r\n';
      for (const cmd of cmds) {
        payload += cmd + '\r\n';
      }
      socket.write(payload);
    });
    socket.on('data', (chunk) => {
      data += chunk.toString();
      const lines = data.split('\r\n');
      const okCount = lines.filter(l => l === '250 OK' || l.startsWith('250 ')).length;
      if (okCount >= cmds.length) {
        socket.destroy();
        resolve(data);
      }
    });
    socket.on('error', (e) => reject(e));
    socket.setTimeout(TOR_CONTROL_TIMEOUT, () => { socket.destroy(); reject(new Error('timeout')); });
  });
}

async function checkTorNode() {
  if (!TOR_CONTROL_PASS || !TOR_FINGERPRINT) return { up: false };
  try {
    const raw = await torControlCommand([
      'GETINFO fingerprint',
      'GETINFO traffic/read',
      'GETINFO traffic/written',
      'GETINFO ns/id/' + TOR_FINGERPRINT
    ]);
    console.log('[tor-node] raw:', raw);

    const readMatch = raw.match(/traffic\/read=(\d+)/);
    const writtenMatch = raw.match(/traffic\/written=(\d+)/);
    const totalBytes = (parseInt(readMatch ? readMatch[1] : '0') || 0) + (parseInt(writtenMatch ? writtenMatch[1] : '0') || 0);

    const flagsMatch = raw.match(/s\s+(.*)/);
    const flags = flagsMatch ? flagsMatch[1].trim().split(/\s+/) : [];

    return { up: flags.includes('Running'), total_bytes: totalBytes, flags };
  } catch (e) {
    console.error('[tor-node] error:', e.message);
    return { up: false };
  }
}

async function checkSites() {
  try {
    i2pUp = await checkI2P();
    torNodeInfo = await checkTorNode();
    if (torUp) {
      onionUp = await checkOnion();
    }
  } catch (e) {
    console.error('[status]', new Date().toISOString(), 'ERROR:', e);
  }
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
  checkSites();
  setInterval(checkAndLog, PING_INTERVAL);
  setInterval(checkSites, SITE_PING);
  setInterval(() => {
    const cleaned = statusDb.cleanupOldLogs();
    if (cleaned > 0) console.log('cleaned up', cleaned, 'old status logs');
  }, 24 * 60 * 60 * 1000);
});
