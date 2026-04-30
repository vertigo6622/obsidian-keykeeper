const express = require('express');
const http = require('http');
const httpProxy = require('http-proxy');
const { SocksProxyAgent } = require('socks-proxy-agent');

const app = express();

app.disable('x-powered-by');
app.disable('etag');

const ONION_ADDRESS = process.env.ONION_ADDRESS;
const ONION_PORT = parseInt(process.env.ONION_PORT || '3000');
const SOCKS_PROXY = process.env.SOCKS_PROXY || '127.0.0.1:9050';
const PORT = parseInt(process.env.PROXY_PORT || '8888');

if (!ONION_ADDRESS) {
  console.error('ONION_ADDRESS env var required');
  process.exit(1);
}

if (!ONION_ADDRESS.endsWith('.onion')) {
  console.error('ONION_ADDRESS must end with .onion');
  process.exit(1);
}

const RATE_LIMIT_WINDOW = 60 * 60 * 1000;
const RATE_LIMIT_MAX = 1000;
const MAX_CONCURRENT = 5;
const MAX_BODY_BYTES = 1024 * 1024;

const rateLimitMap = new Map();
const concurrentMap = new Map();

setInterval(() => {
  const cutoff = Date.now() - RATE_LIMIT_WINDOW;
  for (const [key, val] of rateLimitMap) {
    if (val.windowStart < cutoff) rateLimitMap.delete(key);
  }
  for (const [key, val] of concurrentMap) {
    if (Date.now() - val.lastSeen > 300000) concurrentMap.delete(key);
  }
}, 60000);

function getClientIp(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim();
}

function checkRateLimit(ip) {
  const now = Date.now();
  let entry = rateLimitMap.get(ip);

  if (!entry || now - entry.windowStart >= RATE_LIMIT_WINDOW) {
    entry = { windowStart: now, count: 0 };
    rateLimitMap.set(ip, entry);
  }

  entry.count++;
  const remaining = Math.max(0, RATE_LIMIT_MAX - entry.count);
  const retryAfter = entry.count > RATE_LIMIT_MAX
    ? Math.ceil((RATE_LIMIT_WINDOW - (now - entry.windowStart)) / 1000)
    : 0;

  return { allowed: entry.count <= RATE_LIMIT_MAX, remaining, retryAfter };
}

function trackConcurrent(ip) {
  if (!concurrentMap.has(ip)) concurrentMap.set(ip, { count: 0, lastSeen: Date.now() });
  const entry = concurrentMap.get(ip);
  entry.count++;
  entry.lastSeen = Date.now();
  return entry.count;
}

function releaseConcurrent(ip) {
  const entry = concurrentMap.get(ip);
  if (entry) entry.count = Math.max(0, entry.count - 1);
}

const socksAgent = new SocksProxyAgent('socks5h://' + SOCKS_PROXY);

const socketio_proxy = httpProxy.createProxyServer({
  target: 'http://' + ONION_ADDRESS + ':' + ONION_PORT + '/socket.io/',
  agent: socksAgent,
  ws: true,
  proxyTimeout: 60000,
  timeout: 60000,
  changeOrigin: true,
  followRedirects: false
});

socketio_proxy.on('error', (err, req, res) => {
  console.error('[proxy] error:', req.method, req.url, err.code || '', err.message);
  if (res && !res.headersSent) {
    res.writeHead(502, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Bad Gateway' }));
  }
});

const kkproxy = httpProxy.createProxyServer({
  target: 'http://' + ONION_ADDRESS + ':' + ONION_PORT + '/keykeeper/',
  agent: socksAgent,
  ws: true,
  proxyTimeout: 60000,
  timeout: 60000,
  changeOrigin: true,
  followRedirects: false
});

kkproxy.on('error', (err, req, res) => {
  console.error('[proxy] error:', req.method, req.url, err.code || '', err.message);
  if (res && !res.headersSent) {
    res.writeHead(502, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Bad Gateway' }));
  }
});

app.use((req, res, next) => {
  const ip = getClientIp(req);
  const contentLength = parseInt(req.headers['content-length'] || '0');

  if (contentLength > MAX_BODY_BYTES) {
    return res.status(413).json({ error: 'Payload Too Large' });
  }

  const concurrent = concurrentMap.get(ip);
  if (concurrent && concurrent.count >= MAX_CONCURRENT) {
    return res.status(429).json({ error: 'Too Many Concurrent Connections' });
  }

  const rate = checkRateLimit(ip);
  if (!rate.allowed) {
    res.set('Retry-After', rate.retryAfter);
    return res.status(429).json({ error: 'Too Many Requests', retryAfter: rate.retryAfter });
  }

  res.set('X-RateLimit-Remaining', rate.remaining);
  trackConcurrent(ip);
  res.on('finish', () => releaseConcurrent(ip));
  next();
});

const requestHistory = new Array(1440).fill(0);

setInterval(() => {
  const total24h = requestHistory.reduce((sum, count) => sum + count, 0);
  console.log(`[proxy] stats: forwarded ${total24h} requests in the last 24 hours.`);
  requestHistory.shift();
  requestHistory.push(0);
}, 300000);

app.use('/keykeeper', (req, res) => {
  requestHistory[requestHistory.length - 1]++; 
  kkproxy.web(req, res);
});

app.use('/socket.io', (req, res) => {
  requestHistory[requestHistory.length - 1]++; 
  socketio_proxy.web(req, res);
});

app.use((req, res) => res.status(404).send());

const server = http.createServer(app);

server.on('upgrade', (req, socket, head) => {
  if (req.url.startsWith('/socket.io/')) {
    const ip = req.socket.remoteAddress;
    const concurrent = concurrentMap.get(ip);
    if (concurrent && concurrent.count >= MAX_CONCURRENT) {
      socket.end();
      return;
    }
    trackConcurrent(ip);
    socket.on('close', () => releaseConcurrent(ip));
    socketio_proxy.ws(req, socket, head);
  } else {
    socket.end();
  }
});

server.listen(PORT, '127.0.0.1', () => {
  console.log('[proxy] proxy running on 127.0.0.1:' + PORT);
  console.log('[proxy] forwarding to keykeeper on port:' + ONION_PORT + ' via SOCKS ' + SOCKS_PROXY);
});
