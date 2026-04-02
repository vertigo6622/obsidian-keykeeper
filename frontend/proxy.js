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
const STATUS_PORT = parseInt(process.env.STATUS_PORT || '4444');

if (!ONION_ADDRESS) {
  console.error('ONION_ADDRESS env var required');
  process.exit(1);
}

if (!ONION_ADDRESS.endsWith('.onion')) {
  console.error('ONION_ADDRESS must end with .onion');
  process.exit(1);
}

const ALLOWED_ORIGINS = [
  'http://localhost',
  'http://localhost:3000',
  'http://localhost:8080',
  'http://localhost:8000',
  'http://127.0.0.1',
  'http://127.0.0.1:3000',
  'http://127.0.0.1:8080',
  'http://127.0.0.1:8000',
  'http://127.0.0.1:' + PORT,
  'https://obsidian.st',
  'https://verify.obsidian.st'
];

function isOriginAllowed(headers) {
  const referer = headers.referer || '';
  const origin = headers.origin || '';
  const host = headers.host || '';

  const checkUrl = (url) => {
    return ALLOWED_ORIGINS.some(allowed =>
      url.startsWith(allowed) || url === allowed
    );
  };

  return checkUrl(referer) || checkUrl(origin) || checkUrl('http://' + host);
}

const BLOCKED_BOTS = [
  'bot', 'crawler', 'spider', 'googlebot', 'bingbot',
  'slurp', 'duckduckbot', 'yandex', 'baidu', 'sogou',
  'facebookexternalhit', 'twitterbot', 'applebot', 'semrush',
  'ahrefs', 'mj12bot', 'dotbot', 'rogerbot', 'screaming frog'
];

const RATE_LIMIT_WINDOW = 60 * 60 * 1000;
const RATE_LIMIT_MAX = 100;

const rateLimitMap = new Map();

setInterval(() => {
  const cutoff = Date.now() - RATE_LIMIT_WINDOW;
  for (const [key, val] of rateLimitMap) {
    if (val.windowStart < cutoff) rateLimitMap.delete(key);
  }
}, RATE_LIMIT_WINDOW);

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
  console.error('[PROXY ERROR]', req.method, req.url, err.code || '', err.message);
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
  console.error('[PROXY ERROR]', req.method, req.url, err.code || '', err.message);
  if (res && !res.headersSent) {
    res.writeHead(502, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Bad Gateway' }));
  }
});

app.use((req, res, next) => {
  if (!isOriginAllowed(req.headers)) {
    console.log('Blocked request from:', req.headers.origin, req.headers.referer, req.ip);
    return res.status(403).json({ error: 'Forbidden' });
  }

  const ua = (req.headers['user-agent'] || '').toLowerCase();
  const isBot = BLOCKED_BOTS.some(bot => ua.includes(bot));
  if (isBot) {
    return res.status(403).send();
  }

  next();
});

app.use('/keykeeper', (req, res) => {
  const apiKey = req.headers['x-api-key'];
  if (apiKey) {
    const now = Date.now();
    const windowStart = now - RATE_LIMIT_WINDOW;
    let record = rateLimitMap.get(apiKey);
    if (!record || record.windowStart < windowStart) {
      record = { windowStart: now, count: 0 };
    }
    record.count++;
    rateLimitMap.set(apiKey, record);
    if (record.count > RATE_LIMIT_MAX) {
      return res.status(429).send();
    }
  }

  kkproxy.web(req, res);
});

app.use('/socket.io', (req, res) => {
  socketio_proxy.web(req, res);
});

app.use((req, res) => res.status(404).send());

const server = http.createServer(app);

server.on('upgrade', (req, socket, head) => {
  if (req.url.startsWith('/socket.io/')) {
    if (!isOriginAllowed(req.headers)) {
      console.log('Blocked WS upgrade from:', req.headers.origin);
      socket.end();
      return;
    }
    socketio_proxy.ws(req, socket, head);
  } else {
    socket.end();
  }
});

server.listen(PORT, '127.0.0.1', () => {
  console.log('Proxy running on 127.0.0.1:' + PORT);
  console.log('Forwarding /socket.io/* and /keykeeper/* to ' + ONION_ADDRESS + ':' + ONION_PORT + ' via SOCKS ' + SOCKS_PROXY);
});
