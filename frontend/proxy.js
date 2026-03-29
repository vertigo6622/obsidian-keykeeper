const express = require('express');
const http = require('http');
const { SocksClient } = require('socks');

const db = require('./database');

const app = express();

app.disable('x-powered-by');
app.disable('etag');

const ALLOWED_ORIGINS = [
  'http://localhost',
  'http://localhost:3000',
  'http://localhost:8080',
  'http://127.0.0.1',
  'http://127.0.0.1:3000',
  'http://127.0.0.1:8080',
  'https://obsidian.st',
  'http://obsidian.st'
];

function isOriginAllowed(req) {
  const referer = req.headers.referer || '';
  const origin = req.headers.origin || '';
  const host = req.headers.host || '';
  
  const checkUrl = (url) => {
    return ALLOWED_ORIGINS.some(allowed => 
      url.startsWith(allowed) || url === allowed
    );
  };
  
  return checkUrl(referer) || checkUrl(origin) || checkUrl('http://' + host);
}

const originValidator = (req, res, next) => {
  if (req.path.startsWith('/api')) {
    if (!isOriginAllowed(req)) {
      console.log('Blocked request from:', req.headers.origin, req.headers.referer, req.ip);
      return res.status(403).json({ error: 'Forbidden' });
    }
  }
  next();
};

app.use(originValidator);
const ONION_PORT = process.env.ONION_PORT || 3000;
const SOCKS_PROXY = process.env.SOCKS_PROXY || '127.0.0.1:9050';
const PORT = process.env.PORT || 8080;

if (!ONION_ADDRESS) {
  console.error('ONION_ADDRESS env var required');
  process.exit(1);
}

if (!ONION_ADDRESS.endsWith('.onion')) {
  console.error('ONION_ADDRESS must end with .onion');
  process.exit(1);
}

const RATE_LIMIT_WINDOW = 60 * 60 * 1000;
const RATE_LIMIT_MAX = 100;
const REQUEST_TIMEOUT = 20 * 1000;
const MAX_RESPONSE_SIZE = 5 * 1024 * 1024;

const BLOCKED_BOTS = [
  'bot', 'crawler', 'spider', 'googlebot', 'bingbot', 
  'slurp', 'duckduckbot', 'yandex', 'baidu', 'sogou',
  'facebookexternalhit', 'twitterbot', 'applebot', 'semrush',
  'ahrefs', 'mj12bot', 'dotbot', 'rogerbot', 'screaming frog'
];

function sanitizePath(path) {
  let decoded = path;
  for (let i = 0; i < 5; i++) {
    try {
      const prev = decoded;
      decoded = decodeURIComponent(decoded);
      if (decoded === prev) break;
    } catch (e) {
      return null;
    }
  }
  return decoded
    .replace(/[\r\n]/g, '')
    .replace(/[\x00-\x1f]/g, '');
}

const crawlerBlocker = (req, res, next) => {
  const ua = (req.headers['user-agent'] || '').toLowerCase();
  
  if (!ua) {
    return res.status(403).send();
  }
  
  const isBot = BLOCKED_BOTS.some(bot => ua.includes(bot));
  if (isBot) {
    return res.status(403).send();
  }
  
  next();
};

const rateLimitMap = new Map();

setInterval(() => {
  const cutoff = Date.now() - RATE_LIMIT_WINDOW;
  for (const [key, val] of rateLimitMap) {
    if (val.windowStart < cutoff) rateLimitMap.delete(key);
  }
}, RATE_LIMIT_WINDOW);

const rateLimiter = (req, res, next) => {
  const key = req.headers['x-api-key'] || req.ip;
  const now = Date.now();
  const windowStart = now - RATE_LIMIT_WINDOW;
  
  let record = rateLimitMap.get(key);
  if (!record || record.windowStart < windowStart) {
    record = { windowStart: now, count: 0 };
  }
  
  record.count++;
  rateLimitMap.set(key, record);
  
  if (record.count > RATE_LIMIT_MAX) {
    return res.status(429).send();
  }
  
  next();
};

const apiKeyAuth = (req, res, next) => {
  const providedKey = req.headers['x-api-key'];
  if (!providedKey) {
    return res.status(401).send();
  }
  
  const keyRecord = db.prepare(`
    SELECT id, user_id, active FROM api_keys 
    WHERE key = ? AND active = 1
  `).get(providedKey);
  
  if (!keyRecord) {
    return res.status(401).send();
  }
  
  db.prepare(`
    UPDATE api_keys SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?
  `).run(keyRecord.id);
  
  req.apiKeyId = keyRecord.id;
  req.apiUserId = keyRecord.user_id;
  
  next();
};

const apiRouter = express.Router();

apiRouter.use(rateLimiter);
apiRouter.use(express.json({ limit: '50kb' }));
apiRouter.use(crawlerBlocker);
apiRouter.use(apiKeyAuth);
apiRouter.all('*', proxyRequest);

app.use('/api', apiRouter);

app.use((req, res) => res.status(404).send());

function withTimeout(promise, ms, res) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error('Request timeout'));
    }, ms);
    
    promise
      .then((result) => {
        clearTimeout(timer);
        resolve(result);
      })
      .catch((err) => {
        clearTimeout(timer);
        reject(err);
      });
  });
}

async function proxyRequest(req, res) {
  const path = sanitizePath(req.originalUrl);
  if (!path) {
    return res.status(400).send();
  }
  if (!path.startsWith('/api/')) {
    return res.status(403).send();
  }

  let body;
  try {
    body = JSON.stringify(req.body);
  } catch (e) {
    return res.status(400).send();
  }

  const [socksHost, socksPort] = SOCKS_PROXY.split(':');
  const safeHost = ONION_ADDRESS.replace(/[^\w.-]/g, '');

  try {
    const socket = await withTimeout(
      SocksClient.createConnection({
        proxy: {
          host: socksHost,
          port: parseInt(socksPort),
          type: 5
        },
        destination: {
          host: ONION_ADDRESS,
          port: parseInt(ONION_PORT)
        }
      }),
      REQUEST_TIMEOUT,
      res
    );
    
    let responseData = '';
    let timedOut = false;
    let responseSizeExceeded = false;
    
    const timeoutTimer = setTimeout(() => {
      timedOut = true;
      socket.socket.end();
      res.status(408).send();
    }, REQUEST_TIMEOUT);
    
    socket.socket.on('data', (data) => {
      if (responseData.length + data.length > MAX_RESPONSE_SIZE) {
        responseSizeExceeded = true;
        socket.socket.end();
        res.status(502).send();
        return;
      }
      responseData += data.toString();
    });
    
    socket.socket.on('end', () => {
      clearTimeout(timeoutTimer);
      if (timedOut || responseSizeExceeded) return;
      try {
        const parsed = JSON.parse(responseData);
        res.json(parsed);
      } catch (e) {
        res.send(responseData);
      }
      socket.socket.end();
    });
    
    const requestLine = `${req.method} ${path} HTTP/1.1\r\n`;
    const headers = [
      `Host: ${safeHost}`,
      'Content-Type: application/json',
      `Content-Length: ${body.length}`,
      'Connection: close',
      '',
      '',
      body
    ].join('\r\n');
    
    socket.socket.write(requestLine + headers);
    socket.socket.on('error', (err) => {
      clearTimeout(timeoutTimer);
      console.error('Socket error:', err);
      res.status(500).send();
    });
    
  } catch (error) {
    console.error('Proxy error:', error);
    if (error.message === 'Request timeout') {
      return res.status(408).send();
    }
    res.status(500).send();
  }
}

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Clearnet proxy running on port ${PORT}`);
  console.log(`Forwarding /api/* to ${ONION_ADDRESS}:${ONION_PORT} via SOCKS ${SOCKS_PROXY}`);
});
