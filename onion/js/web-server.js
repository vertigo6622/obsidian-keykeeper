const express = require('express');
const expressLayouts = require('express-ejs-layouts');
const session = require('express-session');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const morgan = require('morgan');
const rfs = require('rotating-file-stream');

const authRoutes = require('../routes/auth');
const txRoutes = require('../routes/transactions');
const userRoutes = require('../routes/user');
const pageRoutes = require('../routes/pages');
const licenseRoutes = require('../routes/license');

const auth = require('./auth');
const tx = require('./transactions');
const pgp = require('./pgp');
const wallet = require('./wallet');

const logDir = path.join(__dirname, '..', 'data', 'logs');
fs.mkdirSync(logDir, { recursive: true });

const accessLogStream = rfs.createStream('access.log', {
  path: logDir,
  size: '10M',
  interval: '1d',
  compress: 'gzip'
});

const errorLogStream = rfs.createStream('error.log', {
  path: logDir,
  size: '10M',
  interval: '1d',
  compress: 'gzip'
});

const app = express();

app.disable('x-powered-by');

const rateLimit = require('express-rate-limit');

const limiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 500,
  standardHeaders: false, 
  legacyHeaders: false,
});

app.use(limiter); 

const morganFormat = ':remote-addr - :remote-user [:date[clf]] ":method :url HTTP/:http-version" :status :res[content-length] ":referrer" ":user-agent"';

app.use(morgan(morganFormat, { stream: accessLogStream }));
app.use(morgan(morganFormat));

const PORT = process.env.WEB_PORT || 3001;

app.use(express.urlencoded({ limit: '10kb', extended: true }));
app.use(express.json({ limit: '10kb' }));

const SESSION_SECRET = crypto.randomBytes(32).toString('hex');

app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false,
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000,
    sameSite: 'strict'
  }
}));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '..', 'templates'));
app.use(expressLayouts);

app.use(express.static(path.join(__dirname, 'public')));

app.use((req, res, next) => {
  if (req.method === 'OPTIONS' || req.method === 'CONNECT') {
    return res.sendStatus(403);
  }
  next();
});

app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'SAMEORIGIN'); 
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader("Content-Security-Policy", 
    "default-src 'self'; " +
    "script-src 'none'; " + 
    "style-src 'self' 'unsafe-inline'; " +
    "img-src 'self' data:; " +
    "object-src 'none'; " +
    "base-uri 'self';"
  );
  next();
});

app.use((req, res, next) => {
  res.locals.user = null;
  res.locals.path = req.path;
  if (req.session && req.session.userId) {
    const user = auth.getUserById(req.session.userId);
    if (user) {
      res.locals.user = user;
    } else {
      req.session.destroy();
    }
  }
  next();
});

app.use('/', authRoutes);
app.use('/', txRoutes);
app.use('/', userRoutes);
app.use('/', pageRoutes);
app.use('/', licenseRoutes);

app.use((req, res) => {
  res.status(404).render('error', { title: 'not found', message: 'page not found' });
});

app.use((err, req, res, next) => {
  const ts = new Date().toISOString();
  const line = `${ts} ${err.status || 500} ${req.method} ${req.url} ${err.message}\n${err.stack}\n`;
  errorLogStream.write(line);
  console.error(line);
  res.status(err.status || 500).render('error', { title: 'error', message: 'internal server error' });
});

process.on('uncaughtException', (err) => {
  const ts = new Date().toISOString();
  const line = `${ts} UNCAUGHT ${err.message}\n${err.stack}\n`;
  errorLogStream.write(line);
  console.error(line);
});

process.on('unhandledRejection', (reason) => {
  const ts = new Date().toISOString();
  const line = `${ts} UNHANDLED REJECTION ${reason}\n`;
  errorLogStream.write(line);
  console.error(line);
});

app.listen(PORT, '127.0.0.1', () => {
  console.log('[tor-web] obsidian tor hidden service running on port ' + PORT);
  pgp.loadPrivateKey();
});

module.exports = app;
