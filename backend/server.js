const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const session = require('express-session');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const Database = require('better-sqlite3');


const auth = require('./auth');
const tx = require('./transactions');
const validate = require('./validate');
const wallet = require('./wallet');
const packer = require('./packer-bridge');
const pgp = require('./pgp')
const helmet = require('helmet');

const app = express();
const server = http.createServer(app);

const MIN_ACCOUNT_AGE_HOURS = 24;
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || 'http://localhost:8000,http://127.0.0.1:8000,https://obsidian.st,https://status.obsidian.st').split(',');

const io = new Server(server, {
  cors: {
    origin: ALLOWED_ORIGINS,
    methods: ["GET", "POST"],
    credentials: true
  },
  maxHttpBufferSize: 1024 * 1024
});

const IDLE_TIMEOUT_MS = 15 * 60 * 1000;

tx.setSocketIO(io);

const PORT = process.env.PORT || 3000;
const SESSION_SECRET = require('crypto').randomBytes(32).toString('hex');

app.use(express.json());

const isDev = process.env.NODE_ENV !== 'production';

const cspDirectives = {
  defaultSrc: ["'self'"],
  styleSrc: ["'self'", "'unsafe-inline'"],
  scriptSrc: ["'self'"],
  imgSrc: ["'self'", "data:"],
  connectSrc: ["'self'", "ws:", "wss:"],
  fontSrc: ["'self'"],
  objectSrc: ["'none'"],
  mediaSrc: ["'self'"],
  frameSrc: ["'none'"],
  baseUri: ["'self'"],
  formAction: ["'self'"]
};

if (!isDev) {
  cspDirectives.upgradeInsecureRequests = [];
}

app.use(helmet.contentSecurityPolicy({
  directives: cspDirectives
}));

if (!isDev) {
  app.use(helmet.hsts({
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }));
}

const sessionMiddleware = session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true,
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000,
    sameSite: 'strict'
  }
});

app.use(sessionMiddleware);

io.use((socket, next) => {
  console.log('Socket.io session middleware - socket id:', socket.id);
  sessionMiddleware(socket.request, socket.request.res || {}, (err) => {
    if (err) {
      console.error('Session middleware error:', err);
    } else {
      console.log('Session middleware OK - sessionID:', socket.request.sessionID);
    }
    next(err);
  });
});

app.get('/', (req, res) => {
  res.json({ status: 'ok', service: 'obsidian-keykeeper' });
});

app.get('/keykeeper/status', async (req, res) => {
  try {
    let dbStatus = 'ok';
    let xmrStatus = 'ok';
    try {
      await wallet.moneroRPC('get_version');
    } catch (e) {
      xmrStatus = 'down';
    }
    
    let ltcStatus = 'ok';
    try {
      await wallet.electrumRPC('getbalance', {});
    } catch (e) {
      console.log('Error', e);
      ltcStatus = 'down';
    }
    
    const cpus = require('os').cpus();
    const load = require('os').loadavg()[0] / cpus.length;
    
    res.json({
      up: true,
      uptime: Math.floor(process.uptime()),
      database: dbStatus,
      xmr_wallet: xmrStatus,
      ltc_wallet: ltcStatus,
      capacity: load < 0.5 ? 'normal' : 'strained'
    });
  } catch (error) {
    res.json({ up: false, uptime: 0, database: 'down', xmr_wallet: 'down', ltc_wallet: 'down', capacity: 'down' });
  }
});

app.post('/keykeeper/product/verify', async (req, res) => {
  try {
    const { license, sum, cpu, disk, mac, ram } = req.body;
    const sessionId = req.sessionID || 'unknown';

    if (auth.isHwidVerifyRateLimited(null, sessionId)) {
      return res.json({ valid: false, error: 'Too many verification attempts. Try again later.' });
    }
    
    if (!license || !sum || !cpu || !disk || !mac || !ram) {
      auth.logProductVerification(license || 'unknown', sessionId, false);
      return res.json({ valid: false, error: 'license, sum, cpu, disk, mac, and ram required' });
    }
        
    const licenseData = auth.getLicenseById(license);
    if (!licenseData) {
      auth.logProductVerification(license, sessionId, false);
      return res.json({ valid: false, error: 'License not found' });
    }
    
    const standing = auth.getAccountStanding(licenseData.user_id);
    if (!standing.exists || standing.locked || standing.suspended) {
      auth.logProductVerification(license, sessionId, false);
      return res.json({ valid: false, error: 'Account not in good standing' });
    }
    
    if (new Date(licenseData.expires_at) < new Date()) {
      auth.logProductVerification(license, sessionId, false);
      return res.json({ valid: false, error: 'License expired' });
    }
    
    auth.verifyHwidIntegrity(license, sum, cpu, disk, mac, ram, (result) => {
      if (!result.valid) {
        auth.logProductVerification(license, sessionId, false);
        return res.json(result);
      }
      
      const decryptionKey = auth.getSpeckKey(license);
      auth.logProductVerification(license, sessionId, true);
      
      res.json({
        valid: true,
        type: result.type,
        decryption_key: decryptionKey,
        expires_at: licenseData.expires_at
      });
    });
  } catch (error) {
    console.error('Product verify error:', error);
    res.json({ valid: false, error: 'Verification failed' });
  }
});

app.post('/keykeeper/product/create', (req, res) => {
  const userId = req.session.userId;
  if (!userId) {
    return res.status(401).send('Unauthorized');
  }
  
  const { license_id } = req.body;
  
  if (!license_id) {
    return res.status(400).send('license_id required');
  }
  
  const license = auth.getLicenseById(license_id);
  if (!license || license.user_id !== userId) {
    return res.status(404).send('License not found');
  }
  
  const licenseType = license.type;
  const hwid = license.license_hwid || null;
  
  packer.createPackedBinary(licenseType, hwid, license_id, (err, result) => {
    if (err) {
      console.error('Packer error:', err.message);
      return res.status(500).send('Failed to create binary');
    }
    
    auth.updateLicenseDownloadFilename(license_id, result.filename);
    auth.updateLicenseStubMac(license_id, result.mac);
    auth.updateUserSpeckKey(userId, result.key);
    auth.updateLicenseIntegrity(license_id, result.integrity);
    
    res.setHeader('Content-Type', 'application/exe');
    res.setHeader('Content-Disposition', 'attachment; filename="' + result.filename + '"');
    res.send(result.data);
  });
});

function isAuthenticated(req) {
  return req.session && req.session.userId;
}

io.on('error', (err) => {
  console.error('IO Error:', err);
});

io.on('connection', (socket) => {
  console.log('Client connected:', socket.id);
  console.log('Session data:', socket.request.session);
  
  socket.on('error', (err) => {
    console.error('Socket error:', socket.id, err);
  });
  
  let lastActivity = Date.now();
  
  const checkIdle = () => {
    if (socket.request.session && socket.request.session.userId) {
      if (Date.now() - lastActivity > IDLE_TIMEOUT_MS) {
        console.log('Client idle timeout:', socket.id);
        socket.emit('session:timeout', { message: 'Session expired due to inactivity' });
        socket.request.session.destroy();
        socket.disconnect(true);
      }
    }
  };
  
  const idleInterval = setInterval(checkIdle, 60000);
  
  socket.onAny(() => {
    lastActivity = Date.now();
  });
  
  socket.on('disconnect', () => {
    clearInterval(idleInterval);
    console.log('Client disconnected:', socket.id);
  });
  
  if (socket.request.session && socket.request.session.userId) {
    socket.join('user_' + socket.request.session.userId);
    console.log('Socket joined room: user_' + socket.request.session.userId);
  }

  socket.on('auth:register', async (data, callback) => {
    try {
      const { password, hwid } = data;
      const sessionId = socket.request.session.id || 'unknown';
      
      const sanitizedPassword = validate.sanitizePassword(password);
      
      if (!sanitizedPassword) {
        return callback({ success: false, error: 'Password must be 8-128 characters' });
      }
      
      if (auth.isRateLimited(sessionId)) {
        return callback({ success: false, error: 'Rate limited. Try again later.' });
      }
      
      const passwordHash = await auth.hashPassword(sanitizedPassword);
      const user = auth.createUser(passwordHash, hwid);
      
      auth.addRateLimitEntry(sessionId);
      
      socket.request.session.userId = user.id;
      socket.request.session.save();
      socket.join('user_' + user.id);
      
      callback({ success: true, accountNumber: user.accountNumber });
    } catch (error) {
      console.error('Register error:', error);
      callback({ success: false, error: 'Registration failed' });
    }
  });
  
  socket.on('auth:login', async (data, callback) => {
    try {
      const { account_number, password } = data;
      
      const sanitizedAccountNumber = validate.sanitizeAccountNumber(account_number);
      const sanitizedPassword = validate.sanitizePassword(password);
      const sessionId = socket.request.session.id || 'unknown';
      
      console.log('Login attempt - account_number:', sanitizedAccountNumber);
      
      if (!sanitizedAccountNumber) {
        console.log('Login failed: invalid account number');
        return callback({ success: false, error: 'Invalid account number format' });
      }
      
      if (!sanitizedPassword) {
        console.log('Login failed: password issue, length:', password ? password.length : 'undefined');
        return callback({ success: false, error: 'Password must be 8-128 characters' });
      }
      
      if (auth.isLoginRateLimited(sessionId)) {
        console.log('Login failed: rate limited');
        return callback({ success: false, error: 'Too many login attempts. Try again later.' });
      }
      
      auth.addLoginAttempt(sessionId);
      
      const user = auth.getUserByAccountNumber(sanitizedAccountNumber);
      if (!user) {
        return callback({ success: false, error: 'Invalid credentials' });
      }
      
      if (auth.isAccountLocked(user.id)) {
        return callback({ success: false, error: 'Account locked. Contact support.' });
      }
      
      if (auth.isAccountSuspended(user.id)) {
        return callback({ success: false, error: 'Account suspended. contact support.' });
      }
      
      const valid = await auth.verifyPassword(sanitizedPassword, user.password_hash);
      if (!valid) {
        auth.addFailedLoginAttempt(user.id, sessionId);
        const attemptsLeft = 5 - auth.getFailedLoginAttempts(user.id);
        return callback({ success: false, error: 'Invalid credentials. ' + attemptsLeft + ' attempts remaining.' });
      }
      
      auth.clearFailedLoginAttempts(user.id);
      auth.updateLastLogin(user.id);
      
      socket.request.session.userId = user.id;
      socket.request.session.save();
      socket.join('user_' + user.id);
      
      callback({ success: true });
    } catch (error) {
      console.error('Login error:', error);
      callback({ success: false, error: 'Login failed' });
    }
  });
  
  socket.on('auth:logout', (data, callback) => {
    socket.request.session.destroy();
    callback({ success: true });
  });
  
  socket.on('user:getProfile', (data, callback) => {
    const userId = socket.request.session.userId;
    if (!userId) {
      return callback({ error: 'Not authenticated' });
    }
    
    const user = auth.getUserById(userId);
    const license = auth.getLicenseByUserId(userId);
    const balance = tx.getUserBalance(userId);
    const pendingTx = tx.getPendingTransaction(userId);
    
    callback({
      account_number: user.account_number,
      license: license ? license.type : 'none',
      license_id: license ? license.license_id : null,
      hwid: user.hwid,
      license_status: license && new Date(license.expires_at) > new Date() ? 'active' : 'expired',
      balance,
      pending_transaction: pendingTx || null
    });
  });
  
  socket.on('license:verify', async (data, callback) => {
    try {
      const { licenseId, sum, mac, cpu, disk, ram, tpm } = data;
      const sessionId = socket.request.session.id || 'unknown';
      
      const sanitizedLicenseId = validate.sanitizeLicenseId(licenseId);
      if (!sanitizedLicenseId) {
        return callback({ valid: false, error: 'Invalid license ID format' });
      }
      
      if (!sum || !mac || !cpu || !disk || !ram || !tpm) {
        return callback({ valid: false, error: 'sum, cpu, disk, mac, ram, and tpm required' });
      }
      
      if (auth.isHwidVerifyRateLimited(null, sessionId)) {
        return callback({ valid: false, error: 'Too many verification attempts. Try again later.' });
      }

      const license = auth.getLicenseById(sanitizedLicenseId);

      if (!license) {
        return callback({ valid: false, error: 'No active license' });
      }
      
      const standing = auth.getAccountStanding(license.user_id);
      if (!standing.exists || standing.locked || standing.suspended) {
        return callback({ valid: false, error: 'Account not in good standing' });
      }
        
      if (license.stub_mac) {
        const clientStubMac = data.mac || '';
        if (clientStubMac && license.stub_mac !== clientStubMac) {
          auth.suspendAccount(license.user_id);
          return callback({ valid: false, error: 'License violated' });
        }
      }
      
      auth.addHwidVerifyAttempt(license.user_id, sessionId);
      auth.verifyHwidIntegrity(sanitizedLicenseId, sum, mac, cpu, disk, ram, tpm, (result) => {
        if (!result.valid) {
          return callback(result);
        }
        
        socket.request.session.userId = license.user_id;
        socket.request.session.licenseId = sanitizedLicenseId;
        socket.request.session.save();
        
        callback({
          valid: true,
          type: result.type,
          account_number: license.account_number,
          hwid: license.license_hwid
        });
      });
    } catch (error) {
      console.error('License verify error:', error);
      callback({ valid: false, error: 'Verification failed' });
    }
  });
  
  socket.on('tx:create', async (data, callback) => {
    const userId = socket.request.session.userId;
    if (!userId) {
      return callback({ error: 'Not authenticated' });
    }
    
    const standing = auth.getAccountStanding(userId);
    if (!standing.exists || standing.locked || standing.suspended || standing.created_at < MIN_ACCOUNT_AGE_HOURS) {
      return callback({ error: 'Account not in good standing' });
    }
    
    if (auth.isTxCreateRateLimited(userId)) {
      return callback({ error: 'Too many transactions. Try again later.' });
    }
    
    try {
      const { currency, licenseType, hwid, stub_mac } = data;
      
      const sanitizedCurrency = validate.sanitizeCurrency(currency);
      const sanitizedLicenseType = validate.sanitizeLicenseType(licenseType);
      const sanitizedStubMac = validate.sanitizeString(stub_mac, 64);
      
      if (!sanitizedCurrency) {
        return callback({ error: 'Invalid currency' });
      }
      
      if (!sanitizedLicenseType) {
        return callback({ error: 'Invalid license type' });
      }
      
      const transaction = await tx.createTransaction(userId, sanitizedCurrency, sanitizedLicenseType, hwid, sanitizedStubMac);
      auth.addTxCreateAttempt(userId);
      callback({ success: true, ...transaction });
    } catch (error) {
      console.error('Create tx error:', error);
      callback({ error: error.message });
    }
  });

  socket.on('tx:deposit', async (data, callback) => {
    const userId = socket.request.session.userId;
    if (!userId) {
      return callback({ error: 'Not authenticated' });
    }
    
    const standing = auth.getAccountStanding(userId);
    if (!standing.exists || standing.locked || standing.suspended || standing.created_at < MIN_ACCOUNT_AGE_HOURS) {
      return callback({ error: 'Account not in good standing' });
    }
    
    if (auth.isTxCreateRateLimited(userId)) {
      return callback({ error: 'Too many transactions. Try again later.' });
    }
    
    try {
      const { currency, amount } = data;
      
      const sanitizedCurrency = validate.sanitizeCurrency(currency);
      const sanitizedAmount = validate.sanitizeDepositAmount(amount);
      
      if (!sanitizedCurrency) {
        return callback({ error: 'Invalid currency' });
      }
      
      if (!sanitizedAmount) {
        return callback({ error: 'Invalid amount' });
      }
      
      const transaction = await tx.createDepositTransaction(userId, sanitizedCurrency, sanitizedAmount);
      auth.addTxCreateAttempt(userId);
      callback({ success: true, ...transaction });
    } catch (error) {
      console.error('Create deposit error:', error);
      callback({ error: error.message });
    }
  });
  
  socket.on('tx:withdraw', async (data, callback) => {
    const userId = socket.request.session.userId;
    if (!userId) {
      return callback({ error: 'Not authenticated' });
    }
    
    const standing = auth.getAccountStanding(userId);
    if (!standing.exists || standing.locked || standing.suspended || standing.created_at < MIN_ACCOUNT_AGE_HOURS) {
      return callback({ error: 'Account not in good standing' });
    }
    
    try {
      const { currency, amount, address } = data;
      
      const sanitizedCurrency = validate.sanitizeCurrency(currency);
      const sanitizedAmount = validate.sanitizeWithdrawAmount(amount, sanitizedCurrency);
      const sanitizedAddress = validate.sanitizeAddress(address);
      
      if (!sanitizedCurrency) {
        return callback({ error: 'Invalid currency' });
      }
      
      if (!sanitizedAmount) {
        return callback({ error: 'Invalid amount' });
      }
      
      if (!sanitizedAddress) {
        return callback({ error: 'Invalid address' });
      }
      
      if (!validate.validateWithdrawAddress(sanitizedAddress, sanitizedCurrency)) {
        return callback({ error: 'Address does not match selected currency' });
      }
      
      if (auth.isWithdrawRateLimited(userId)) {
        return callback({ error: 'Too many withdrawal attempts. Try again later.' });
      }
      
      const transaction = await tx.createWithdrawTransaction(userId, sanitizedCurrency, sanitizedAmount, sanitizedAddress);
      
      auth.addWithdrawAttempt(userId, sanitizedCurrency);
      
      callback({ success: true, tx_id: transaction.tx_id, tx_hash: transaction.tx_hash });
    } catch (error) {
      console.error('Withdraw error:', error);
      callback({ error: error.message });
    }
  });
  
  socket.on('history:get', (data, callback) => {
    const userId = socket.request.session.userId;
    if (!userId) {
      return callback({ error: 'Not authenticated' });
    }
    
    const transactions = tx.getTransactionsByUserId(userId);
    const licenses = tx.getLicensesByUserId(userId);
    
    const history = [];
    
    transactions.forEach(t => {
      history.push({
        type: 'transaction',
        subtype: t.type,
        currency: t.currency,
        amount: t.amount,
        status: t.status,
        tx_hash: t.tx_hash,
        license_type: t.license_type,
        date: t.created_at
      });
    });
    
    licenses.forEach(l => {
      history.push({
        type: 'license',
        license_id: l.license_id,
        license_type: l.type,
        expires_at: l.expires_at,
        date: l.created_at
      });
    });
    
    history.sort((a, b) => new Date(b.date) - new Date(a.date));
    
    callback({ history });
  });
  
  socket.on('license:initRelink', (data, callback) => {
    const userId = socket.request.session.userId;
    if (!userId) {
      return callback({ error: 'Not authenticated' });
    }
    
    const { licenseId } = data;
    
    const sanitizedLicenseId = validate.sanitizeLicenseId(licenseId);
    if (!sanitizedLicenseId) {
      return callback({ error: 'Invalid license ID format' });
    }
    
    const license = auth.getLicenseById(sanitizedLicenseId);
    if (!license || license.user_id !== userId) {
      return callback({ error: 'License not found' });
    }
    
    if (!auth.canRelink(sanitizedLicenseId)) {
      return callback({ error: 'Can only relink once per month' });
    }
    
    const speckKey = auth.getSpeckKey(userId);
    
    callback({
      success: true,
      speckKey: speckKey,
      machineInfoFields: ['cpu_serial', 'disk_serial', 'mac_address', 'ram_serial', 'tpm_key']
    });
  });

  socket.on('license:relink', (data, callback) => {
    const { licenseId, machineInfo } = data;
    
    const sanitizedLicenseId = validate.sanitizeLicenseId(licenseId);
    if (!sanitizedLicenseId) {
      return callback({ error: 'Invalid license ID format' });
    }
    
    const license = auth.getLicenseById(sanitizedLicenseId);
    if (!license) {
      return callback({ error: 'License not found' });
    }

    const userId = license.user_id;

    if (auth.isRelinkRateLimited(userId)) {
      return callback({ error: 'Too many relink attempts. Try again later.' });
    }
    
    if (!auth.canRelink(sanitizedLicenseId)) {
      return callback({ error: 'Can only relink once per month' });
    }
    
    if (!machineInfo || typeof machineInfo !== 'object') {
      return callback({ error: 'machineInfo required' });
    }
    
    const sanitizedMachineInfo = {
      cpu_serial: validate.sanitizeString(machineInfo.cpu_serial, 64) || '',
      disk_serial: validate.sanitizeString(machineInfo.disk_serial, 64) || '',
      mac_address: validate.sanitizeString(machineInfo.mac_address, 64) || '',
      ram_serial: validate.sanitizeString(machineInfo.ram_serial, 256) || '',
      tpm_key: validate.sanitizeString(machineInfo.tpm_key, 256) || ''
    };
    
    const computedHwid = auth.computeHwidFromMachineInfo(sanitizedMachineInfo, license);
    if (!computedHwid) {
      return callback({ error: 'Failed to compute HWID' });
    }
    
    auth.addRelinkAttempt(userId);
    
    const result = auth.relinkLicense(sanitizedLicenseId, computedHwid);
    
    if (result.success) {
      io.emit('license:relink:complete', { licenseId: sanitizedLicenseId });
    }
    
    callback(result);
  });
  
  socket.on('license:canRelink', (data, callback) => {
    const userId = socket.request.session.userId;
    if (!userId) {
      return callback({ error: 'Not authenticated' });
    }
    
    const { licenseId } = data;
    const sanitizedLicenseId = validate.sanitizeLicenseId(licenseId);
    if (!sanitizedLicenseId) {
      return callback({ error: 'Invalid license ID format' });
    }
    
    const license = auth.getLicenseById(sanitizedLicenseId);
    if (!license || license.user_id !== userId) {
      return callback({ error: 'License not found' });
    }
    
callback({ canRelink: auth.canRelink(sanitizedLicenseId) });
  });
  
  socket.on('user:changePassword', (data, callback) => {
    const userId = socket.request.session.userId;
    if (!userId) {
      return callback({ error: 'Not authenticated' });
    }
    
    const { oldPassword, newPassword } = data;
    const sanitizedOldPassword = validate.sanitizePassword(oldPassword);
    const sanitizedNewPassword = validate.sanitizePassword(newPassword);
    
    if (!sanitizedOldPassword || !sanitizedNewPassword) {
      return callback({ error: 'Password must be 8-128 characters' });
    }
    
    const result = auth.changePassword(userId, sanitizedOldPassword, sanitizedNewPassword);
    callback(result);
  });
  
  socket.on('user:deleteAccount', (data, callback) => {
    const userId = socket.request.session.userId;
    if (!userId) {
      return callback({ error: 'Not authenticated' });
    }
    
    const { password } = data;
    const sanitizedPassword = validate.sanitizePassword(password);
    
    if (!sanitizedPassword) {
      return callback({ error: 'Invalid password' });
    }
    
    const result = auth.deleteAccount(userId, sanitizedPassword);
    if (result.success) {
      socket.request.session.destroy();
    }
    callback(result);
  });
});

const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

server.listen(PORT, '127.0.0.1', () => {
  console.log('Obsidian backend running on port ' + PORT);
  console.log('PGP key path: ' + (process.env.PGP_KEY_PATH || '/srv/pgp/key.asc'));
  pgp.loadPrivateKey();
  
  auth.cleanupOldSessions();
  setInterval(() => {
    auth.cleanupOldSessions();
  }, 24 * 60 * 60 * 1000);
  
  tx.checkPendingPayments();
  setInterval(() => {
    tx.checkPendingPayments();
  }, 30000);
  
  wallet.getExchangeRates().then(rates => {
    console.log('Initial exchange rates:', rates);
  });
  setInterval(() => {
    wallet.getExchangeRates();
  }, 5 * 60 * 1000);
  
  tx.cleanupOldXMRTransactions();
  setInterval(() => {
    tx.cleanupOldXMRTransactions();
  }, 24 * 60 * 60 * 1000);
  
  auth.cleanupOldTxCreateRateLimits();
  setInterval(() => {
    auth.cleanupOldTxCreateRateLimits();
  }, 60 * 60 * 1000);
  
  auth.cleanupOldHwidVerifyRateLimits();
  setInterval(() => {
    auth.cleanupOldHwidVerifyRateLimits();
  }, 60 * 60 * 1000);
});
