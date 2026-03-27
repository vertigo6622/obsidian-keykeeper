const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const session = require('express-session');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const auth = require('./auth');
const tx = require('./transactions');
const validate = require('./validate');
const wallet = require('./wallet');
const packer = require('./packer-bridge');

const app = express();
const server = http.createServer(app);

const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || 'http://localhost:8000,http://127.0.0.1:8000').split(',');

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
const SESSION_SECRET = process.env.SESSION_SECRET || require('crypto').randomBytes(32).toString('hex');

app.use(express.json());

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
  sessionMiddleware(socket.request, socket.request.res || {}, next);
});

app.get('/', (req, res) => {
  res.json({ status: 'ok', service: 'obsidian-keykeeper' });
});

app.post('/api/register', async (req, res) => {
  try {
    const { email, password, hwid } = req.body;
    
    if (!email || !password) {
      return res.json({ success: false, error: 'Email and password required' });
    }
    
    const ip = req.ip || req.connection.remoteAddress;
    
    if (auth.isRateLimited(ip)) {
      return res.json({ success: false, error: 'Rate limited. Try again later.' });
    }
    
    const existingUser = auth.getUserByEmail(email);
    if (existingUser) {
      return res.json({ success: false, error: 'Email already registered' });
    }
    
    const passwordHash = await auth.hashPassword(password);
    const user = auth.createUser(email, passwordHash, hwid);
    
    auth.addRateLimitEntry(ip);
    
    req.session.userId = user.id;
    req.session.save();
    
    res.json({ success: true });
  } catch (error) {
    console.error('Register error:', error);
    res.json({ success: false, error: 'Registration failed' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.json({ success: false, error: 'Email and password required' });
    }
    
    const user = auth.getUserByEmail(email);
    if (!user) {
      return res.json({ success: false, error: 'Invalid credentials' });
    }
    
    const valid = await auth.verifyPassword(password, user.password_hash);
    if (!valid) {
      return res.json({ success: false, error: 'Invalid credentials' });
    }
    
    auth.updateLastLogin(user.id);
    
    req.session.userId = user.id;
    req.session.save();
    
    res.json({ success: true });
  } catch (error) {
    console.error('Login error:', error);
    res.json({ success: false, error: 'Login failed' });
  }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

app.post('/api/product/verify', async (req, res) => {
  try {
    const { license_id, hwid_data, stub_mac, client_mac } = req.body;
    const clientIp = req.ip || req.connection.remoteAddress;
    
    if (!license_id || !hwid_data || !stub_mac || !client_mac) {
      auth.logProductVerification(license_id || 'unknown', clientIp, false);
      return res.json({ valid: false, error: 'license_id, hwid_data, stub_mac, and client_mac required' });
    }
    
    if (auth.isHwidVerifyRateLimited(null, clientIp)) {
      return res.json({ valid: false, error: 'Too many verification attempts. Try again later.' });
    }
    
    const license = auth.getLicenseById(license_id);
    if (!license) {
      auth.logProductVerification(license_id, clientIp, false);
      return res.json({ valid: false, error: 'License not found' });
    }
    
    if (new Date(license.expires_at) < new Date()) {
      auth.logProductVerification(license_id, clientIp, false);
      return res.json({ valid: false, error: 'License expired' });
    }
    
    if (!auth.verifyHwidIntegrity(hwid_data, license.stub_mac, client_mac)) {
      auth.logProductVerification(license_id, clientIp, false);
      return res.json({ valid: false, error: 'Hardware ID integrity check failed' });
    }
    
    const decryptionKey = crypto.randomBytes(32).toString('hex');
    
    auth.logProductVerification(license_id, clientIp, true);
    
    res.json({
      valid: true,
      type: license.type,
      decryption_key: decryptionKey,
      expires_at: license.expires_at
    });
  } catch (error) {
    console.error('Product verify error:', error);
    res.json({ valid: false, error: 'Verification failed' });
  }
});

app.post('/api/product/create', (req, res) => {
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
  
  packer.createPackedBinary(licenseType, hwid, (err, result) => {
    if (err) {
      console.error('Packer error:', err.message);
      return res.status(500).send('Failed to create binary');
    }
    
    auth.updateLicenseDownloadFilename(license_id, result.filename);
    auth.updateLicenseStubMac(license_id, result.mac);
    
    if (result.key) {
      auth.updateUserSpeckKey(userId, result.key);
    }
    
    if (result.hwid) {
      auth.updateLicenseHwid(license_id, result.hwid);
    }
    
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', 'attachment; filename="' + result.filename + '"');
    res.send(result.data);
  });
});

function isAuthenticated(req) {
  return req.session && req.session.userId;
}

io.on('connection', (socket) => {
  console.log('Client connected:', socket.id);
  
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
      const { email, password, hwid } = data;
      const ip = socket.handshake.address || 'unknown';
      
      const sanitizedEmail = validate.sanitizeEmail(email);
      const sanitizedPassword = validate.sanitizePassword(password);
      
      if (!sanitizedEmail || !validate.isValidEmail(sanitizedEmail)) {
        return callback({ success: false, error: 'Invalid email format' });
      }
      
      if (!sanitizedPassword) {
        return callback({ success: false, error: 'Password must be 8-128 characters' });
      }
      
      if (auth.isRateLimited(ip)) {
        return callback({ success: false, error: 'Rate limited. Try again later.' });
      }
      
      const existingUser = auth.getUserByEmail(sanitizedEmail);
      if (existingUser) {
        return callback({ success: false, error: 'Email already registered' });
      }
      
      const passwordHash = await auth.hashPassword(sanitizedPassword);
      const user = auth.createUser(sanitizedEmail, passwordHash, hwid);
      
      auth.addRateLimitEntry(ip);
      
      socket.request.session.userId = user.id;
      socket.request.session.save();
      socket.join('user_' + user.id);
      
      callback({ success: true });
    } catch (error) {
      console.error('Register error:', error);
      callback({ success: false, error: 'Registration failed' });
    }
  });
  
  socket.on('auth:login', async (data, callback) => {
    try {
      const { email, password } = data;
      
      const sanitizedEmail = validate.sanitizeEmail(email);
      const sanitizedPassword = validate.sanitizePassword(password);
      const ip = socket.handshake.address || 'unknown';
      
      console.log('Login attempt - email:', sanitizedEmail, 'password length:', password ? password.length : 0);
      
      if (!sanitizedEmail || !validate.isValidEmail(sanitizedEmail)) {
        console.log('Login failed: invalid email');
        return callback({ success: false, error: 'Invalid email format' });
      }
      
      if (!sanitizedPassword) {
        console.log('Login failed: password issue, length:', password ? password.length : 'undefined');
        return callback({ success: false, error: 'Password must be 8-128 characters' });
      }
      
      if (auth.isLoginRateLimited(ip)) {
        console.log('Login failed: rate limited');
        return callback({ success: false, error: 'Too many login attempts. Try again later.' });
      }
      
      auth.addLoginAttempt(ip);
      
      const user = auth.getUserByEmail(sanitizedEmail);
      if (!user) {
        return callback({ success: false, error: 'Invalid credentials' });
      }
      
      if (auth.isAccountLocked(user.id)) {
        return callback({ success: false, error: 'Account locked. Contact support.' });
      }
      
      if (auth.isAccountSuspended(user.id)) {
        return callback({ success: false, error: 'account suspended. contact support.' });
      }
      
      const valid = await auth.verifyPassword(sanitizedPassword, user.password_hash);
      if (!valid) {
        auth.addFailedLoginAttempt(user.id, ip);
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
    
    callback({
      account_number: user.account_number,
      email: user.email,
      license: license ? license.type : 'none',
      license_id: license ? license.license_id : null,
      hwid: user.hwid,
      license_status: license && new Date(license.expires_at) > new Date() ? 'active' : 'expired',
      balance
    });
  });
  
  socket.on('license:verify', async (data, callback) => {
    try {
      const { licenseId, hwid_data, stub_mac, client_mac } = data;
      const ip = socket.handshake.address || 'unknown';
      
      const sanitizedLicenseId = validate.sanitizeLicenseId(licenseId);
      if (!sanitizedLicenseId) {
        return callback({ valid: false, error: 'Invalid license ID format' });
      }
      
      if (!hwid_data || !stub_mac || !client_mac) {
        return callback({ valid: false, error: 'hwid_data, stub_mac, and client_mac required' });
      }
      
      if (auth.isHwidVerifyRateLimited(null, ip)) {
        return callback({ valid: false, error: 'Too many verification attempts. Try again later.' });
      }
      
      const license = auth.getLicenseById(sanitizedLicenseId);
      if (!license) {
        return callback({ valid: false, error: 'License not found' });
      }
      
      if (new Date(license.expires_at) < new Date()) {
        return callback({ valid: false, error: 'License expired' });
      }
      
      if (license.stub_mac && license.stub_mac !== stub_mac) {
        auth.suspendAccount(license.user_id);
        return callback({ valid: false, error: 'License violated' });
      }
      
      if (!auth.verifyHwidIntegrity(hwid_data, license.stub_mac, client_mac)) {
        return callback({ valid: false, error: 'Hardware ID integrity check failed' });
      }
      
      auth.addHwidVerifyAttempt(null, ip);
      
      socket.request.session.userId = license.user_id;
      socket.request.session.licenseId = sanitizedLicenseId;
      socket.request.session.save();
      
      callback({
        valid: true,
        type: license.type,
        email: license.email,
        account_number: license.account_number,
        hwid: license.license_hwid
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
    
    const ip = socket.handshake.address || 'unknown';
    
    if (auth.isTxCreateRateLimited(userId, ip)) {
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
      auth.addTxCreateAttempt(userId, ip);
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
    
    const ip = socket.handshake.address || 'unknown';
    
    if (auth.isTxCreateRateLimited(userId, ip)) {
      return callback({ error: 'Too many transactions. Try again later.' });
    }
    
    try {
      const { currency, amount } = data;
      
      const sanitizedCurrency = validate.sanitizeCurrency(currency);
      const sanitizedAmount = validate.sanitizeAmount(amount);
      
      if (!sanitizedCurrency) {
        return callback({ error: 'Invalid currency' });
      }
      
      if (!sanitizedAmount || sanitizedAmount <= 0) {
        return callback({ error: 'Invalid amount' });
      }
      
      const transaction = await tx.createDepositTransaction(userId, sanitizedCurrency, sanitizedAmount);
      auth.addTxCreateAttempt(userId, ip);
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
    
    try {
      const { currency, amount, address } = data;
      
      const sanitizedCurrency = validate.sanitizeCurrency(currency);
      const sanitizedAmount = validate.sanitizeAmount(amount);
      const sanitizedAddress = validate.sanitizeAddress(address);
      
      if (!sanitizedCurrency) {
        return callback({ error: 'Invalid currency' });
      }
      
      if (!sanitizedAmount || sanitizedAmount <= 0) {
        return callback({ error: 'Invalid amount' });
      }
      
      if (!sanitizedAddress) {
        return callback({ error: 'Invalid address' });
      }
      
      const balance = tx.getUserBalance(userId);
      const available = sanitizedCurrency === 'XMR' ? balance.xmr : balance.ltc;
      
      if (sanitizedAmount > available) {
        return callback({ error: 'Insufficient balance' });
      }
      
      const transaction = await tx.createWithdrawTransaction(userId, sanitizedCurrency, sanitizedAmount, sanitizedAddress);
      
      callback({ success: true, tx_id: transaction.tx_id });
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
    
    const speckKey = auth.getOrCreateSpeckKey(userId);
    
    callback({
      success: true,
      speckKey: speckKey,
      machineInfoFields: ['cpu_serial', 'disk_serial', 'mac_address', 'ram_serial']
    });
  });

  socket.on('license:relink', (data, callback) => {
    const ip = socket.handshake.address || 'unknown';
    
    if (auth.isRelinkRateLimited(ip)) {
      return callback({ error: 'Too many relink attempts. Try again later.' });
    }
    
    const { licenseId, machineInfo } = data;
    
    const sanitizedLicenseId = validate.sanitizeLicenseId(licenseId);
    if (!sanitizedLicenseId) {
      return callback({ error: 'Invalid license ID format' });
    }
    
    if (!machineInfo || typeof machineInfo !== 'object') {
      return callback({ error: 'machineInfo required' });
    }
    
    const license = auth.getLicenseById(sanitizedLicenseId);
    if (!license) {
      return callback({ error: 'License not found' });
    }
    
    const userId = license.user_id;
    
    if (!auth.canRelink(sanitizedLicenseId)) {
      return callback({ error: 'Can only relink once per month' });
    }
    
    const sanitizedMachineInfo = {
      cpu_serial: validate.sanitizeString(machineInfo.cpu_serial, 64) || '',
      disk_serial: validate.sanitizeString(machineInfo.disk_serial, 64) || '',
      mac_address: validate.sanitizeString(machineInfo.mac_address, 64) || '',
      ram_serial: validate.sanitizeString(machineInfo.ram_serial, 256) || ''
    };
    
    const speckKey = auth.getSpeckKey(userId);
    if (!speckKey) {
      return callback({ error: 'Speck key not found. Run initRelink from authenticated session first.' });
    }
    
    const computedHwid = auth.computeHwidFromMachineInfo(sanitizedMachineInfo, speckKey);
    if (!computedHwid) {
      return callback({ error: 'Failed to compute HWID' });
    }
    
    auth.addRelinkAttempt(ip);
    
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
  
  socket.on('user:changeEmail', (data, callback) => {
    const userId = socket.request.session.userId;
    if (!userId) {
      return callback({ error: 'Not authenticated' });
    }
    
    const { oldPassword, newEmail } = data;
    const sanitizedOldPassword = validate.sanitizePassword(oldPassword);
    const sanitizedNewEmail = validate.sanitizeEmail(newEmail);
    
    if (!sanitizedOldPassword) {
      return callback({ error: 'Invalid password' });
    }
    
    if (!sanitizedNewEmail || !validate.isValidEmail(sanitizedNewEmail)) {
      return callback({ error: 'Invalid email format' });
    }
    
    const result = auth.changeEmail(userId, sanitizedOldPassword, sanitizedNewEmail);
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
  
  socket.on('user:getNotifications', (data, callback) => {
    const userId = socket.request.session.userId;
    if (!userId) {
      return callback({ error: 'Not authenticated' });
    }
    
    callback({ enabled: auth.getNotifications(userId) });
  });
  
  socket.on('user:setNotifications', (data, callback) => {
    const userId = socket.request.session.userId;
    if (!userId) {
      return callback({ error: 'Not authenticated' });
    }
    
    const { enabled } = data;
    auth.setNotifications(userId, enabled);
    callback({ success: true });
  });
  
  socket.on('user:getSessions', (data, callback) => {
    const userId = socket.request.session.userId;
    if (!userId) {
      return callback({ error: 'Not authenticated' });
    }
    
    const sessions = auth.getUserSessions(userId);
    callback({ sessions });
  });
  
  socket.on('user:logoutAll', (data, callback) => {
    const userId = socket.request.session.userId;
    if (!userId) {
      return callback({ error: 'Not authenticated' });
    }
    
    db.prepare('DELETE FROM sessions WHERE user_id = ?').run(userId);
    callback({ success: true });
  });
});

const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

const downloadsDir = path.join(__dirname, 'downloads');

app.get('/api/downloads/:filename', (req, res) => {
  const userId = req.session.userId;
  if (!userId) {
    return res.send();
  }
  
  const license = auth.getLicenseByUserId(userId);
  if (!license || new Date(license.expires_at) < new Date()) {
    return res.send();
  }
  
  const filename = req.params.filename;
  const validFiles = ['obsidian-ce.exe'];
  if (!validFiles.includes(filename)) {
    return res.send();
  }
  
  const safePath = path.join(downloadsDir, filename);
  if (!safePath.startsWith(downloadsDir)) {
    return res.send();
  }
  
  if (!fs.existsSync(safePath)) {
    return res.send();
  }
  
  res.download(safePath);
});

server.listen(PORT, '127.0.0.1', () => {
  console.log('Obsidian backend running on port ' + PORT);
  console.log('PGP key path: ' + (process.env.PGP_KEY_PATH || '/srv/pgp/key.asc'));
  
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
