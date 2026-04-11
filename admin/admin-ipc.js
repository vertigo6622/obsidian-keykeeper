const net = require('net');
const db = require('./database');
const auth = require('./auth');
const tx = require('./transactions');
const wallet = require('./wallet');
const validate = require('./validate');

const SOCKET_PATH = '/tmp/obsidian-admin.sock';

function logAudit(actionType, targetType, targetId, details) {
  db.prepare(
    'INSERT INTO admin_audit (action_type, target_type, target_id, details) VALUES (?, ?, ?, ?)'
  ).run(actionType, targetType || null, targetId || null, details || null);
}

function cleanup() {
  try { require('fs').unlinkSync(SOCKET_PATH); } catch (e) {}
}

const handlers = {
  'user:info': async (data) => {
    const user = db.prepare('SELECT * FROM users WHERE account_number = ?').get(data.account_number);
    if (!user) return { error: 'User not found' };
    const license = auth.getLicenseByUserId(user.id);
    const balance = await tx.getUserBalance(user.id);
    logAudit('user:info', 'user', user.account_number, null);
    return {
      id: user.id,
      account_number: user.account_number,
      hwid: license ? license.hwid : null,
      suspended: user.suspended,
      locked_at: user.locked_at,
      created_at: user.created_at,
      last_login: user.last_login,
      license: license || null,
      balance
    };
  },

  'user:search': async (data) => {
    const users = db.prepare(
      "SELECT id, account_number, created_at, suspended, locked_at FROM users WHERE account_number LIKE ? LIMIT 20"
    ).all('%' + data.query + '%');
    logAudit('user:search', 'user', null, data.query);
    return { users };
  },

  'user:list': async (data) => {
    const limit = Math.min(data.limit || 20, 100);
    const users = db.prepare(
      'SELECT id, account_number, created_at, last_login, suspended, locked_at FROM users ORDER BY id DESC LIMIT ?'
    ).all(limit);
    logAudit('user:list', 'user', null, 'limit=' + limit);
    return { users };
  },

  'user:create': async (data) => {
    const password = require('crypto').randomBytes(16).toString('base64').slice(0, 20);
    const passwordHash = await auth.hashPassword(password);
    const user = auth.createUser(passwordHash, null);
    logAudit('user:create', 'user', user.accountNumber, null);
    return { account_number: user.accountNumber, password };
  },

  'user:suspend': async (data) => {
    const user = db.prepare('SELECT id FROM users WHERE account_number = ?').get(data.account_number);
    if (!user) return { error: 'User not found' };
    auth.suspendAccount(user.id);
    logAudit('user:suspend', 'user', data.account_number, null);
    return { success: true };
  },

  'user:unsuspend': async (data) => {
    const user = db.prepare('SELECT id FROM users WHERE account_number = ?').get(data.account_number);
    if (!user) return { error: 'User not found' };
    db.prepare('UPDATE users SET suspended = 0 WHERE id = ?').run(user.id);
    logAudit('user:unsuspend', 'user', data.account_number, null);
    return { success: true };
  },

  'user:lock': async (data) => {
    const user = db.prepare('SELECT id FROM users WHERE account_number = ?').get(data.account_number);
    if (!user) return { error: 'User not found' };
    db.prepare('UPDATE users SET locked_at = datetime(\'now\') WHERE id = ?').run(user.id);
    logAudit('user:lock', 'user', data.account_number, null);
    return { success: true };
  },

  'user:unlock': async (data) => {
    const user = db.prepare('SELECT id FROM users WHERE account_number = ?').get(data.account_number);
    if (!user) return { error: 'User not found' };
    auth.unlockAccount(user.id);
    logAudit('user:unlock', 'user', data.account_number, null);
    return { success: true };
  },

  'user:delete': async (data) => {
    const user = db.prepare('SELECT id FROM users WHERE account_number = ?').get(data.account_number);
    if (!user) return { error: 'User not found' };
    db.prepare('DELETE FROM transactions WHERE user_id = ?').run(user.id);
    db.prepare('DELETE FROM licenses WHERE user_id = ?').run(user.id);
    db.prepare('DELETE FROM sessions WHERE user_id = ?').run(user.id);
    db.prepare('DELETE FROM auth_tokens WHERE user_id = ?').run(user.id);
    db.prepare('DELETE FROM users WHERE id = ?').run(user.id);
    logAudit('user:delete', 'user', data.account_number, null);
    return { success: true };
  },

  'user:changepassword': async (data) => {
    const user = db.prepare('SELECT id FROM users WHERE account_number = ?').get(data.account_number);
    if (!user) return { error: 'User not found' };
    const hash = await auth.hashPassword(data.new_password);
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, user.id);
    logAudit('user:changepassword', 'user', data.account_number, null);
    return { success: true };
  },

  'license:create': async (data) => {
    const user = db.prepare('SELECT id FROM users WHERE id = ? OR account_number = ?').get(data.user_id, data.user_id);
    if (!user) return { error: 'User not found' };
    const duration = data.duration_months || 6;
    const licenseId = auth.generateLicenseId();
    db.prepare(
      "INSERT INTO licenses (license_id, user_id, type, expires_at) VALUES (?, ?, ?, datetime('now', '+' || ? || ' months'))"
    ).run(licenseId, user.id, data.type, duration);
    logAudit('license:create', 'license', licenseId, 'user=' + user.account_number + ' type=' + data.type + ' dur=' + duration + 'm');
    return { license_id: licenseId };
  },

  'license:info': async (data) => {
    const license = db.prepare(
      'SELECT l.*, u.account_number FROM licenses l JOIN users u ON l.user_id = u.id WHERE l.license_id = ?'
    ).get(data.license_id);
    if (!license) return { error: 'License not found' };
    logAudit('license:info', 'license', data.license_id, null);
    return { license };
  },

  'license:list': async (data) => {
    if (data.user_id) {
      const user = db.prepare('SELECT id FROM users WHERE id = ? OR account_number = ?').get(data.user_id, data.user_id);
      if (!user) return { error: 'User not found' };
      const licenses = db.prepare('SELECT * FROM licenses WHERE user_id = ? ORDER BY created_at DESC').all(user.id);
      logAudit('license:list', 'license', null, 'user=' + data.user_id);
      return { licenses };
    }
    const limit = Math.min(data.limit || 20, 100);
    const licenses = db.prepare('SELECT l.*, u.account_number FROM licenses l JOIN users u ON l.user_id = u.id ORDER BY l.created_at DESC LIMIT ?').all(limit);
    logAudit('license:list', 'license', null, 'limit=' + limit);
    return { licenses };
  },

  'license:discard': async (data) => {
    const license = db.prepare('SELECT * FROM licenses WHERE license_id = ?').get(data.license_id);
    if (!license) return { error: 'License not found' };
    db.prepare('DELETE FROM licenses WHERE license_id = ?').run(data.license_id);
    logAudit('license:discard', 'license', data.license_id, null);
    return { success: true };
  },

  'license:extend': async (data) => {
    const license = db.prepare('SELECT * FROM licenses WHERE license_id = ?').get(data.license_id);
    if (!license) return { error: 'License not found' };
    const months = data.duration_months || 6;
    db.prepare(
      "UPDATE licenses SET expires_at = datetime(expires_at, '+' || ? || ' months') WHERE license_id = ?"
    ).run(months, data.license_id);
    logAudit('license:extend', 'license', data.license_id, '+' + months + ' months');
    return { success: true };
  },

  'license:relink': async (data) => {
    const license = db.prepare('SELECT * FROM licenses WHERE license_id = ?').get(data.license_id);
    if (!license) return { error: 'License not found' };
    db.prepare('UPDATE licenses SET hwid = ?, last_relink_at = datetime(\'now\') WHERE license_id = ?').run(data.new_hwid, data.license_id);
    logAudit('license:relink', 'license', data.license_id, 'hwid=' + data.new_hwid);
    return { success: true };
  },

  'license:change-stub-mac': async (data) => {
    const validate = require('./validate');
    const sanitizedMac = validate.sanitizeStubMac(data.new_stub_mac);
    if (!sanitizedMac) return { error: 'Invalid stub MAC format. Must be 32 hexadecimal characters.' };
    const license = db.prepare('SELECT * FROM licenses WHERE license_id = ?').get(data.license_id);
    if (!license) return { error: 'License not found' };
    db.prepare('UPDATE licenses SET stub_mac = ? WHERE license_id = ?').run(sanitizedMac, data.license_id);
    logAudit('license:change-stub-mac', 'license', data.license_id, null);
    return { success: true };
  },

  'license:change-integrity': async (data) => {
    const sanitized = validate.sanitizeIntegrityKey(data.new_integrity);
    if (!sanitized) return { error: 'Invalid integrity key format. Must be 32 hexadecimal characters.' };
    const license = db.prepare('SELECT * FROM licenses WHERE license_id = ?').get(data.license_id);
    if (!license) return { error: 'License not found' };
    db.prepare('UPDATE licenses SET integrity = ? WHERE license_id = ?').run(sanitized, data.license_id);
    logAudit('license:change-integrity', 'license', data.license_id, null);
    return { success: true };
  },

  'license:change-speck-key': async (data) => {
    const sanitizedKey = validate.sanitizeIntegrityKey(data.new_speck_key);
    if (!sanitizedKey) return { error: 'Invalid speck key format. Must be 32 hex characters.' };
    const sanitizedLicenseId = validate.sanitizeLicenseId(data.license_id);
    if (!sanitizedLicenseId) return { error: 'Invalid license ID format' };
    const license = db.prepare('SELECT * FROM licenses WHERE license_id = ?').get(sanitizedLicenseId);
    if (!license) return { error: 'License not found' };
    db.prepare('UPDATE licenses SET speck_key = ? WHERE license_id = ?').run(sanitizedKey, sanitizedLicenseId);
    logAudit('license:change-speck-key', 'license', sanitizedLicenseId, null);
    return { success: true };
  },

  'license:reset-hwid': async (data) => {
    const license = db.prepare('SELECT * FROM licenses WHERE license_id = ?').get(data.license_id);
    if (!license) return { error: 'License not found' };
    db.prepare('UPDATE licenses SET hwid = NULL, last_relink_at = datetime(\'now\') WHERE license_id = ?').run(data.license_id);
    logAudit('license:reset-hwid', 'license', data.license_id, null);
    return { success: true };
  },

  'license:verify': async (data) => {
    const license = db.prepare('SELECT * FROM licenses WHERE license_id = ?').get(data.license_id);
    if (!license) return { error: 'License not found' };
    const expired = new Date(license.expires_at) < new Date();
    logAudit('license:verify', 'license', data.license_id, expired ? 'expired' : 'valid');
    return { valid: !expired, license };
  },

  'tx:info': async (data) => {
    const transaction = db.prepare('SELECT * FROM transactions WHERE id = ?').get(data.tx_id);
    if (!transaction) return { error: 'Transaction not found' };
    logAudit('tx:info', 'transaction', String(data.tx_id), null);
    return { transaction };
  },

  'tx:list': async (data) => {
    if (data.user_id) {
      const user = db.prepare('SELECT id FROM users WHERE id = ? OR account_number = ?').get(data.user_id, data.user_id);
      if (!user) return { error: 'User not found' };
      const transactions = db.prepare('SELECT * FROM transactions WHERE user_id = ? ORDER BY created_at DESC LIMIT ?').all(user.id, data.limit || 50);
      logAudit('tx:list', 'transaction', null, 'user=' + data.user_id);
      return { transactions };
    }
    const status = data.status;
    const limit = Math.min(data.limit || 20, 100);
    let transactions;
    if (status) {
      transactions = db.prepare('SELECT t.*, u.account_number FROM transactions t JOIN users u ON t.user_id = u.id WHERE t.status = ? ORDER BY t.created_at DESC LIMIT ?').all(status, limit);
    } else {
      transactions = db.prepare('SELECT t.*, u.account_number FROM transactions t JOIN users u ON t.user_id = u.id ORDER BY t.created_at DESC LIMIT ?').all(limit);
    }
    logAudit('tx:list', 'transaction', null, status ? 'status=' + status : 'all');
    return { transactions };
  },

  'tx:pending': async () => {
    const transactions = db.prepare(
      "SELECT t.*, u.account_number FROM transactions t JOIN users u ON t.user_id = u.id WHERE t.status = 'pending' AND t.expires_at >= datetime('now') ORDER BY t.created_at DESC"
    ).all();
    logAudit('tx:pending', 'transaction', null, null);
    return { transactions };
  },

  'tx:forcecomplete': async (data) => {
    const transaction = db.prepare('SELECT * FROM transactions WHERE id = ?').get(data.tx_id);
    if (!transaction) return { error: 'Transaction not found' };
    const io = tx.getIO();
    if (transaction.type === 'purchase') {
      const licenseId = auth.createLicense(transaction.user_id, transaction.license_type, transaction.hwid, transaction.stub_mac);
      db.prepare('UPDATE transactions SET status = ?, license_id = ? WHERE id = ?').run('completed', licenseId, data.tx_id);
      if (io) {
        io.to('user_' + transaction.user_id).emit('tx:confirmed', {
          transactionId: data.tx_id,
          license_id: licenseId,
          currency: transaction.currency,
          amount: transaction.amount
        });
      }
      logAudit('tx:forcecomplete', 'transaction', String(data.tx_id), 'license=' + licenseId);
      return { success: true, license_id: licenseId };
    }
    db.prepare('UPDATE transactions SET status = ? WHERE id = ?').run('completed', data.tx_id);
    if (transaction.type === 'deposit' && io) {
      io.to('user_' + transaction.user_id).emit('tx:deposit_completed', {
        transactionId: data.tx_id,
        currency: transaction.currency,
        amount: transaction.amount
      });
    }
    logAudit('tx:forcecomplete', 'transaction', String(data.tx_id), null);
    return { success: true };
  },

  'tx:cancel': async (data) => {
    const transaction = db.prepare('SELECT * FROM transactions WHERE id = ?').get(data.tx_id);
    db.prepare('UPDATE transactions SET status = ? WHERE id = ? AND status = ?').run('expired', data.tx_id, 'pending');
    const io = tx.getIO();
    if (transaction && io) {
      io.to('user_' + transaction.user_id).emit('tx:expired', {
        transactionId: data.tx_id,
        currency: transaction.currency
      });
    }
    logAudit('tx:cancel', 'transaction', String(data.tx_id), null);
    return { success: true };
  },

  'tx:checkpayments': async () => {
    await tx.checkPendingPayments();
    logAudit('tx:checkpayments', 'transaction', null, null);
    return { success: true };
  },

  'tx:withdraw': async (data) => {
    try {
      const currency = data.currency.toUpperCase();
      if (!['XMR', 'LTC'].includes(currency)) return { error: 'Invalid currency' };
      const amount = parseFloat(data.amount);
      if (isNaN(amount) || amount <= 0) return { error: 'Invalid amount' };
      if (!data.address) return { error: 'Address required' };

      let result;
      if (currency === 'XMR') {
        result = await wallet.sendXMR(data.address, amount);
      } else {
        result = await wallet.sendLTC(data.address, amount);
      }
      logAudit('tx:withdraw', 'transaction', result.txHash, currency + ' ' + amount + ' -> ' + data.address);
      return { success: true, tx_hash: result.txHash, fee: result.fee };
    } catch (e) {
      return { error: e.message };
    }
  },

  'balance:info': async (data) => {
    const user = db.prepare('SELECT id FROM users WHERE account_number = ?').get(data.account_number);
    if (!user) return { error: 'User not found' };
    const balance = await tx.getUserBalance(user.id);
    logAudit('balance:info', 'user', data.account_number, null);
    return { balance };
  },

  'balance:adjust': async (data) => {
    const user = db.prepare('SELECT id FROM users WHERE account_number = ?').get(data.account_number);
    if (!user) return { error: 'User not found' };
    const amount = parseFloat(data.amount);
    if (isNaN(amount) || amount === 0) return { error: 'Invalid amount' };
    const currency = data.currency.toUpperCase();
    if (!['XMR', 'LTC'].includes(currency)) return { error: 'Invalid currency' };

    if (amount > 0) {
      db.prepare(
        "INSERT INTO transactions (user_id, type, currency, amount, address, status, usd_amount) VALUES (?, 'deposit', ?, ?, 'admin_adjust', 'completed', 0)"
      ).run(user.id, currency, Math.abs(amount));
    } else {
      db.prepare(
        "INSERT INTO transactions (user_id, type, currency, amount, address, status, usd_amount) VALUES (?, 'withdraw', ?, ?, 'admin_adjust', 'completed', 0)"
      ).run(user.id, currency, Math.abs(amount));
    }
    logAudit('balance:adjust', 'user', data.account_number, currency + ' ' + data.amount);
    return { success: true };
  },

  'status': async () => {
    const userCount = db.prepare('SELECT COUNT(*) as c FROM users').get().c;
    const licenseCount = db.prepare('SELECT COUNT(*) as c FROM licenses').get().c;
    const txCount = db.prepare('SELECT COUNT(*) as c FROM transactions').get().c;
    const pendingCount = db.prepare("SELECT COUNT(*) as c FROM transactions WHERE status = 'pending'").get().c;
    let xmrStatus = 'ok';
    let ltcStatus = 'ok';
    try { await wallet.moneroRPC('get_version'); } catch (e) { xmrStatus = 'down'; }
    try { await wallet.electrumRPC('getbalance', {}); } catch (e) { ltcStatus = 'down'; }
    const rates = await wallet.getExchangeRates();
    return {
      uptime: Math.floor(process.uptime()),
      users: userCount,
      licenses: licenseCount,
      transactions: txCount,
      pending_transactions: pendingCount,
      xmr_wallet: xmrStatus,
      ltc_wallet: ltcStatus,
      rates: rates.available ? { xmr: rates.xmr, ltc: rates.ltc } : null
    };
  },

  'stats': async () => {
    const usersToday = db.prepare("SELECT COUNT(*) as c FROM users WHERE created_at > datetime('now', '-24 hours')").get().c;
    const licensesToday = db.prepare("SELECT COUNT(*) as c FROM licenses WHERE created_at > datetime('now', '-24 hours')").get().c;
    const revenue = db.prepare("SELECT COALESCE(SUM(usd_amount), 0) as total FROM transactions WHERE status = 'completed' AND type = 'purchase' AND created_at > datetime('now', '-30 days')").get().total;
    const deposits = db.prepare("SELECT COALESCE(SUM(usd_amount), 0) as total FROM transactions WHERE status = 'completed' AND type = 'deposit' AND created_at > datetime('now', '-30 days')").get().total;
    return { users_today: usersToday, licenses_today: licensesToday, revenue_30d: revenue, deposits_30d: deposits };
  },

  'audit:list': async (data) => {
    const limit = Math.min(data.limit || 20, 100);
    const entries = db.prepare('SELECT * FROM admin_audit ORDER BY created_at DESC LIMIT ?').all(limit);
    return { entries };
  },

  'audit:search': async (data) => {
    const limit = Math.min(data.limit || 20, 100);
    let entries;
    if (data.target_type && data.target_id) {
      entries = db.prepare('SELECT * FROM admin_audit WHERE target_type = ? AND target_id = ? ORDER BY created_at DESC LIMIT ?').all(data.target_type, data.target_id, limit);
    } else if (data.target_type) {
      entries = db.prepare('SELECT * FROM admin_audit WHERE target_type = ? ORDER BY created_at DESC LIMIT ?').all(data.target_type, limit);
    } else {
      entries = db.prepare('SELECT * FROM admin_audit ORDER BY created_at DESC LIMIT ?').all(limit);
    }
    return { entries };
  },

  'wallet:balance': async (data) => {
    try {
      const currency = (data.currency || 'all').toUpperCase();
      const result = {};
      if (currency === 'XMR' || currency === 'ALL') {
        const xmrBalance = await wallet.moneroRPC('get_balance');
        result.xmr = {
          balance: xmrBalance.balance / 1e12,
          unlocked: xmrBalance.unlocked_balance / 1e12
        };
      }
      if (currency === 'LTC' || currency === 'ALL') {
        const ltcBalance = await wallet.electrumRPC('getbalance', {});
        result.ltc = {
          confirmed: ltcBalance.confirmed / 1e8,
          unmatured: (ltcBalance.mempool_uncleared || 0) / 1e8
        };
      }
      logAudit('wallet:balance', 'wallet', currency, null);
      return result;
    } catch (e) {
      return { error: e.message };
    }
  }
};

function startIPCServer() {
  cleanup();

  const server = net.createServer((socket) => {
    let buffer = '';

    socket.on('data', (chunk) => {
      buffer += chunk.toString();
      let lines = buffer.split('\n');
      buffer = lines.pop();

      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          const msg = JSON.parse(line);
          handleMessage(msg, socket);
        } catch (e) {
          socket.write(JSON.stringify({ id: 'error', error: 'Invalid JSON' }) + '\n');
        }
      }
    });

    socket.on('error', () => {});
  });

  server.listen(SOCKET_PATH, () => {
    console.log('[admin-ipc] listening on', SOCKET_PATH);
  });

  server.on('error', (err) => {
    console.error('[admin-ipc] server error:', err.message);
  });

  return server;
}

async function handleMessage(msg, socket) {
  const { id, command, data } = msg;
  const handler = handlers[command];

  if (!handler) {
    socket.write(JSON.stringify({ id, error: 'Unknown command: ' + command }) + '\n');
    return;
  }

  try {
    const result = await handler(data || {});
    const response = Object.assign({}, result, { id });
    socket.write(JSON.stringify(response) + '\n');
  } catch (e) {
    console.error('[admin-ipc] Handler error for', command, e.message);
    socket.write(JSON.stringify({ id, error: e.message }) + '\n');
  }
}

module.exports = { startIPCServer, SOCKET_PATH };
