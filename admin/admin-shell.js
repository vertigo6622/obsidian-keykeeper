const net = require('net');
const readline = require('readline');
const fs = require('fs');

const SOCKET_PATH = '/tmp/obsidian-admin.sock';
const RED = '\x1b[31m';
const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';
const CYAN = '\x1b[36m';
const GRAY = '\x1b[90m';
const BOLD = '\x1b[1m';
const RESET = '\x1b[0m';

let msgId = 0;
let pendingCallbacks = {};
let pendingConfirm = null;
let socket;
let rl;

function sendCommand(command, data) {
  return new Promise((resolve, reject) => {
    const id = String(++msgId);
    pendingCallbacks[id] = { resolve, reject };
    socket.write(JSON.stringify({ id, command, data }) + '\n');
    setTimeout(() => {
      if (pendingCallbacks[id]) {
        delete pendingCallbacks[id];
        reject(new Error('Timeout'));
      }
    }, 15000);
  });
}

function connect() {
  socket = net.createConnection(SOCKET_PATH);

  socket.on('connect', () => {
    console.log(GREEN + '  connected to keykeeper\n' + RESET);
    startREPL();
  });

  let buffer = '';
  socket.on('data', (chunk) => {
    buffer += chunk.toString();
    let lines = buffer.split('\n');
    buffer = lines.pop();
    for (const line of lines) {
      if (!line.trim()) continue;
      try {
        const msg = JSON.parse(line);
        if (msg.id && pendingCallbacks[msg.id]) {
          const cb = pendingCallbacks[msg.id];
          delete pendingCallbacks[msg.id];
          cb.resolve(msg);
        }
      } catch (e) {}
    }
  });

  socket.on('error', (err) => {
    console.error(RED + 'connection error: ' + err.message + RESET);
    console.error(YELLOW + 'make sure server.js is running' + RESET);
    process.exit(1);
  });

  socket.on('close', () => {
    console.error(RED + 'disconnected from keykeeper' + RESET);
    process.exit(1);
  });
}

function formatTS(ts) {
  if (!ts) return GRAY + 'never' + RESET;
  return GRAY + ts + RESET;
}

function formatStatus(suspended, locked_at) {
  if (locked_at) return RED + 'LOCKED' + RESET;
  if (suspended) return YELLOW + 'SUSPENDED' + RESET;
  return GREEN + 'ACTIVE' + RESET;
}

function formatLicenseStatus(expires_at) {
  if (!expires_at) return GRAY + 'none' + RESET;
  if (new Date(expires_at) < new Date()) return RED + 'EXPIRED' + RESET;
  return GREEN + 'ACTIVE' + RESET;
}

async function handleUserCreate(parts) {
  const res = await sendCommand('user:create', {});
  if (res.error) return error(res.error);
  console.log(GREEN + 'account created:' + RESET);
  console.log('  account:  ' + BOLD + res.account_number + RESET);
  console.log('  password: ' + BOLD + res.password + RESET);
}

async function handleUserInfo(parts) {
  const acct = parts[2];
  if (!acct) return console.log(YELLOW + 'usage: user info <account_number>' + RESET);
  const res = await sendCommand('user:info', { account_number: acct });
  if (res.error) return error(res.error);
  const u = res;
  console.log(BOLD + '=== user info ===' + RESET);
  console.log('  id:             ' + u.id);
  console.log('  account:        ' + u.account_number);
  console.log('  status:         ' + formatStatus(u.suspended, u.locked_at));
  console.log('  hwid:           ' + (u.hwid || GRAY + 'none' + RESET));
  console.log('  created:        ' + formatTS(u.created_at));
  console.log('  last login:     ' + formatTS(u.last_login));
  if (u.license) {
    console.log('  license type:   ' + CYAN + u.license.type + RESET);
    console.log('  license status: ' + formatLicenseStatus(u.license.expires_at));
    console.log('  license expiry: ' + formatTS(u.license.expires_at));
  }
  console.log(BOLD + '  Balances:' + RESET);
  console.log('    XMR: ' + u.balance.xmr);
  console.log('    LTC: ' + u.balance.ltc);
  console.log('    USD: $' + u.balance.usd);
}

async function handleUserSearch(parts) {
  const q = parts[2];
  if (!q) return console.log(YELLOW + 'usage: user search <query>' + RESET);
  const res = await sendCommand('user:search', { query: q });
  if (res.error) return error(res.error);
  if (!res.users.length) return console.log(GRAY + 'no users found' + RESET);
  for (const u of res.users) {
    console.log('  ' + u.account_number + '  ' + formatStatus(u.suspended, u.locked_at) + '  ' + formatTS(u.created_at));
  }
}

async function handleUserList(parts) {
  const limit = parseInt(parts[2]) || 20;
  const res = await sendCommand('user:list', { limit });
  if (res.error) return error(res.error);
  console.log(BOLD + '=== users (last ' + limit + ') ===' + RESET);
  for (const u of res.users) {
    console.log('  ' + GRAY + String(u.id).padEnd(5) + RESET + ' ' + u.account_number + '  ' + formatStatus(u.suspended, u.locked_at) + '  ' + formatTS(u.created_at));
  }
}

async function handleSuspend(parts) {
  const acct = parts[1];
  if (!acct) return console.log(YELLOW + 'usage: suspend <account_number>' + RESET);
  const res = await sendCommand('user:suspend', { account_number: acct });
  if (res.error) return error(res.error);
  console.log(GREEN + 'account ' + acct + ' suspended' + RESET);
}

async function handleUnsuspend(parts) {
  const acct = parts[1];
  if (!acct) return console.log(YELLOW + 'usage: unsuspend <account_number>' + RESET);
  const res = await sendCommand('user:unsuspend', { account_number: acct });
  if (res.error) return error(res.error);
  console.log(GREEN + 'account ' + acct + ' unsuspended' + RESET);
}

async function handleLock(parts) {
  const acct = parts[1];
  if (!acct) return console.log(YELLOW + 'usage: lock <account_number>' + RESET);
  const res = await sendCommand('user:lock', { account_number: acct });
  if (res.error) return error(res.error);
  console.log(GREEN + 'account ' + acct + ' locked' + RESET);
}

async function handleUnlock(parts) {
  const acct = parts[1];
  if (!acct) return console.log(YELLOW + 'usage: unlock <account_number>' + RESET);
  const res = await sendCommand('user:unlock', { account_number: acct });
  if (res.error) return error(res.error);
  console.log(GREEN + 'account ' + acct + ' unlocked' + RESET);
}

async function handleDelete(parts) {
  const acct = parts[1];
  if (!acct) return console.log(YELLOW + 'usage: delete <account_number>' + RESET);
  const confirmed = await confirmAction(RED + 'permanently delete account ' + acct + '? (yes/no): ' + RESET);
  if (!confirmed) return console.log(YELLOW + 'cancelled' + RESET);
  const res = await sendCommand('user:delete', { account_number: acct });
  if (res.error) return error(res.error);
  console.log(GREEN + 'account ' + acct + ' deleted' + RESET);
}

async function handleChangePassword(parts) {
  const acct = parts[2];
  const pw = parts[3];
  if (!acct || !pw) return console.log(YELLOW + 'usage: change password <account_number> <new_password>' + RESET);
  const res = await sendCommand('user:changepassword', { account_number: acct, new_password: pw });
  if (res.error) return error(res.error);
  console.log(GREEN + 'password changed for ' + acct + RESET);
}

async function handleCreateLicense(parts) {
  const userId = parts[2];
  const type = (parts[3] || '').toLowerCase();
  const duration = parseInt(parts[4]) || 6;
  if (!userId || !type) return console.log(YELLOW + 'usage: create license <user_id|account_number> <pro|commercial> [duration_months]' + RESET);
  if (!['pro', 'commercial'].includes(type)) return console.log(YELLOW + 'Type must be pro or commercial' + RESET);
  const res = await sendCommand('license:create', { user_id: userId, type, duration_months: duration });
  if (res.error) return error(res.error);
  console.log(GREEN + 'license created: ' + BOLD + res.license_id + RESET);
}

async function handleLicenseInfo(parts) {
  const lid = parts[2];
  if (!lid) return console.log(YELLOW + 'usage: license info <license_id>' + RESET);
  const res = await sendCommand('license:info', { license_id: lid });
  if (res.error) return error(res.error);
  const l = res.license;
  console.log(BOLD + '=== license info ===' + RESET);
  console.log('  id:          ' + l.license_id);
  console.log('  type:        ' + CYAN + l.type + RESET);
  console.log('  user:        ' + l.account_number + ' (id:' + l.user_id + ')');
  console.log('  status:      ' + formatLicenseStatus(l.expires_at));
  console.log('  expires:     ' + formatTS(l.expires_at));
  console.log('  created:     ' + formatTS(l.created_at));
  console.log('  hwid:        ' + (l.hwid || GRAY + 'none' + RESET));
  console.log('  last relink: ' + formatTS(l.last_relink_at));
}

async function handleLicenseList(parts) {
  const userId = parts[2];
  const limit = parseInt(parts[3]) || 20;
  const res = await sendCommand('license:list', { user_id: userId || null, limit });
  if (res.error) return error(res.error);
  if (!res.licenses.length) return console.log(GRAY + 'no licenses found' + RESET);
  console.log(BOLD + '=== licenses ===' + RESET);
  for (const l of res.licenses) {
    const acct = l.account_number || l.user_id;
    console.log('  ' + l.license_id + '  ' + CYAN + String(l.type).padEnd(11) + RESET + ' ' + formatLicenseStatus(l.expires_at) + '  ' + GRAY + acct + RESET + '  ' + formatTS(l.expires_at));
  }
}

async function handleDiscardLicense(parts) {
  const lid = parts[2];
  if (!lid) return console.log(YELLOW + 'usage: discard license <license_id>' + RESET);
  const confirmed = await confirmAction(RED + 'discard license ' + lid + '? (yes/no): ' + RESET);
  if (!confirmed) return console.log(YELLOW + 'cancelled' + RESET);
  const res = await sendCommand('license:discard', { license_id: lid });
  if (res.error) return error(res.error);
  console.log(GREEN + 'license ' + lid + ' discarded' + RESET);
}

async function handleExtendLicense(parts) {
  const lid = parts[2];
  const months = parseInt(parts[3]) || 6;
  if (!lid) return console.log(YELLOW + 'usage: extend license <license_id> [months]' + RESET);
  const res = await sendCommand('license:extend', { license_id: lid, duration_months: months });
  if (res.error) return error(res.error);
  console.log(GREEN + 'license ' + lid + ' extended by ' + months + ' months' + RESET);
}

async function handleRelinkLicense(parts) {
  const lid = parts[2];
  const hwid = parts[3];
  if (!lid || !hwid) return console.log(YELLOW + 'usage: relink license <license_id> <new_hwid>' + RESET);
  const res = await sendCommand('license:relink', { license_id: lid, new_hwid: hwid });
  if (res.error) return error(res.error);
  console.log(GREEN + 'license ' + lid + ' relinked to ' + hwid + RESET);
}

async function handleVerifyLicense(parts) {
  const lid = parts[2];
  if (!lid) return console.log(YELLOW + 'usage: verify license <license_id>' + RESET);
  const res = await sendCommand('license:verify', { license_id: lid });
  if (res.error) return error(res.error);
  console.log('  license: ' + lid);
  console.log('  valid:   ' + (res.valid ? GREEN + 'YES' : RED + 'NO') + RESET);
  console.log('  type:    ' + CYAN + res.license.type + RESET);
  console.log('  expires: ' + formatTS(res.license.expires_at));
}

async function handleTxInfo(parts) {
  const txId = parts[2];
  if (!txId) return console.log(YELLOW + 'usage: tx info <tx_id>' + RESET);
  const res = await sendCommand('tx:info', { tx_id: parseInt(txId) });
  if (res.error) return error(res.error);
  const t = res.transaction;
  console.log(BOLD + '=== transaction ===' + RESET);
  console.log('  id:         ' + t.id);
  console.log('  type:       ' + CYAN + t.type + RESET);
  console.log('  currency:   ' + t.currency);
  console.log('  amount:     ' + t.amount);
  console.log('  status:     ' + txStatusColor(t.status));
  console.log('  address:    ' + (t.address || GRAY + 'none' + RESET));
  console.log('  tx hash:    ' + (t.tx_hash || GRAY + 'none' + RESET));
  console.log('  usd:        $' + (t.usd_amount || 0));
  console.log('  user id:    ' + t.user_id);
  console.log('  license:    ' + (t.license_type || GRAY + 'none' + RESET));
  console.log('  created:    ' + formatTS(t.created_at));
  console.log('  expires:    ' + formatTS(t.expires_at));
  console.log('  confirmations: ' + (t.confirmations || 0));
}

async function handleTxList(parts) {
  const userId = parts[2];
  const status = parts[3];
  const limit = parseInt(parts[4]) || 20;
  if (userId && userId !== 'all') {
    const res = await sendCommand('tx:list', { user_id: userId, limit });
    if (res.error) return error(res.error);
    printTxList(res.transactions);
    return;
  }
  const res = await sendCommand('tx:list', { user_id: null, status: status || null, limit });
  if (res.error) return error(res.error);
  printTxList(res.transactions);
}

function printTxList(txs) {
  if (!txs.length) return console.log(GRAY + 'no transactions found' + RESET);
  console.log(BOLD + '=== transactions ===' + RESET);
  for (const t of txs) {
    const acct = t.account_number || t.user_id;
    console.log('  ' + GRAY + String(t.id).padEnd(5) + RESET + ' ' + CYAN + String(t.type).padEnd(8) + RESET + ' ' + t.currency + ' ' + String(t.amount).padEnd(12) + ' ' + txStatusColor(t.status) + '  ' + GRAY + acct + RESET + '  ' + formatTS(t.created_at));
  }
}

function txStatusColor(s) {
  if (s === 'completed') return GREEN + s + RESET;
  if (s === 'pending' || s === 'detected') return YELLOW + s + RESET;
  if (s === 'expired' || s === 'failed') return RED + s + RESET;
  return CYAN + s + RESET;
}

async function handleTxPending(parts) {
  const res = await sendCommand('tx:pending', {});
  if (res.error) return error(res.error);
  printTxList(res.transactions);
}

async function handleTxForceComplete(parts) {
  const txId = parts[2];
  if (!txId) return console.log(YELLOW + 'usage: tx force complete <tx_id>' + RESET);
  const confirmed = await confirmAction(YELLOW + 'force complete transaction ' + txId + '? (yes/no): ' + RESET);
  if (!confirmed) return console.log(YELLOW + 'cancelled' + RESET);
  const res = await sendCommand('tx:forcecomplete', { tx_id: parseInt(txId) });
  if (res.error) return error(res.error);
  console.log(GREEN + 'transaction ' + txId + ' force completed' + RESET);
  if (res.license_id) console.log(CYAN + 'license created: ' + res.license_id + RESET);
}

async function handleTxCancel(parts) {
  const txId = parts[2];
  if (!txId) return console.log(YELLOW + 'usage: tx cancel <tx_id>' + RESET);
  const res = await sendCommand('tx:cancel', { tx_id: parseInt(txId) });
  if (res.error) return error(res.error);
  console.log(GREEN + 'transaction ' + txId + ' cancelled' + RESET);
}

async function handleTxCheckPayments(parts) {
  console.log(GRAY + 'checking pending payments...' + RESET);
  const res = await sendCommand('tx:checkpayments', {});
  if (res.error) return error(res.error);
  console.log(GREEN + 'payment check complete' + RESET);
}

async function handleTxWithdraw(parts) {
  const currency = (parts[2] || '').toUpperCase();
  const amount = parts[3];
  const address = parts[4];
  if (!currency || !amount || !address) return console.log(YELLOW + 'usage: tx withdraw <xmr|ltc> <amount> <address>' + RESET);
  if (!['xmr', 'ltc'].includes(currency)) return console.log(YELLOW + 'currency must be xmr or ltc' + RESET);
  console.log(YELLOW + 'withdrawing ' + amount + ' ' + currency + ' to ' + address + RESET);
  const confirmed = await confirmAction(RED + 'confirm withdrawal? (yes/no): ' + RESET);
  if (!confirmed) return console.log(YELLOW + 'cancelled' + RESET);
  const res = await sendCommand('tx:withdraw', { currency, amount: parseFloat(amount), address });
  if (res.error) return error(res.error);
  console.log(GREEN + 'withdrawal sent!' + RESET);
  console.log('  tx hash: ' + res.tx_hash);
  if (res.fee) console.log('  fee:     ' + res.fee);
}

async function handleBalance(parts) {
  const acct = parts[1];
  if (!acct) return console.log(YELLOW + 'usage: balance <account_number>' + RESET);
  const res = await sendCommand('balance:info', { account_number: acct });
  if (res.error) return error(res.error);
  console.log(BOLD + '=== balance for ' + acct + ' ===' + RESET);
  console.log('  XMR: ' + res.balance.xmr);
  console.log('  LTC: ' + res.balance.ltc);
  console.log('  USD: $' + res.balance.usd);
}

async function handleAdjustBalance(parts) {
  const acct = parts[2];
  const currency = (parts[3] || '').toUpperCase();
  const amount = parts[4];
  if (!acct || !currency || !amount) return console.log(YELLOW + 'Usage: adjust balance <account_number> <XMR|LTC> <amount>' + RESET);
  if (!['XMR', 'LTC'].includes(currency)) return console.log(YELLOW + 'Currency must be XMR or LTC' + RESET);
  console.log(YELLOW + 'Adjusting ' + acct + ' ' + currency + ' by ' + amount + RESET);
  const confirmed = await confirmAction('confirm? (yes/no): ');
  if (!confirmed) return console.log(YELLOW + 'Cancelled' + RESET);
  const res = await sendCommand('balance:adjust', { account_number: acct, currency, amount: parseFloat(amount) });
  if (res.error) return error(res.error);
  console.log(GREEN + 'Balance adjusted' + RESET);
}

async function handleStatus(parts) {
  const res = await sendCommand('status', {});
  if (res.error) return error(res.error);
  console.log(BOLD + '=== system status ===' + RESET);
  console.log('  uptime:     ' + Math.floor(res.uptime / 3600) + 'h ' + Math.floor((res.uptime % 3600) / 60) + 'm');
  console.log('  users:      ' + res.users);
  console.log('  licenses:   ' + res.licenses);
  console.log('  tx total:   ' + res.transactions);
  console.log('  pending tx: ' + YELLOW + res.pending_transactions + RESET);
  console.log('  xmr wallet: ' + (res.xmr_wallet === 'ok' ? GREEN : RED) + res.xmr_wallet + RESET);
  console.log('  ltc wallet: ' + (res.ltc_wallet === 'ok' ? GREEN : RED) + res.ltc_wallet + RESET);
  if (res.rates) {
    console.log('  xmr rate:   $' + res.rates.xmr);
    console.log('  ltc rate:   $' + res.rates.ltc);
  }
}

async function handleStats(parts) {
  const res = await sendCommand('stats', {});
  if (res.error) return error(res.error);
  console.log(BOLD + '=== stats (24h / 30d) ===' + RESET);
  console.log('  new users (24h):    ' + res.users_today);
  console.log('  new licenses (24h): ' + res.licenses_today);
  console.log('  revenue (30d):      $' + res.revenue_30d);
  console.log('  deposits (30d):     $' + res.deposits_30d);
}

async function handleAuditList(parts) {
  const limit = parseInt(parts[2]) || 20;
  const res = await sendCommand('audit:list', { limit });
  if (res.error) return error(res.error);
  if (!res.entries.length) return console.log(GRAY + 'No audit entries' + RESET);
  console.log(BOLD + '=== Audit Log ===' + RESET);
  for (const e of res.entries) {
    console.log('  ' + GRAY + e.created_at + RESET + ' ' + CYAN + e.action_type.padEnd(22) + RESET + ' ' + (e.target_type || '').padEnd(8) + ' ' + (e.target_id || '').padEnd(15) + ' ' + GRAY + (e.details || '') + RESET);
  }
}

async function handleAuditSearch(parts) {
  const targetType = parts[2];
  const targetId = parts[3];
  const limit = parseInt(parts[4]) || 20;
  if (!targetType) return console.log(YELLOW + 'Usage: audit search <target_type> [target_id] [limit]' + RESET);
  const res = await sendCommand('audit:search', { target_type: targetType, target_id: targetId || null, limit });
  if (res.error) return error(res.error);
  if (!res.entries.length) return console.log(GRAY + 'No matching entries' + RESET);
  for (const e of res.entries) {
    console.log('  ' + GRAY + e.created_at + RESET + ' ' + CYAN + e.action_type.padEnd(22) + RESET + ' ' + (e.target_type || '').padEnd(8) + ' ' + (e.target_id || '').padEnd(15) + ' ' + GRAY + (e.details || '') + RESET);
  }
}

async function handleWalletBalance(parts) {
  const currency = (parts[2] || 'all').toUpperCase();
  if (!['XMR', 'LTC', 'ALL'].includes(currency)) return console.log(YELLOW + 'usage: wallet balance [XMR|LTC|all]' + RESET);
  const res = await sendCommand('wallet:balance', { currency: currency === 'ALL' ? 'all' : currency });
  if (res.error) return error(res.error);
  console.log(BOLD + '=== Wallet Balances ===' + RESET);
  if (res.xmr) {
    console.log('  XMR Balance:  ' + res.xmr.balance);
    console.log('  XMR Unlocked: ' + res.xmr.unlocked);
  }
  if (res.ltc) {
    console.log('  LTC Confirmed: ' + res.ltc.confirmed);
    if (res.ltc.unmatured) console.log('  LTC Unmatured: ' + res.ltc.unmatured);
  }
}

function error(msg) {
  console.error(RED + 'Error: ' + msg + RESET);
}

function confirmAction(prompt) {
  return new Promise((resolve) => {
    pendingConfirm = resolve;
    rl.setPrompt(prompt);
    rl.prompt();
  });
}

function printHelp(parts) {
  if (parts[1]) {
    const cmd = parts[1];
    const helpText = {
      'user':       'user info <account_number>\n  user search <query>\n  user list [limit]\n  user delete <account_number>',
      'create':     'create account\n  create license <user_id|account_number> <pro|commercial> [duration_months]',
      'suspend':    'suspend <account_number>',
      'unsuspend':  'unsuspend <account_number>',
      'lock':       'lock <account_number>',
      'unlock':     'unlock <account_number>',
      'delete':     'delete <account_number>',
      'change':     'change password <account_number> <new_password>',
      'license':    'license info <license_id>\n  license list [user_id|all] [limit]\n  license discard <license_id>\n  license extend <license_id> [months]\n  license relink <license_id> <new_hwid>\n  license verify <license_id>',
      'discard':    'discard license <license_id>',
      'extend':     'extend license <license_id> [months]',
      'relink':     'relink license <license_id> <new_hwid>',
      'verify':     'verify license <license_id>',
      'tx':         'tx info <tx_id>\n  tx list [user_id|all] [status] [limit]\n  tx pending\n  tx force complete <tx_id>\n  tx cancel <tx_id>\n  tx check payments\n  tx withdraw <XMR|LTC> <amount> <address>',
      'balance':    'balance <account_number>',
      'adjust':     'adjust balance <account_number> <XMR|LTC> <amount>',
      'status':     'status',
      'stats':      'stats',
      'audit':      'audit list [limit]\n  audit search <target_type> [target_id] [limit]',
      'wallet':     'wallet balance [XMR|LTC|all]',
    };
    if (helpText[cmd]) {
      console.log(CYAN + cmd + ':\n' + RESET + helpText[cmd]);
    } else {
      console.log(YELLOW + 'No help for: ' + cmd + RESET);
    }
    return;
  }
  console.log(BOLD + '\n=== obsidian admin shell ===\n' + RESET);
  console.log(CYAN + 'user management:' + RESET);
  console.log('  user info <account_number>        user details & balance');
  console.log('  user search <query>               search users');
  console.log('  user list [limit]                  list recent users');
  console.log('  create account                     generate new account');
  console.log('  suspend <account_number>           suspend account');
  console.log('  unsuspend <account_number>         unsuspend account');
  console.log('  lock <account_number>              lock account');
  console.log('  unlock <account_number>            unlock account');
  console.log('  delete <account_number>            delete account');
  console.log('  change password <acct> <pw>        force password change');
  console.log();
  console.log(CYAN + 'license management:' + RESET);
  console.log('  create license <user> <type> [mo]  create license');
  console.log('  license info <license_id>          license details');
  console.log('  license list [user|all] [limit]    list licenses');
  console.log('  discard license <license_id>       discard license');
  console.log('  extend license <license_id> [mo]   extend license');
  console.log('  relink license <id> <new_hwid>     force HWID relink');
  console.log('  verify license <license_id>        check license validity');
  console.log();
  console.log(CYAN + 'transaction management:' + RESET);
  console.log('  tx info <tx_id>                    transaction details');
  console.log('  tx list [user|all] [status] [lim]  list transactions');
  console.log('  tx pending                         show pending TX');
  console.log('  tx force complete <tx_id>          force complete TX');
  console.log('  tx cancel <tx_id>                  cancel pending TX');
  console.log('  tx check payments                  check pending payments');
  console.log('  tx withdraw <XMR|LTC> <amt> <addr> withdraw to wallet');
  console.log();
  console.log(CYAN + 'balances:' + RESET);
  console.log('  balance <account_number>           show user balance');
  console.log('  adjust balance <acct> <cur> <amt>  adjust user balance');
  console.log();
  console.log(CYAN + 'system:' + RESET);
  console.log('  status                             system status');
  console.log('  stats                              statistics');
  console.log('  wallet balance [XMR|LTC|all]       server wallet balances');
  console.log('  audit list [limit]                 ciew audit log');
  console.log('  audit search <type> [id] [limit]   search audit log');
  console.log();
  console.log(GRAY + '  help [command]    clear    exit' + RESET);
  console.log();
}

function processCommand(line) {
  const trimmed = line.trim();
  if (!trimmed) return;

  const parts = trimmed.split(/\s+/);
  const cmd = parts[0].toLowerCase();

  switch (cmd) {
    case 'user':
      if (parts[1] === 'info') return handleUserInfo(parts);
      if (parts[1] === 'search') return handleUserSearch(parts);
      if (parts[1] === 'list') return handleUserList(parts);
      if (parts[1] === 'delete') return handleDelete(parts);
      console.log(YELLOW + 'usage: user info|search|list|delete' + RESET);
      return;
    case 'create':
      if (parts[1] === 'account') return handleUserCreate(parts);
      if (parts[1] === 'license') return handleCreateLicense(parts);
      console.log(YELLOW + 'usage: create account | create license ...' + RESET);
      return;
    case 'suspend': return handleSuspend(parts);
    case 'unsuspend': return handleUnsuspend(parts);
    case 'lock': return handleLock(parts);
    case 'unlock': return handleUnlock(parts);
    case 'delete': return handleDelete(parts);
    case 'change':
      if (parts[1] === 'password') return handleChangePassword(parts);
      console.log(YELLOW + 'usage: change password <account_number> <new_password>' + RESET);
      return;
    case 'license':
      if (parts[1] === 'info') return handleLicenseInfo(parts);
      if (parts[1] === 'list') return handleLicenseList(parts);
      if (parts[1] === 'discard') return handleDiscardLicense(parts);
      if (parts[1] === 'extend') return handleExtendLicense(parts);
      if (parts[1] === 'relink') return handleRelinkLicense(parts);
      if (parts[1] === 'verify') return handleVerifyLicense(parts);
      console.log(YELLOW + 'usage: license info|list|discard|extend|relink|verify' + RESET);
      return;
    case 'discard':
      if (parts[1] === 'license') return handleDiscardLicense(parts);
      console.log(YELLOW + 'usage: discard license <license_id>' + RESET);
      return;
    case 'extend':
      if (parts[1] === 'license') return handleExtendLicense(parts);
      console.log(YELLOW + 'usage: extend license <license_id> [months]' + RESET);
      return;
    case 'relink':
      if (parts[1] === 'license') return handleRelinkLicense(parts);
      console.log(YELLOW + 'usage: relink license <license_id> <new_hwid>' + RESET);
      return;
    case 'verify':
      if (parts[1] === 'license') return handleVerifyLicense(parts);
      console.log(YELLOW + 'usage: verify license <license_id>' + RESET);
      return;
    case 'tx':
      if (parts[1] === 'info') return handleTxInfo(parts);
      if (parts[1] === 'list') return handleTxList(parts);
      if (parts[1] === 'pending') return handleTxPending(parts);
      if (parts[1] === 'force' && parts[2] === 'complete') return handleTxForceComplete(parts);
      if (parts[1] === 'cancel') return handleTxCancel(parts);
      if (parts[1] === 'check') return handleTxCheckPayments(parts);
      if (parts[1] === 'withdraw') return handleTxWithdraw(parts);
      console.log(YELLOW + 'Usage: tx info|list|pending|force complete|cancel|check payments|withdraw' + RESET);
      return;
    case 'balance':
      return handleBalance(parts);
    case 'adjust':
      if (parts[1] === 'balance') return handleAdjustBalance(parts);
      console.log(YELLOW + 'Usage: adjust balance <account_number> <XMR|LTC> <amount>' + RESET);
      return;
    case 'status': return handleStatus(parts);
    case 'stats': return handleStats(parts);
    case 'wallet':
      if (parts[1] === 'balance') return handleWalletBalance(parts);
      console.log(YELLOW + 'Usage: wallet balance [XMR|LTC|all]' + RESET);
      return;
    case 'audit':
      if (parts[1] === 'list') return handleAuditList(parts);
      if (parts[1] === 'search') return handleAuditSearch(parts);
      console.log(YELLOW + 'Usage: audit list|search' + RESET);
      return;
    case 'help': printHelp(parts); return;
    case 'clear': console.clear(); return;
    case 'exit':
    case 'quit':
      console.log(GRAY + 'goodbye' + RESET);
      socket.destroy();
      process.exit(0);
    default:
      console.log(YELLOW + 'unknown command: ' + cmd + RESET);
  }
}

function startREPL() {
  rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    prompt: BOLD + 'keykeeper> ' + RESET,
    completer: (line) => {
      const cmds = [
        'user info ', 'user search ', 'user list ', 'user delete ',
        'create account', 'create license ',
        'suspend ', 'unsuspend ', 'lock ', 'unlock ', 'delete ',
        'change password ',
        'license info ', 'license list ', 'license discard ', 'license extend ', 'license relink ', 'license verify ',
        'discard license ', 'extend license ', 'relink license ', 'verify license ',
        'tx info ', 'tx list ', 'tx pending', 'tx force complete ', 'tx cancel ', 'tx check payments', 'tx withdraw ',
        'balance ', 'adjust balance ',
        'status', 'stats', 'wallet balance ',
        'audit list ', 'audit search ',
        'help', 'clear', 'exit'
      ];
      const hits = cmds.filter(c => c.startsWith(line));
      return [hits.length ? hits : cmds, line];
    }
  });

  rl.prompt();

  rl.on('line', async (line) => {
    if (pendingConfirm) {
      const answer = line.trim().toLowerCase();
      const cb = pendingConfirm;
      pendingConfirm = null;
      rl.setPrompt(BOLD + 'keykeeper> ' + RESET);
      cb(answer === 'yes' || answer === 'y');
      rl.prompt();
      return;
    }

    try {
      await processCommand(line);
    } catch (e) {
      error(e.message);
    }
    rl.prompt();
  });

  rl.on('close', () => {
    socket.destroy();
    process.exit(0);
  });
}

console.log(BOLD + CYAN + '\n  ╔══════════════════════════════════╗' + RESET);
console.log(BOLD + CYAN + '  ║   keykeeper admin shell v1.0     ║' + RESET);
console.log(BOLD + CYAN + '  ╚══════════════════════════════════╝' + RESET);
console.log(GRAY + '  type "help" for commands' + RESET);

connect();
