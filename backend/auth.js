const db = require('./database');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const validate = require('./validate');

const RATE_LIMIT_HOURS = 1;
const REGISTRATION_RATE_LIMIT = 5;
const LOGIN_RATE_LIMIT = 30;
const FAILED_ATTEMPTS_LIMIT = 5;
const SPECK_ROUNDS = 34;

function rol64(x, r) {
  return ((x << r) | (x >> (64n - r))) & 0xFFFFFFFFFFFFFFFFn;
}

function ror64(x, r) {
  return ((x >> r) | (x << (64n - r))) & 0xFFFFFFFFFFFFFFFFn;
}

function speckRound(x, y, k) {
  x = ror64(x, 8n);
  x = (x + y) & 0xFFFFFFFFFFFFFFFFn;
  x = x ^ k;
  y = rol64(y, 3n);
  y = y ^ x;
  return [x, y];
}

function speckKeySchedule(key) {
  const roundKeys = new Array(SPECK_ROUNDS);
  let b = key[1];
  roundKeys[0] = key[0];
  
  for (let i = 0; i < SPECK_ROUNDS - 1; i++) {
    b = (ror64(b, 8n) + roundKeys[i]) & 0xFFFFFFFFFFFFFFFFn;
    b = (b ^ BigInt(i)) & 0xFFFFFFFFFFFFFFFFn;
    roundKeys[i + 1] = (rol64(roundKeys[i], 3n) ^ b) & 0xFFFFFFFFFFFFFFFFn;
  }
  
  return roundKeys;
}

function speckEncryptBlock(x, y, roundKeys) {
  for (let i = 0; i < SPECK_ROUNDS; i++) {
    x = (ror64(x, 8n) + y) & 0xFFFFFFFFFFFFFFFFn;
    x = (x ^ roundKeys[i]) & 0xFFFFFFFFFFFFFFFFn;
    y = (rol64(y, 3n) ^ x) & 0xFFFFFFFFFFFFFFFFn;
  }
  return [x, y];
}

function speckCbcMac(data, keyHex) {
  const keyBuffer = Buffer.from(keyHex, 'hex');
  if (keyBuffer.length !== 16) {
    throw new Error('Invalid key length for SPECK-128');
  }
  
  const key = [
    keyBuffer.readBigUInt64LE(0),
    keyBuffer.readBigUInt64LE(8)
  ];
  
  const roundKeys = speckKeySchedule(key);
  
  const dataBuffer = Buffer.isBuffer(data) ? data : Buffer.from(data);
  
  let chain0 = 0n;
  let chain1 = 0n;
  
  const fullBlocks = Math.floor(dataBuffer.length / 16);
  
  for (let i = 0; i < fullBlocks; i++) {
    let block0 = dataBuffer.readBigUInt64LE(i * 16);
    let block1 = dataBuffer.readBigUInt64LE(i * 16 + 8);
    
    block0 = (block0 ^ chain0) & 0xFFFFFFFFFFFFFFFFn;
    block1 = (block1 ^ chain1) & 0xFFFFFFFFFFFFFFFFn;
    
    [chain0, chain1] = speckEncryptBlock(block0, block1, roundKeys);
  }
  
  const remaining = dataBuffer.length % 16;
  if (remaining > 0) {
    const lastBlock = Buffer.alloc(16);
    dataBuffer.copy(lastBlock, 0, fullBlocks * 16);
    let block0 = lastBlock.readBigUInt64LE(0);
    let block1 = lastBlock.readBigUInt64LE(8);
    
    block0 = (block0 ^ chain0) & 0xFFFFFFFFFFFFFFFFn;
    block1 = (block1 ^ chain1) & 0xFFFFFFFFFFFFFFFFn;
    
    [chain0, chain1] = speckEncryptBlock(block0, block1, roundKeys);
  }
  
  return [chain0, chain1];
}

function verifyHwidIntegrity(licenseId, sum, cpu, disk, mac, ram, tpm, callback) {
  try {
    const license = getLicenseById(licenseId);
    if (!license || !license.stub_mac) {
      return callback({ valid: false, error: 'License not found' });
    }
    
    if (new Date(license.expires_at) < new Date()) {
      return callback({ valid: false, error: 'License expired' });
    }
    
    const cpuStr = cpu ? cpu.slice(0, 16).padEnd(16, '\0') : '';
    const diskStr = disk ? disk.slice(0, 16).padEnd(16, '\0') : '';
    const macStr = mac ? mac.slice(0, 16).padEnd(16, '\0') : '';
    const ramStr = ram ? ram.slice(0, 16).padEnd(16, '\0') : '';
    const tpmStr = tpm ? tpm.slice(0, 16).padEnd(16, '\0') : '';
    
    const data = Buffer.alloc(96);
    
    const stubMacBuf = Buffer.from(license.stub_mac, 'hex');
    stubMacBuf.copy(data, 0, 0, 16);
    
    Buffer.from(cpuStr, 'utf8').copy(data, 16, 0, 16);
    Buffer.from(diskStr, 'utf8').copy(data, 32, 0, 16);
    Buffer.from(macStr, 'utf8').copy(data, 48, 0, 16);
    Buffer.from(ramStr, 'utf8').copy(data, 64, 0, 16);
    Buffer.from(tpmStr, 'utf8').copy(data, 80, 0, 16);
    
    const keyHex = license.stub_mac;
    const [computed0, computed1] = speckCbcMac(data, keyHex);
    
    const computedMac = Buffer.alloc(16);
    computedMac.writeBigUInt64LE(computed0, 0);
    computedMac.writeBigUInt64LE(computed1, 8);
    
    const expectedMac = Buffer.from(sum, 'hex');
    const databaseHwid = license.hwid;
    
    const valid1 = crypto.timingSafeEqual(computedMac, expectedMac);
    const valid2 = crypto.timingSafeEqual(expectedMac, databaseHwid);
    const valid3 = crypto.timingSafeEqual(computedMac, databaseHwid);

    if (!valid1 || !valid2 || !valid3) {
      return callback({ valid: false, error: 'Hardware ID integrity check failed' });
    } else {
      return callback({ valid: true, type: license.type });
    }
  } catch (e) {
    console.error('HWID verification error:', e.message);
    return callback({ valid: false, error: 'Verification failed' });
  }
}

function generateAccountNumber() {
  const maxAttempts = 10;
  for (let i = 0; i < maxAttempts; i++) {
    const bytes = crypto.randomBytes(12);
    let result = '';
    for (let j = 0; j < 12; j++) {
      result += String(bytes[j] % 10);
    }
    if (result[0] === '0') {
      result = String(Math.floor(Math.random() * 9) + 1) + result.slice(1);
    }
    const existing = db.prepare('SELECT id FROM users WHERE account_number = ?').get(result);
    if (!existing) {
      return result;
    }
  }
  throw new Error('Failed to generate unique account number after ' + maxAttempts + ' attempts');
}

function generateLicenseId() {
  const bytes = crypto.randomBytes(32);
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  
  const getChunk = (offset, len) => {
    let val = 0n;
    for (let i = 0; i < len; i++) {
      val = (val << 6n) | BigInt(bytes.readUInt8(offset + i) % 64);
    }
    
    let result = '';
    for (let i = 0; i < len; i++) {
      result += chars.charAt(Number((val >> BigInt(i * 5)) & 0x1fn));
    }
    return result;
  };
  
  return getChunk(0, 8) + '-' + getChunk(8, 4) + '-' + getChunk(12, 4) + '-' + getChunk(16, 4) + '-' + getChunk(20, 12);
}

function getUserByAccountNumber(accountNumber) {
  const stmt = db.prepare(`SELECT id, account_number, password_hash, hwid, created_at, last_login FROM users WHERE account_number = ?`);
  return stmt.get(accountNumber);
}

function isRateLimited(ip) {
  const stmt = db.prepare(`
    SELECT COUNT(*) as count FROM register_rate_limit 
    WHERE ip = ? AND attempted_at > datetime('now', '-${RATE_LIMIT_HOURS} hour')
  `);
  const result = stmt.get(ip);
  return result.count >= REGISTRATION_RATE_LIMIT;
}

function addRateLimitEntry(ip) {
  const stmt = db.prepare(`INSERT INTO register_rate_limit (ip) VALUES (?)`);
  stmt.run(ip);
}

function isLoginRateLimited(ip) {
  const stmt = db.prepare(`
    SELECT COUNT(*) as count FROM login_rate_limit 
    WHERE ip = ? AND attempted_at > datetime('now', '-1 hour')
  `);
  const result = stmt.get(ip);
  return result.count >= LOGIN_RATE_LIMIT;
}

function addLoginAttempt(ip) {
  const stmt = db.prepare(`INSERT INTO login_rate_limit (ip) VALUES (?)`);
  stmt.run(ip);
}

function getFailedLoginAttempts(userId) {
  const stmt = db.prepare(`
    SELECT COUNT(*) as count FROM login_failures 
    WHERE user_id = ? AND attempted_at > datetime('now', '-1 hour')
  `);
  const result = stmt.get(userId);
  return result.count;
}

function addFailedLoginAttempt(userId, ip) {
  const stmt = db.prepare(`INSERT INTO login_failures (user_id, ip) VALUES (?, ?)`);
  stmt.run(userId, ip);
  
  const attempts = getFailedLoginAttempts(userId);
  if (attempts >= FAILED_ATTEMPTS_LIMIT) {
    lockAccount(userId);
  }
}

function clearFailedLoginAttempts(userId) {
  const stmt = db.prepare(`DELETE FROM login_failures WHERE user_id = ?`);
  stmt.run(userId);
}

function isAccountLocked(userId) {
  const stmt = db.prepare(`SELECT locked_at FROM users WHERE id = ?`);
  const user = stmt.get(userId);
  return user && user.locked_at !== null;
}

function lockAccount(userId) {
  const stmt = db.prepare(`UPDATE users SET locked_at = datetime('now') WHERE id = ?`);
  stmt.run(userId);
}

function unlockAccount(userId) {
  const stmt = db.prepare(`UPDATE users SET locked_at = NULL WHERE id = ?`);
  stmt.run(userId);
  clearFailedLoginAttempts(userId);
}

function isAccountSuspended(userId) {
  const stmt = db.prepare(`SELECT suspended FROM users WHERE id = ?`);
  const user = stmt.get(userId);
  return user && user.suspended === 1;
}

function suspendAccount(userId) {
  const stmt = db.prepare(`UPDATE users SET suspended = 1 WHERE id = ?`);
  stmt.run(userId);
}

async function hashPassword(password) {
  return bcrypt.hash(password, 10);
}

async function verifyPassword(password, hash) {
  return bcrypt.compare(password, hash);
}

function getUserById(id) {
  const stmt = db.prepare(`SELECT id, account_number, hwid, created_at, last_login FROM users WHERE id = ?`);
  return stmt.get(id);
}

function createUser(passwordHash, hwid = null) {
  const accountNumber = generateAccountNumber();
  const stmt = db.prepare(`
    INSERT INTO users (password_hash, account_number, hwid)
    VALUES (?, ?, ?)
  `);
  const result = stmt.run(passwordHash, accountNumber, hwid);
  return { id: result.lastInsertRowid, accountNumber };
}

function updateLastLogin(userId) {
  const stmt = db.prepare(`UPDATE users SET last_login = datetime('now') WHERE id = ?`);
  stmt.run(userId);
}

function getLicenseByUserId(userId) {
  const stmt = db.prepare(`
    SELECT license_id, type, expires_at FROM licenses 
    WHERE user_id = ? ORDER BY created_at DESC LIMIT 1
  `);
  return stmt.get(userId);
}

function getLicenseById(licenseId) {
  const stmt = db.prepare(`
    SELECT l.license_id, l.type, l.expires_at, l.user_id, l.hwid as license_hwid, l.stub_mac, l.integrity, u.account_number, u.hwid as user_hwid, u.speck_key
    FROM licenses l
    JOIN users u ON l.user_id = u.id
    WHERE l.license_id = ?
  `);
  return stmt.get(licenseId);
}

function createLicense(userId, type, hwid, stubMac) {
  const licenseId = generateLicenseId();
  const stmt = db.prepare(`
    INSERT INTO licenses (license_id, user_id, type, hwid, stub_mac, expires_at)
    VALUES (?, ?, ?, ?, ?, datetime('now', '+6 months'))
  `);
  stmt.run(licenseId, userId, type, hwid, stubMac);
  return licenseId;
}

function canRelink(licenseId) {
  const stmt = db.prepare(`
    SELECT last_relink_at FROM licenses WHERE license_id = ?
  `);
  const license = stmt.get(licenseId);
  if (!license) return false;
  if (!license.last_relink_at) return true;
  
  const relinkDate = new Date(license.last_relink_at);
  const now = new Date();
  const monthsDiff = (now - relinkDate) / (1000 * 60 * 60 * 24 * 30);
  return monthsDiff >= 1;
}

function relinkLicense(licenseId, newHwid) {
  if (!canRelink(licenseId)) {
    return { success: false, error: 'Can only relink once per month' };
  }
  const stmt = db.prepare(`
    UPDATE licenses SET hwid = ?, last_relink_at = datetime('now') WHERE license_id = ?
  `);
  stmt.run(newHwid, licenseId);
  return { success: true };
}

function updateLicenseDownloadFilename(licenseId, filename) {
  const stmt = db.prepare(`UPDATE licenses SET download_filename = ? WHERE license_id = ?`);
  stmt.run(filename, licenseId);
}

function updateLicenseStubMac(licenseId, stubMac) {
  const stmt = db.prepare(`UPDATE licenses SET stub_mac = ? WHERE license_id = ?`);
  stmt.run(stubMac, licenseId);
}

function updateLicenseHwid(licenseId, hwid) {
  const stmt = db.prepare(`UPDATE licenses SET hwid = ? WHERE license_id = ?`);
  stmt.run(hwid, licenseId);
}

function updateLicenseIntegrity(licenseId, integrity) {
  const stmt = db.prepare(`UPDATE licenses SET integrity = ? WHERE license_id = ?`);
  stmt.run(integrity, licenseId);
}

function logProductVerification(licenseId, ip, success) {
  const stmt = db.prepare(`
    INSERT INTO product_verifications (license_id, ip, success) VALUES (?, ?, ?)
  `);
  stmt.run(licenseId, ip, success ? 1 : 0);
}

async function changePassword(userId, oldPassword, newPassword) {
  const user = getUserById(userId);
  if (!user) return { success: false, error: 'User not found' };
  
  const userWithHash = db.prepare(`SELECT password_hash FROM users WHERE id = ?`).get(userId);
  const valid = await bcrypt.compare(oldPassword, userWithHash.password_hash);
  if (!valid) return { success: false, error: 'Invalid password' };
  
  const newHash = bcrypt.hash(newPassword, 10);
  db.prepare(`UPDATE users SET password_hash = ? WHERE id = ?`).run(newHash, userId);
  return { success: true };
}

async function deleteAccount(userId, password) {
  const userWithHash = db.prepare(`SELECT password_hash FROM users WHERE id = ?`).get(userId);
  const valid = await bcrypt.compare(password, userWithHash.password_hash);
  if (!valid) return { success: false, error: 'Invalid password' };
  
  db.prepare(`DELETE FROM transactions WHERE user_id = ?`).run(userId);
  db.prepare(`DELETE FROM licenses WHERE user_id = ?`).run(userId);
  db.prepare(`DELETE FROM sessions WHERE user_id = ?`).run(userId);
  db.prepare(`DELETE FROM users WHERE id = ?`).run(userId);
  
  return { success: true };
}

function getUserSessions(userId) {
  const sessions = db.prepare(`
    SELECT sid, ip, user_agent, created_at FROM sessions 
    WHERE user_id = ? AND expired > datetime('now')
    ORDER BY created_at DESC
  `).all(userId);
  return sessions;
}

function cleanupOldSessions() {
  db.prepare(`DELETE FROM sessions WHERE expired < datetime('now', '-7 days')`).run();
}

function getSpeckKey(userId) {
  const stmt = db.prepare(`SELECT speck_key FROM users WHERE id = ?`);
  const user = stmt.get(userId);
  return user ? user.speck_key : null;
}

function updateUserSpeckKey(userId, key) {
  const stmt = db.prepare(`UPDATE users SET speck_key = ? WHERE id = ?`);
  stmt.run(key, userId);
}

function computeHwidFromMachineInfo(machineInfo, license) {
  if (!license.integrity || !license.stub_mac) {
    console.error('Missing integrity or stub_mac in license');
    return null;
  }
  
  const data = Buffer.alloc(96);
  
  const fields = [
    machineInfo.cpu_serial,
    machineInfo.disk_serial,
    machineInfo.mac_address,
    machineInfo.ram_serial,
    machineInfo.tpm_ek
  ];
  
  let offset = 16;
  for (const field of fields) {
    const fieldData = field || '';
    const fieldBuffer = Buffer.from(fieldData, 'utf8');
    fieldBuffer.copy(data, offset);
    offset += 16;
  }
  
  try {
    const keyHex = license.stub_mac;
    const [mac0, mac1] = speckCbcMac(data, keyHex);
    const macBuffer = Buffer.alloc(16);
    macBuffer.writeBigUInt64LE(mac0, 0);
    macBuffer.writeBigUInt64LE(mac1, 8);
    return macBuffer.toString('hex');
  } catch (e) {
    console.error('HWID computation error:', e.message);
    return null;
  }
}

function getUserByLicenseId(licenseId) {
  const stmt = db.prepare(`
    SELECT u.id, u.account_number, u.speck_key 
    FROM users u
    JOIN licenses l ON u.id = l.user_id
    WHERE l.license_id = ?
  `);
  return stmt.get(licenseId);
}

module.exports = {
  isRateLimited,
  addRateLimitEntry,
  isLoginRateLimited,
  addLoginAttempt,
  getFailedLoginAttempts,
  addFailedLoginAttempt,
  clearFailedLoginAttempts,
  isAccountLocked,
  hashPassword,
  verifyPassword,
  getUserById,
  createUser,
  updateLastLogin,
  getLicenseByUserId,
  getLicenseById,
  generateLicenseId,
  createLicense,
  canRelink,
  relinkLicense,
  logProductVerification,
  changePassword,
  deleteAccount,
  getUserSessions,
  cleanupOldSessions,
  verifyHwidIntegrity,
  getSpeckKey,
  updateUserSpeckKey,
  computeHwidFromMachineInfo,
  getUserByLicenseId,
  getUserByAccountNumber,
  isRelinkRateLimited,
  addRelinkAttempt,
  updateLicenseDownloadFilename,
  updateLicenseStubMac,
  updateLicenseHwid,
  updateLicenseIntegrity,
  isTxCreateRateLimited,
  addTxCreateAttempt,
  cleanupOldTxCreateRateLimits,
  isAccountSuspended,
  suspendAccount,
  isHwidVerifyRateLimited,
  addHwidVerifyAttempt,
  cleanupOldHwidVerifyRateLimits,
  isWithdrawRateLimited,
  addWithdrawAttempt,
  cleanupOldWithdrawRateLimits,
  getAccountStanding,
  generateAuthToken,
  validateAuthToken
};

const RELINK_RATE_LIMIT = 10;

function isRelinkRateLimited(ip) {
  const stmt = db.prepare(`
    SELECT COUNT(*) as count FROM relink_rate_limit 
    WHERE ip = ? AND attempted_at > datetime('now', '-1 hour')
  `);
  const result = stmt.get(ip);
  return result.count >= RELINK_RATE_LIMIT;
}

function addRelinkAttempt(ip) {
  const stmt = db.prepare(`INSERT INTO relink_rate_limit (ip) VALUES (?)`);
  stmt.run(ip);
}

const TX_CREATE_RATE_LIMIT = 1;

function isTxCreateRateLimited(userId, ip) {
  const stmt = db.prepare(`
    SELECT COUNT(*) as count FROM tx_create_rate_limit 
    WHERE (user_id = ? OR ip = ?) AND attempted_at > datetime('now', '-1 hour')
  `);
  const result = stmt.get(userId, ip);
  return result.count >= TX_CREATE_RATE_LIMIT;
}

function addTxCreateAttempt(userId, ip) {
  const stmt = db.prepare(`INSERT INTO tx_create_rate_limit (user_id, ip) VALUES (?, ?)`);
  stmt.run(userId, ip);
}

function cleanupOldTxCreateRateLimits() {
  db.prepare(`DELETE FROM tx_create_rate_limit WHERE attempted_at < datetime('now', '-1 hour')`).run();
}

const HWID_VERIFY_RATE_LIMIT = 100;

function isHwidVerifyRateLimited(userId, ip) {
  const stmt = db.prepare(`
    SELECT COUNT(*) as count FROM hwid_verify_rate_limit 
    WHERE (user_id = ? OR ip = ?) AND attempted_at > datetime('now', '-1 hour')
  `);
  const result = stmt.get(userId, ip);
  return result.count >= HWID_VERIFY_RATE_LIMIT;
}

function addHwidVerifyAttempt(userId, ip) {
  const stmt = db.prepare(`INSERT INTO hwid_verify_rate_limit (user_id, ip) VALUES (?, ?)`);
  stmt.run(userId, ip);
}

function cleanupOldHwidVerifyRateLimits() {
  db.prepare(`DELETE FROM hwid_verify_rate_limit WHERE attempted_at < datetime('now', '-1 hour')`).run();
}

const WITHDRAW_RATE_LIMIT = 5;

function isWithdrawRateLimited(userId, ip) {
  const stmt = db.prepare(`
    SELECT COUNT(*) as count FROM withdraw_rate_limit 
    WHERE user_id = ? AND attempted_at > datetime('now', '-1 hour')
  `);
  const result = stmt.get(userId);
  return result.count >= WITHDRAW_RATE_LIMIT;
}

function addWithdrawAttempt(userId, ip, currency) {
  const stmt = db.prepare(`INSERT INTO withdraw_rate_limit (user_id, ip, currency) VALUES (?, ?, ?)`);
  stmt.run(userId, ip, currency);
}

function cleanupOldWithdrawRateLimits() {
  db.prepare(`DELETE FROM withdraw_rate_limit WHERE attempted_at < datetime('now', '-1 hour')`).run();
}

function getAccountStanding(userId) {
  const user = db.prepare(`SELECT locked_at, suspended, created_at FROM users WHERE id = ?`).get(userId);
  if (!user) return { exists: false };
  return {
    exists: true,
    locked: user.locked_at !== null,
    suspended: user.suspended === 1,
    age: (Date.now() - new Date(user.created_at).getTime()) / (1000 * 60 * 60)
  };
}

function generateAuthToken(userId, existingToken = null) {
  const token = existingToken || crypto.randomBytes(32).toString('hex');
  const stmt = db.prepare(`INSERT OR REPLACE INTO auth_tokens (user_id, token) VALUES (?, ?)`);
  stmt.run(userId, token);
  return token;
}

function validateAuthToken(token) {
  if (!token) return null;
  const stmt = db.prepare(`
    SELECT user_id FROM auth_tokens WHERE token = ?
  `);
  const result = stmt.get(token);
  return result ? result.user_id : null;
}

function getUserById(userId) {
  const stmt = db.prepare(`SELECT id, account_number, hwid, created_at, last_login FROM users WHERE id = ?`);
  return stmt.get(userId);
}
