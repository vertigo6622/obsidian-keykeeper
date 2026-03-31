const db = require('./database');
const wallet = require('./wallet');
const pgp = require('./pgp');
const auth = require('./auth');
const crypto = require('crypto');

const PRICES_USD_CENTS = {
  pro: 100,
  commercial: 2000
};

const TOLERANCE = {
  XMR: BigInt(100000000),
  LTC: BigInt(10000000)
};

const PICONERO_PER_XMR = BigInt(1e12);
const SATOSHIS_PER_LTC = BigInt(1e8);

let io = null;

function setSocketIO(socketIO) {
  io = socketIO;
}

function generateTransactionId() {
  return crypto.randomBytes(12).toString('hex').toUpperCase();
}

function formatAmount(amount, currency) {
  if (currency === 'XMR') {
    return (Number(amount) / 1e12).toFixed(8);
  } else if (currency === 'LTC') {
    return (Number(amount) / 1e8).toFixed(8);
  } else {
    throw new Error('Unsupported currency');
  }
}

async function createTransaction(userId, currency, licenseType, hwid, stubMac = null) {
  try {
    let address;
    
    if (currency === 'XMR') {
      const result = await wallet.generateXMRAddress();
      address = result.address;
    } else if (currency === 'LTC') {
      const result = await wallet.generateLTCAddress();
      address = result.address;
    } else {
      throw new Error('Unsupported currency');
    }
    
    const rates = await wallet.getExchangeRates();
    if (!rates.available) {
      throw new Error('Exchange rates unavailable');
    }
    
    const usdPriceCents = PRICES_USD_CENTS[licenseType];
    const rate = currency === 'XMR' ? rates.xmr : rates.ltc;
    const usdPrice = usdPriceCents / 100;
    
    let amountUnits;
    if (currency === 'XMR') {
      const amountXMR = usdPrice / rate;
      amountUnits = BigInt(Math.round(amountXMR * 1e12));
    } else {
      const amountLTC = usdPrice / rate;
      amountUnits = BigInt(Math.round(amountLTC * 1e8));
    }
    
    const amountDisplay = formatAmount(amountUnits, currency);
    const signedAddress = await pgp.signAddress(address, parseFloat(amountDisplay), currency, usdPriceCents / 100);
    
    const stmt = db.prepare(`
      INSERT INTO transactions (user_id, type, currency, amount, address, signed_address, status, license_type, hwid, stub_mac, expires_at, usd_amount)
      VALUES (?, 'purchase', ?, ?, ?, ?, 'pending', ?, ?, ?, datetime('now', '+24 hours'), ?)
    `);
    const txResult = stmt.run(userId, currency, amountDisplay, address, signedAddress, licenseType, hwid, stubMac, usdPriceCents / 100);
    
    return {
      id: txResult.lastInsertRowid,
      address,
      signed_address: signedAddress,
      amount: amountDisplay,
      currency,
      tx_id: generateTransactionId(),
      status: 'pending'
    };
  } catch (error) {
    console.error('Create transaction error:', error);
    throw new Error('Failed to create transaction');
  }
}

async function activateLicense(transactionId) {
  try {
    const lockStmt = db.prepare('UPDATE transactions SET status = ? WHERE id = ? AND status = ?');
    const lockResult = lockStmt.run('activating', transactionId, 'pending');
    
    if (lockResult.changes === 0) {
      return { success: false, error: 'Transaction already processed' };
    }
    
    const txStmt = db.prepare('SELECT * FROM transactions WHERE id = ?');
    const transaction = txStmt.get(transactionId);
    
    const licenseId = auth.createLicense(transaction.user_id, transaction.license_type, transaction.hwid, transaction.stub_mac);
    
    const updateStmt = db.prepare('UPDATE transactions SET status = ?, license_id = ? WHERE id = ?');
    updateStmt.run('completed', licenseId, transactionId);
    
    if (io) {
      io.to('user_' + transaction.user_id).emit('tx:confirmed', {
        transactionId: transactionId,
        license_id: licenseId,
        currency: transaction.currency,
        amount: transaction.amount
      });
    }
    
    return { success: true, license_id: licenseId };
  } catch (error) {
    console.error('Activate license error:', error);
    return { success: false, error: 'Failed to activate license' };
  }
}

async function createDepositTransaction(userId, currency, amount) {
  try {
    const rates = await wallet.getExchangeRates();
    if (!rates.available) {
      throw new Error('Exchange rates unavailable');
    }
    
    const rate = currency === 'XMR' ? rates.xmr : rates.ltc;
    const usdAmount = amount * rate;
    
    if (usdAmount < 20) {
      throw new Error('Minimum deposit is $20 USD');
    }
    
    let address;
    
    if (currency === 'XMR') {
      const result = await wallet.generateXMRAddress();
      address = result.address;
    } else if (currency === 'LTC') {
      const result = await wallet.generateLTCAddress();
      address = result.address;
    } else {
      throw new Error('Unsupported currency');
    }
    
    let amountUnits;
    let usdAmountCents;
    if (currency === 'XMR') {
      amountUnits = BigInt(Math.round(amount * 1e12));
      usdAmountCents = BigInt(Math.round(amount * rate * 100));
    } else {
      amountUnits = BigInt(Math.round(amount * 1e8));
      usdAmountCents = BigInt(Math.round(amount * rate * 100));
    }
    
    const amountDisplay = formatAmount(amountUnits, currency);
    const usdDisplay = (Number(usdAmountCents) / 100).toFixed(2);
    
    const signedAddress = await pgp.signAddress(address, parseFloat(amountDisplay), currency, parseFloat(usdDisplay));
    
    const stmt = db.prepare(`
      INSERT INTO transactions (user_id, type, currency, amount, address, signed_address, status, expires_at, usd_amount)
      VALUES (?, 'deposit', ?, ?, ?, ?, 'pending', datetime('now', '+24 hours'), ?)
    `);
    const txResult = stmt.run(userId, currency, amountDisplay, address, signedAddress, usdDisplay);
    
    return {
      id: txResult.lastInsertRowid,
      address,
      signed_address: signedAddress,
      amount: amountDisplay,
      currency,
      tx_id: generateTransactionId(),
      status: 'pending'
    };
  } catch (error) {
    console.error('Create deposit error:', error);
    throw new Error('Failed to create deposit');
  }
}

async function createWithdrawTransaction(userId, currency, amount, address) {
  const stmt = db.prepare(`
    INSERT INTO transactions (user_id, type, currency, amount, address, status)
    VALUES (?, 'withdraw', ?, ?, ?, 'pending')
  `);
  const result = stmt.run(userId, currency, amount, address);
  
  return {
    id: result.lastInsertRowid,
    tx_id: generateTransactionId()
  };
}

function getTransactionsByUserId(userId, limit = 50) {
  const stmt = db.prepare(`
    SELECT * FROM transactions 
    WHERE user_id = ? 
    ORDER BY created_at DESC 
    LIMIT ?
  `);
  return stmt.all(userId, limit);
}

function getTransactionById(id) {
  const stmt = db.prepare(`SELECT * FROM transactions WHERE id = ?`);
  return stmt.get(id);
}

function getUserBalance(userId) {
  const deposits = db.prepare(`
    SELECT currency, SUM(CAST(amount AS REAL)) as total FROM transactions
    WHERE user_id = ? AND type = 'deposit' AND status = 'completed'
    GROUP BY currency
  `).all(userId);
  
  const withdrawals = db.prepare(`
    SELECT currency, SUM(CAST(amount AS REAL)) as total FROM transactions
    WHERE user_id = ? AND type = 'withdraw' AND status = 'completed'
    GROUP BY currency
  `).all(userId);
  
  let xmrBalance = 0;
  let ltcBalance = 0;
  
  deposits.forEach(d => {
    if (d.currency === 'XMR') xmrBalance += d.total || 0;
    if (d.currency === 'LTC') ltcBalance += d.total || 0;
  });
  
  withdrawals.forEach(w => {
    if (w.currency === 'XMR') xmrBalance -= w.total || 0;
    if (w.currency === 'LTC') ltcBalance -= w.total || 0;
  });

  const rates = wallet.getExchangeRates();
  let usdBalance = 0;
  
  if (rates.available) {
    usdBalance = (xmrBalance * rates.xmr) + (ltcBalance * rates.ltc);
  }
  
  return {
    xmr: Math.max(0, xmrBalance),
    ltc: Math.max(0, ltcBalance),
    usd: usdBalance.toFixed(2)
  };
}

function updateTransactionStatus(id, txHash, status) {
  const stmt = db.prepare(`
    UPDATE transactions SET tx_hash = ?, status = ? WHERE id = ?
  `);
  stmt.run(txHash, status, id);
}

async function checkPendingPayments() {
  try {
    const expiredTxs = db.prepare(`
      SELECT * FROM transactions WHERE status = 'pending' AND type = 'purchase' AND expires_at < datetime('now')
    `).all();
    
    for (const tx of expiredTxs) {
      console.log('Expiring transaction:', tx.id);
      db.prepare('UPDATE transactions SET status = ? WHERE id = ?').run('expired', tx.id);
      
      if (io) {
        io.to('user_' + tx.user_id).emit('tx:expired', {
          transactionId: tx.id,
          currency: tx.currency
        });
      }
    }
    
    const pendingTxs = db.prepare(`
      SELECT * FROM transactions WHERE status = 'pending' AND type = 'purchase' AND expires_at >= datetime('now')
    `).all();
    
    if (pendingTxs.length === 0) return;
    
    console.log('Checking', pendingTxs.length, 'pending transactions...');
    
    for (const tx of pendingTxs) {
      try {
        let confirmed = false;
        
        let actualConfirmations = 0;
        
        if (tx.currency === 'XMR') {
          const balance = await wallet.getXMRBalanceByAddress(tx.address);
          console.log('XMR check:', tx.address, 'balance:', balance, 'needed:', tx.amount);
          const balancePiconero = BigInt(Math.round(balance * 1e12));
          const neededPiconero = BigInt(Math.round(parseFloat(tx.amount) * 1e12));
          const tolerance = BigInt(TOLERANCE.XMR);
          if (balancePiconero >= neededPiconero - tolerance && balancePiconero <= neededPiconero + tolerance * 10n) {
            confirmed = true;
            actualConfirmations = await wallet.getXMRTransactionConfirmations(tx.address);
          }
        } else if (tx.currency === 'LTC') {
          const balance = await wallet.getLTCBalanceByAddress(tx.address);
          console.log('LTC check:', tx.address, 'balance:', balance, 'needed:', tx.amount);
          const balanceSatoshis = BigInt(Math.round(balance * 1e8));
          const neededSatoshis = BigInt(Math.round(parseFloat(tx.amount) * 1e8));
          const tolerance = BigInt(TOLERANCE.LTC);
          if (balanceSatoshis >= neededSatoshis - tolerance && balanceSatoshis <= neededSatoshis + tolerance * 10n) {
            confirmed = true;
            actualConfirmations = await wallet.getLTCTransactionConfirmations(tx.address);
          }
        }
        
        if (confirmed) {
          if (!tx.detected_at) {
            db.prepare('UPDATE transactions SET detected_at = datetime(\'now\'), confirmations = ? WHERE id = ?').run(actualConfirmations, tx.id);
            
            if (io) {
              io.to('user_' + tx.user_id).emit('tx:detected', {
                transactionId: tx.id,
                tx_id: tx.tx_id,
                currency: tx.currency,
                amount: tx.amount,
                confirmations: actualConfirmations
              });
            }
            console.log('Payment detected for transaction:', tx.id, 'confirmations:', actualConfirmations);
          } else {
            db.prepare('UPDATE transactions SET confirmations = ? WHERE id = ?').run(actualConfirmations, tx.id);
            console.log('Transaction', tx.id, 'confirmations:', actualConfirmations);
          }
          
          const txCheck = db.prepare('SELECT status, confirmations FROM transactions WHERE id = ?').get(tx.id);
          
          if (txCheck.status !== 'completed' && actualConfirmations >= 10 && tx.currency === 'XMR') {
            console.log('Payment confirmed for transaction:', tx.id);
            await activateLicense(tx.id);
          } else if (txCheck.status !== 'completed' && actualConfirmations >= 6 && tx.currency === 'LTC') {
            console.log('Payment confirmed for transaction:', tx.id);
            await activateLicense(tx.id);
          }
        }
      } catch (error) {
        console.error('Error checking payment for tx', tx.id, error.message);
      }
    }
  } catch (error) {
    console.error('Check pending payments error:', error);
  }
}

function getLicensesByUserId(userId) {
  const stmt = db.prepare(`
    SELECT license_id, type, expires_at, created_at, hwid
    FROM licenses 
    WHERE user_id = ? 
    ORDER BY created_at DESC
  `);
  return stmt.all(userId);
}

function cleanupOldXMRTransactions() {
  const stmt = db.prepare(`
    DELETE FROM transactions 
    WHERE currency = 'XMR' 
    AND created_at < datetime('now', '-7 days')
  `);
  const result = stmt.run();
  if (result.changes > 0) {
    console.log(`Cleaned up ${result.changes} old XMR transactions`);
  }
  return result.changes;
}

function getPendingTransaction(userId) {
  const stmt = db.prepare(`
    SELECT id, currency, amount, address, status, expires_at
    FROM transactions 
    WHERE user_id = ? AND type = 'purchase' AND status = 'pending' 
    AND expires_at > datetime('now')
    ORDER BY created_at DESC LIMIT 1
  `);
  return stmt.get(userId);
}

module.exports = {
  setSocketIO,
  createTransaction,
  createDepositTransaction,
  createWithdrawTransaction,
  getTransactionsByUserId,
  getTransactionById,
  getUserBalance,
  getPendingTransaction,
  updateTransactionStatus,
  activateLicense,
  checkPendingPayments,
  getLicensesByUserId,
  cleanupOldXMRTransactions
};
