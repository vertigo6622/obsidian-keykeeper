const db = require('./database');
const wallet = require('./wallet');
const pgp = require('./pgp');
const auth = require('./auth');
const crypto = require('crypto');

const PRICES_USD = {
  pro: 60,
  commercial: 200
};

const TOLERANCE = {
  XMR: 0.000001,
  LTC: 0.000001
};

let io = null;

function setSocketIO(socketIO) {
  io = socketIO;
}

function generateTransactionId() {
  return crypto.randomBytes(5).toString('hex').toUpperCase();
}

async function createTransaction(userId, currency, licenseType, hwid) {
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
    
    const usdPrice = PRICES_USD[licenseType];
    const rate = currency === 'XMR' ? rates.xmr : rates.ltc;
    const amount = usdPrice / rate;
    const amountRounded = Math.round(amount * 1e6) / 1e6;
    
    const signedAddress = await pgp.signAddress(address, amountRounded, currency, usdPrice);
    
    const stmt = db.prepare(`
      INSERT INTO transactions (user_id, type, currency, amount, address, signed_address, status, license_type, hwid, expires_at, usd_amount)
      VALUES (?, 'purchase', ?, ?, ?, ?, 'pending', ?, ?, datetime('now', '+24 hours'), ?)
    `);
    const txResult = stmt.run(userId, currency, amountRounded, address, signedAddress, licenseType, hwid, usdPrice);
    
    return {
      id: txResult.lastInsertRowid,
      address,
      signed_address: signedAddress,
      amount: amountRounded,
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
    const txStmt = db.prepare('SELECT * FROM transactions WHERE id = ?');
    const transaction = txStmt.get(transactionId);
    
    if (!transaction || transaction.status !== 'pending') {
      return { success: false, error: 'Transaction not found or already processed' };
    }
    
    const licenseId = auth.createLicense(transaction.user_id, transaction.license_type, transaction.hwid);
    
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
  const purchases = db.prepare(`
    SELECT currency, SUM(amount) as total FROM transactions
    WHERE user_id = ? AND type = 'purchase' AND status = 'completed'
    GROUP BY currency
  `).all(userId);
  
  const withdrawals = db.prepare(`
    SELECT currency, SUM(amount) as total FROM transactions
    WHERE user_id = ? AND type = 'withdraw' AND status = 'completed'
    GROUP BY currency
  `).all(userId);
  
  let xmrBalance = 0;
  let ltcBalance = 0;
  
  purchases.forEach(p => {
    if (p.currency === 'XMR') xmrBalance += p.total;
    if (p.currency === 'LTC') ltcBalance += p.total;
  });
  
  withdrawals.forEach(w => {
    if (w.currency === 'XMR') xmrBalance -= w.total;
    if (w.currency === 'LTC') ltcBalance -= w.total;
  });
  
  return {
    xmr: Math.max(0, xmrBalance),
    ltc: Math.max(0, ltcBalance),
    usd: '0.00'
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
        
        if (tx.currency === 'XMR') {
          const balance = await wallet.getXMRBalanceByAddress(tx.address);
          console.log('XMR check:', tx.address, 'balance:', balance, 'needed:', tx.amount);
          const tolerance = TOLERANCE.XMR;
          if (balance >= tx.amount - tolerance && balance <= tx.amount + tolerance * 10) {
            confirmed = true;
          }
        } else if (tx.currency === 'LTC') {
          const balance = await wallet.getLTCBalanceByAddress(tx.address);
          console.log('LTC check:', tx.address, 'balance:', balance, 'needed:', tx.amount);
          const tolerance = TOLERANCE.LTC;
          if (balance >= tx.amount - tolerance && balance <= tx.amount + tolerance * 10) {
            confirmed = true;
          }
        }
        
        if (confirmed) {
          const newConfirmations = (tx.confirmations || 0) + 1;
          
          if (!tx.detected_at) {
            db.prepare('UPDATE transactions SET detected_at = datetime(\'now\'), confirmations = ? WHERE id = ?').run(newConfirmations, tx.id);
            
            if (io) {
              io.to('user_' + tx.user_id).emit('tx:detected', {
                transactionId: tx.id,
                tx_id: tx.tx_id,
                currency: tx.currency,
                amount: tx.amount
              });
            }
            console.log('Payment detected for transaction:', tx.id, 'confirmations:', newConfirmations);
          } else {
            db.prepare('UPDATE transactions SET confirmations = ? WHERE id = ?').run(newConfirmations, tx.id);
            console.log('Transaction', tx.id, 'confirmations:', newConfirmations);
          }
          
          if (newConfirmations >= 5) {
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

module.exports = {
  setSocketIO,
  createTransaction,
  createWithdrawTransaction,
  getTransactionsByUserId,
  getTransactionById,
  getUserBalance,
  updateTransactionStatus,
  activateLicense,
  checkPendingPayments,
  getLicensesByUserId,
  cleanupOldXMRTransactions
};
