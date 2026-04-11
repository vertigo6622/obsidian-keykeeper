const db = require('./database');
const wallet = require('./wallet');
const pgp = require('./pgp');
const auth = require('./auth');
const crypto = require('crypto');

const PRICES_USD_CENTS = { pro: 600, commercial: 2000 };
const TOLERANCE = { XMR: BigInt(100000), LTC: BigInt(10) };

const MAX_DAILY_WITHDRAW_USD = 200;
const MAX_PENDING_DEPOSITS = 2;

const PICONERO_PER_XMR = 1e12;
const SATOSHIS_PER_LTC = 1e8;

let io = null;

function setSocketIO(socketIO) {
  io = socketIO;
}

function getIO() {
  return io;
}

function generateTransactionId() {
  return crypto.randomBytes(16).toString('hex').toUpperCase();
}

function formatAmount(amount, currency) {
  if (currency === 'XMR') {
    return (Number(amount) / PICONERO_PER_XMR).toFixed(8);
  }
  return (Number(amount) / SATOSHIS_PER_LTC).toFixed(8);
}

async function createTransaction(userId, currency, licenseType, hwid, stubMac = null) {
  try {
    let address;
    let index;
    if (currency === 'XMR') {
      const result = await wallet.generateXMRAddress();
      address = result.address;
      index = result.subaddr_index;
    } else if (currency === 'LTC') {
      const result = await wallet.generateLTCAddress();
      address = result.address;
      index = null;
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
      amountUnits = BigInt(Math.round(amountXMR * PICONERO_PER_XMR));
    } else {
      const amountLTC = usdPrice / rate;
      amountUnits = BigInt(Math.round(amountLTC * SATOSHIS_PER_LTC));
    }
    
    const amountDisplay = formatAmount(amountUnits, currency);
    const signedAddress = await pgp.signAddress(address, parseFloat(amountDisplay), currency, usdPriceCents / 100);
    
    const stmt = db.prepare(`
      INSERT INTO transactions (user_id, type, currency, amount, address, index, signed_address, status, license_type, hwid, stub_mac, expires_at, usd_amount)
      VALUES (?, 'purchase', ?, ?, ?, ?, ?, 'pending', ?, ?, ?, datetime('now', '+24 hours'), ?)
    `);
    const txResult = stmt.run(userId, currency, amountDisplay, address, index, signedAddress, licenseType, hwid, stubMac, usdPriceCents / 100);
    
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
    const lockStmt = db.prepare('UPDATE transactions SET status = ? WHERE id = ? AND status IN (?, ?)');
    const lockResult = lockStmt.run('activating', transactionId, 'pending', 'confirmed');
    
    if (lockResult.changes === 0) {
      return { success: false, error: 'Transaction already processed' };
    }
    
    const txStmt = db.prepare('SELECT * FROM transactions WHERE id = ?');
    const transaction = txStmt.get(transactionId);

    console.log('[transactions][auth] creating license for user', transaction.user_id);
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

/* FIX FOR NEW SUBADDRESS FORMAT + BEFORE ACTIVATING DEPOSIT */
async function createDepositTransaction(userId, currency, amount) {
  try {
    const pendingCount = db.prepare(`
      SELECT COUNT(*) as count FROM transactions
      WHERE user_id = ? AND type = 'deposit' AND status = 'pending'
    `).get(userId);
    
    if (pendingCount.count >= MAX_PENDING_DEPOSITS) {
      throw new Error('Too many pending deposits');
    }
    
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
      amountUnits = BigInt(Math.round(amount * PICONERO_PER_XMR));
      usdAmountCents = BigInt(Math.round(amount * rate * 100));
    } else {
      amountUnits = BigInt(Math.round(amount * SATOSHIS_PER_LTC));
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
  const balance = await getUserBalance(userId);
  const available = currency === 'XMR' ? balance.xmr : balance.ltc;
  
  if (amount > available) {
    throw new Error('Insufficient balance');
  }
  
  const rates = wallet.getExchangeRates();
  if (rates.available) {
    const rate = currency === 'XMR' ? rates.xmr : rates.ltc;
    const usdAmount = amount * rate;
    
    const dailyWithdrawn = db.prepare(`
      SELECT COALESCE(SUM(usd_amount), 0) as total FROM transactions
      WHERE user_id = ? AND type = 'withdraw' AND status = 'completed'
      AND created_at > datetime('now', '-24 hours')
    `).get(userId);
    
    if (Number(dailyWithdrawn.total) + usdAmount > MAX_DAILY_WITHDRAW_USD) {
      throw new Error('Daily withdrawal limit exceeded');
    }
  }
  
  try {
    let result;
    if (currency === 'XMR') {
      result = await wallet.sendXMR(address, amount);
    } else if (currency === 'LTC') {
      result = await wallet.sendLTC(address, amount);
    } else {
      throw new Error('Unsupported currency');
    }
    
    const existingTx = db.prepare(`SELECT id FROM transactions WHERE tx_hash = ?`).get(result.txHash);
    if (existingTx) {
      throw new Error('Transaction already processed');
    }
    
    const stmt = db.prepare(`
      INSERT INTO transactions (user_id, type, currency, amount, address, tx_hash, status, usd_amount)
      VALUES (?, 'withdraw', ?, ?, ?, ?, 'completed', 0)
    `);
    const txResult = stmt.run(userId, currency, amount, address, result.txHash);
    
    const rates = wallet.getExchangeRates();
    let usdAmount = 0;
    if (rates.available) {
      const rate = currency === 'XMR' ? rates.xmr : rates.ltc;
      usdAmount = amount * rate;
      db.prepare('UPDATE transactions SET usd_amount = ? WHERE id = ?').run(usdAmount.toFixed(2), txResult.lastInsertRowid);
    }
    
    if (io) {
      io.to('user_' + userId).emit('tx:withdraw_completed', {
        transactionId: txResult.lastInsertRowid,
        currency,
        amount,
        txHash: result.txHash,
        fee: result.fee
      });
    }
    
    return {
      id: txResult.lastInsertRowid,
      tx_id: generateTransactionId(),
      tx_hash: result.txHash,
      fee: result.fee,
      status: 'completed'
    };
  } catch (error) {
    console.error('Withdraw error:', error);
    throw new Error('Withdrawal failed: ' + error.message);
  }
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

async function getUserBalance(userId) {
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

  const rates = await wallet.getExchangeRates();
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
      SELECT * FROM transactions WHERE status = 'pending' AND type IN ('purchase', 'deposit') AND expires_at < datetime('now')
    `).all();
    
    for (const tx of expiredTxs) {
      console.log('[transactions] expiring transaction:', tx.id);
      db.prepare('UPDATE transactions SET status = ? WHERE id = ?').run('expired', tx.id);
      
      if (io) {
        io.to('user_' + tx.user_id).emit('tx:expired', {
          transactionId: tx.id,
          currency: tx.currency
        });
      }
    }
    
    const pendingTxs = db.prepare(`
      SELECT * FROM transactions WHERE status = 'pending' AND type IN ('purchase', 'deposit') AND expires_at >= datetime('now')
    `).all();
    
    if (pendingTxs.length === 0) return;
    
    console.log('[transactions]', pendingTxs.length, 'pending transactions...');
    
    for (const tx of pendingTxs) {
      try {
        let confirmed = false;
        
        let actualConfirmations = 0;
        
        if (tx.currency === 'XMR') {
          const balance = await wallet.getXMRBalanceByAddress(tx.index);
          console.log('[transactions] pending xmr transaction:', tx.id, 'balance:', balance, 'needed:', tx.amount, 'subaddr_index', tx.index);
          const balancePiconero = BigInt(Math.round(balance * 1e12));
          const neededPiconero = BigInt(Math.round(parseFloat(tx.amount) * 1e12));
          const tolerance = BigInt(TOLERANCE.XMR);
          if (balancePiconero >= neededPiconero - tolerance && balancePiconero <= neededPiconero + tolerance * 2n) {
            confirmed = true;
            actualConfirmations = await wallet.getXMRTransactionConfirmations(tx.index);
          }
        } else if (tx.currency === 'LTC') {
          const balance = await wallet.getLTCBalanceByAddress(tx.address);
          console.log('[transactions] pending ltc transaction:', tx.id, 'balance:', balance, 'needed:', tx.amount);
          const balanceSatoshis = BigInt(Math.round(balance * 1e8));
          const neededSatoshis = BigInt(Math.round(parseFloat(tx.amount) * 1e8));
          const tolerance = BigInt(TOLERANCE.LTC);
          if (balanceSatoshis >= neededSatoshis - tolerance && balanceSatoshis <= neededSatoshis + tolerance * 2n) {
            confirmed = true;
            actualConfirmations = await wallet.getLTCTransactionConfirmations(tx.address);
          }
        }
        
        if (confirmed) {
          const transferResult = await moneroRPC('get_transfers', {
            in: true,
            account_index: 0,
            subaddr_indices: [tx.subaddr_index]
          });

          /* BLOCKCHAIN TXID NOT YET TESTED SERVERSIDE */
          const blockchainTxId = transferResult.in[0].txid;

          if (!tx.detected_at) {
            db.prepare('UPDATE transactions SET detected_at = datetime(\'now\'), confirmations = ?, tx_hash = ? WHERE id = ?').run(actualConfirmations, blockchainTxId, tx.id);
            
            if (io) {
              io.to('user_' + tx.user_id).emit('tx:detected', {
                transactionId: tx.id,
                tx_id: blockchainTxId,
                currency: tx.currency,
                amount: tx.amount,
                confirmations: actualConfirmations
              });
            }
            console.log('[transactions]Payment detected for transaction:', tx.id, 'confirmations:', actualConfirmations);
          } else {
            db.prepare('UPDATE transactions SET confirmations = ? WHERE id = ?').run(actualConfirmations, tx.id);
            console.log('[transactions] transaction', tx.id, 'confirmations:', actualConfirmations);
          }
          
          const txCheck = db.prepare('SELECT status, confirmations FROM transactions WHERE id = ?').get(tx.id);
          
          if (txCheck.status !== 'completed' && actualConfirmations >= 10 && tx.currency === 'XMR') {
            const lock = db.prepare('UPDATE transactions SET status = ? WHERE id = ? AND status = ?').run('confirmed', tx.id, 'pending');
            if (lock.changes === 0) {
              console.log('[transactions] transaction already being processed:', tx.id);
              continue;
            }
            console.log('[transactions] payment confirmed for transaction:', tx.id);
            if (tx.type === 'deposit') {
              db.prepare('UPDATE transactions SET status = ? WHERE id = ?').run('completed', tx.id);
              if (io) {
                io.to('user_' + tx.user_id).emit('tx:deposit_completed', {
                  transactionId: tx.id,
                  currency: tx.currency,
                  amount: tx.amount
                });
              }
            } else {
              await activateLicense(tx.id);
            }
          } else if (txCheck.status !== 'completed' && actualConfirmations >= 6 && tx.currency === 'LTC') {
            const lock = db.prepare('UPDATE transactions SET status = ? WHERE id = ? AND status = ?').run('confirmed', tx.id, 'pending');
            if (lock.changes === 0) {
              console.log('[transactions]Transaction already being processed:', tx.id);
              continue;
            }
            console.log('[transactions]Payment confirmed for transaction:', tx.id);
            if (tx.type === 'deposit') {
              db.prepare('UPDATE transactions SET status = ? WHERE id = ?').run('completed', tx.id);
              if (io) {
                io.to('user_' + tx.user_id).emit('tx:deposit_completed', {
                 transactionId: tx.id,
                  currency: tx.currency,
                  amount: tx.amount
                });
              }
            } else {
              await activateLicense(tx.id);
            }
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
  getIO,
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
