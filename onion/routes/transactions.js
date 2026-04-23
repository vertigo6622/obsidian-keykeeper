const express = require('express');
const router = express.Router();
const auth = require('../js/auth');
const tx = require('../js/transactions');
const validate = require('../js/validate');

function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  next();
}

router.get('/verify', (req, res) => {
  if (req.session.userId) {
    res.redirect('/transactions');
  }
  res.render('verify', { title: 'verify' });
});

router.get('/transactions', (req, res) => {
  res.render('transactions', { title: 'transactions' });
});

router.get('/purchase', (req, res) => {
  res.render('purchase', { title: 'purchase' });
});

router.get('/purchase/commercial', (req, res) => {
  res.render('purchase-commercial', { title: 'commercial' });
});

router.get('/purchase/payment', requireAuth, (req, res) => {
  res.render('payment', { title: 'payment' });
});

router.get('/purchase/monero', requireAuth, async (req, res) => {
  const userId = req.session.userId;
  const pendingTx = tx.getPendingTransaction(userId);
  const rateLimited = auth.isTxCreateRateLimited(userId);
  res.render('monero-pay', { title: 'monero payment', pendingTx, rateLimited });
});

router.get('/purchase/litecoin', requireAuth, async (req, res) => {
  const userId = req.session.userId;
  const pendingTx = tx.getPendingTransaction(userId);
  const rateLimited = auth.isTxCreateRateLimited(userId);
  res.render('litecoin-pay', { title: 'litecoin payment', pendingTx, rateLimited });
});

router.post('/transactions/create', requireAuth, async (req, res) => {
  try {
    const userId = req.session.userId;
    const { currency, license_type } = req.body;

    const standing = auth.getAccountStanding(userId);
    if (!standing.exists || standing.locked || standing.suspended) {
      return res.render('error', { title: 'error', message: 'account not in good standing' });
    }

    if (auth.isTxCreateRateLimited(userId)) {
      return res.render('error', { title: 'error', message: 'too many transactions. try again later.' });
    }

    const sanitizedCurrency = validate.sanitizeCurrency(currency);
    const sanitizedLicenseType = validate.sanitizeLicenseType(license_type);

    if (!sanitizedCurrency) {
      return res.render('error', { title: 'error', message: 'invalid currency' });
    }

    if (!sanitizedLicenseType) {
      return res.render('error', { title: 'error', message: 'invalid license type' });
    }

    const transaction = await tx.createTransaction(userId, sanitizedCurrency, sanitizedLicenseType, null, null);
    auth.addTxCreateAttempt(userId);

    res.redirect('/transactions/' + transaction.id);
  } catch (error) {
    console.error('Create tx error:', error);
    res.render('error', { title: 'error', message: error.message || 'failed to create transaction' });
  }
});

router.get('/transactions/:id', requireAuth, async (req, res) => {
  try {
    const transaction = tx.getTransactionById(req.params.id);
    if (!transaction) {
      return res.render('error', { title: 'not found', message: 'transaction not found' });
    }
    if (transaction.user_id !== req.session.userId) {
      return res.render('error', { title: 'unauthorized', message: 'not your transaction' });
    }
    res.render('transaction-status', { title: 'transaction', tx: transaction });
  } catch (error) {
    console.error('Get tx error:', error);
    res.render('error', { title: 'error', message: 'failed to load transaction' });
  }
});

module.exports = router;
