const express = require('express');
const router = express.Router();
const auth = require('../js/auth');
const tx = require('../js/transactions');

function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  next();
}

router.get('/profile', requireAuth, async (req, res) => {
  const user = auth.getUserById(req.session.userId);
  const license = auth.getLicenseByUserId(req.session.userId);
  res.render('profile', {
    title: 'profile',
    profile: {
      account_number: user.account_number,
      license: license ? license.type : 'none'
    }
  });
});

router.get('/balance', requireAuth, async (req, res) => {
  const balance = await tx.getUserBalance(req.session.userId);
  res.render('balance', { title: 'balance', balance });
});

router.get('/history', requireAuth, (req, res) => {
  const transactions = tx.getTransactionsByUserId(req.session.userId);
  const licenses = tx.getLicensesByUserId(req.session.userId);

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

  res.render('history', { title: 'history', history });
});

router.get('/settings', requireAuth, (req, res) => {
  res.render('settings', { title: 'settings' });
});

router.get('/settings/password', requireAuth, (req, res) => {
  res.render('settings-password', { title: 'change password', error: null, success: false });
});

router.post('/settings/password', requireAuth, async (req, res) => {
  try {
    const { old_password, new_password } = req.body;
    const result = await auth.changePassword(req.session.userId, old_password, new_password);
    if (result.success) {
      res.render('settings-password', { title: 'change password', error: null, success: true });
    } else {
      res.render('settings-password', { title: 'change password', error: result.error || 'failed to change password', success: false });
    }
  } catch (error) {
    console.error('Change password error:', error);
    res.render('settings-password', { title: 'change password', error: 'failed to change password', success: false });
  }
});

router.get('/settings/delete', requireAuth, (req, res) => {
  res.render('settings-delete', { title: 'delete account', error: null });
});

router.post('/settings/delete', requireAuth, async (req, res) => {
  try {
    const { password } = req.body;
    const result = await auth.deleteAccount(req.session.userId, password);
    if (result.success) {
      req.session.destroy(() => {
        res.redirect('/');
      });
    } else {
      res.render('settings-delete', { title: 'delete account', error: result.error || 'failed to delete account' });
    }
  } catch (error) {
    console.error('Delete account error:', error);
    res.render('settings-delete', { title: 'delete account', error: 'failed to delete account' });
  }
});

module.exports = router;
