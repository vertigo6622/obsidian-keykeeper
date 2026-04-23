const express = require('express');
const router = express.Router();
const auth = require('../js/auth');
const validate = require('../js/validate');

router.get('/login', (req, res) => {
  if (req.session.userId) {
    return res.redirect('/transactions');
  }
  res.render('login', { title: 'login', error: null, user: null });
});

router.post('/login', async (req, res) => {
  try {
    const { account_number, password } = req.body;
    const sessionId = req.session.id || 'unknown';

    const sanitizedAccountNumber = validate.sanitizeAccountNumber(account_number);
    const sanitizedPassword = validate.sanitizePassword(password);

    if (!sanitizedAccountNumber) {
      return res.render('login', { title: 'login', error: 'invalid account number format', user: null });
    }

    if (!sanitizedPassword) {
      return res.render('login', { title: 'login', error: 'password must be 8-128 characters', user: null });
    }

    if (auth.isLoginRateLimited(sessionId)) {
      return res.render('login', { title: 'login', error: 'too many login attempts. try again later.', user: null });
    }

    auth.addLoginAttempt(sessionId);

    const user = auth.getUserByAccountNumber(sanitizedAccountNumber);
    if (!user) {
      return res.render('login', { title: 'login', error: 'invalid credentials', user: null });
    }

    if (auth.isAccountLocked(user.id)) {
      return res.render('login', { title: 'login', error: 'account locked. contact support.', user: null });
    }

    if (auth.isAccountSuspended(user.id)) {
      return res.render('login', { title: 'login', error: 'account suspended. contact support.', user: null });
    }

    const valid = await auth.verifyPassword(sanitizedPassword, user.password_hash);
    if (!valid) {
      auth.addFailedLoginAttempt(user.id, sessionId);
      const attemptsLeft = 5 - auth.getFailedLoginAttempts(user.id);
      return res.render('login', { title: 'login', error: 'invalid credentials', user: null });
    }

    auth.clearFailedLoginAttempts(user.id);
    auth.updateLastLogin(user.id);

    req.session.regenerate();
    req.session.userId = user.id;
    res.redirect('/transactions');
  } catch (error) {
    console.error('Login error:', error);
    res.render('login', { title: 'login', error: 'login failed', user: null });
  }
});

router.get('/register', (req, res) => {
  if (req.session.userId) {
    return res.redirect('/transactions');
  }
  res.render('register', { title: 'register', error: null, user: null });
});

router.post('/register', async (req, res) => {
  try {
    const { password, password_confirm } = req.body;
    const sessionId = req.session.id || 'unknown';

    const sanitizedPassword = validate.sanitizePassword(password);

    if (!sanitizedPassword) {
      return res.render('register', { title: 'register', error: 'password must be 8-128 characters', user: null });
    }

    if (password !== password_confirm) {
      return res.render('register', { title: 'register', error: 'passwords do not match', user: null });
    }

    if (auth.isRateLimited(sessionId)) {
      return res.render('register', { title: 'register', error: 'rate limited. try again later.', user: null });
    }

    const passwordHash = await auth.hashPassword(sanitizedPassword);
    const user = auth.createUser(passwordHash);

    auth.addRateLimitEntry(sessionId);

    req.session.userId = user.id;

    res.render('account-created', { title: 'account created', accountNumber: user.accountNumber, user: null });
  } catch (error) {
    console.error('Register error:', error);
    res.render('register', { title: 'register', error: 'registration failed', user: null });
  }
});

router.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/');
  });
});

module.exports = router;
