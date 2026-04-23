const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const auth = require('../js/auth');
const packer = require('../js/packer-bridge');
const db = require('../js/database');

function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  next();
}

const downloadTokens = new Map();
const TOKEN_TTL_MS = 30 * 1000;

router.get('/license/manage', requireAuth, (req, res) => {
  const license = auth.getLicenseByUserId(req.session.userId);
  res.render('license-manage', { title: 'manage license', license });
});

router.get('/license/download', requireAuth, (req, res) => {
  const userId = req.session.userId;
  const license = auth.getLicenseByUserId(userId);

  let token = null;
  if (license && !(license.expires_at && new Date(license.expires_at) <= new Date())) {
    token = crypto.randomBytes(32).toString('hex');
    downloadTokens.set(token, { userId, createdAt: Date.now() });
  }

  res.render('license-download', { title: 'download', license, token });
});

router.get('/license/download/binary', requireAuth, (req, res) => {
  const token = req.query.token;
  if (!token) {
    return res.status(400).send('Unauthorized');
  }

  const tokenData = downloadTokens.get(token);
  if (!tokenData) {
    return res.status(401).send('Unauthorized');
  }
  downloadTokens.delete(token);

  if (Date.now() - tokenData.createdAt > TOKEN_TTL_MS) {
    return res.status(401).send('Token expired');
  }

  const userId = tokenData.userId;
  if (userId !== req.session.userId) {
    return res.status(401).send('Unauthorized');
  }

  const license = auth.getLicenseByUserId(userId);
  if (!license) {
    return res.render('error', { title: 'error', message: 'no license found' });
  }

  if (license.expires_at && new Date(license.expires_at) <= new Date()) {
    return res.render('error', { title: 'error', message: 'license expired' });
  }

  let hwid = license.hwid;
  if (hwid) {
    auth.updateLicenseHwid(license.license_id, null);
    db.prepare('UPDATE licenses SET last_relink_at = datetime(\'now\') WHERE license_id = ?').run(license.license_id);
    hwid = null;
  }

  packer.createPackedBinary(license.type, hwid, license.license_id, (err, result) => {
    if (err) {
      console.error('Packer error:', err.message);
      return res.render('error', { title: 'error', message: 'failed to create binary' });
    }

    auth.updateLicenseDownloadFilename(license.license_id, result.filename);
    auth.updateLicenseStubMac(license.license_id, result.mac);
    auth.updateLicenseSpeckKey(license.license_id, result.key);
    auth.updateLicenseIntegrity(license.license_id, result.integrity);

    res.setHeader('Content-Type', 'application/exe');
    res.setHeader('Content-Disposition', 'attachment; filename="' + result.filename + '"');
    res.send(result.data);
  });
});

router.get('/license/relink', requireAuth, (req, res) => {
  const license = auth.getLicenseByUserId(req.session.userId);
  res.render('license-relink', { title: 'relink license', license });
});

module.exports = router;
