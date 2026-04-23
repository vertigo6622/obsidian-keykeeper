const express = require('express');
const router = express.Router();
const http = require('http');

router.get('/', (req, res) => {
  res.render('landing', { title: 'obsidian', layout: 'layout-minimal' });
});

router.get('/home', (req, res) => {
  res.render('home', { title: 'obsidian' });
});

router.get('/about', (req, res) => {
  res.render('about', { title: 'about' });
});

router.get('/about/community', (req, res) => {
  res.render('about-community', { title: 'community' });
});

router.get('/about/pgp', (req, res) => {
  res.render('about-pgp', { title: 'pgp key' });
});

router.get('/about/privacy', (req, res) => {
  res.render('about-privacy', { title: 'privacy' });
});

router.get('/about/mission', (req, res) => {
  res.render('about-mission', { title: 'mission' });
});

router.get('/about/faq', (req, res) => {
  res.render('about-faq', { title: 'faq' });
});

router.get('/about/changelog', (req, res) => {
  res.render('about-changelog', { title: 'changelog' });
});

router.get('/about/roadmap', (req, res) => {
  res.render('about-roadmap', { title: 'roadmap' });
});

router.get('/source', (req, res) => {
  res.render('source', { title: 'source' });
});

router.get('/canary', (req, res) => {
  res.render('canary', { title: 'canary' });
});

router.get('/clearnet-warning', (req, res) => {
  res.render('clearnet-warning', { title: 'clearnet warning' });
});

router.get('/contact', (req, res) => {
  res.render('contact', { title: 'contact' });
});

router.get('/pro', (req, res) => {
  res.render('pro', { title: 'pro' });
});

router.get('/pro/commercial', (req, res) => {
  res.render('pro-commercial', { title: 'commercial' });
});

router.get('/pro/features', (req, res) => {
  res.render('pro-features', { title: 'features' });
});

router.get('/pro/how-it-evades', (req, res) => {
  res.render('pro-how-it-evades', { title: 'how it evades' });
});

router.get('/status', (req, res) => {
  const options = {
    hostname: '127.0.0.1',
    port: 3000,
    path: '/keykeeper/status',
    method: 'GET',
    timeout: 5000
  };

  const request = http.request(options, (response) => {
    let data = '';
    response.on('data', chunk => data += chunk);
    response.on('end', () => {
      try {
        const json = JSON.parse(data);
        console.log('[status] keykeeper response:', data);
        res.render('status', {
          title: 'status',
          status: {
            up: json.up || false,
            database: json.database || 'down',
            xmr: json.xmr_wallet || 'down',
            ltc: json.ltc_wallet || 'down',
            capacity: json.capacity || 'down',
            uptime: json.uptime || 0
          }
        });
      } catch (e) {
        console.error('[status] parse error:', e.message, 'raw:', data);
        res.render('status', {
          title: 'status',
          status: { up: false, database: 'down', xmr: 'down', ltc: 'down', capacity: 'down', uptime: 0 }
        });
      }
    });
  });

  request.on('error', (e) => {
    console.error('[status] request error:', e.message);
    res.render('status', {
      title: 'status',
      status: { up: false, database: 'down', xmr: 'down', ltc: 'down', capacity: 'down', uptime: 0 }
    });
  });

  request.on('timeout', () => {
    request.destroy();
  });

  request.end();
});

router.get('/license', (req, res) => {
  res.render('license', { title: 'license', ref: req.query.ref || '' });
});

module.exports = router;
