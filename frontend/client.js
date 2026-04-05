let socket = null;
let currentUser = null;
let lastTabBeforeLicense = 'tab-purchase';
let lastTabBeforePro = 'tab-about';

function setLastTabBeforePro() {
  const checked = document.querySelector('input[name="tabs"]:checked');
  const currentTab = checked ? checked.id : 'tab-about';
  const proSubPages = ['tab-commercial', 'tab-features', 'tab-how-it-evades'];
  if (currentTab !== 'tab-pro' && !proSubPages.includes(currentTab)) {
    lastTabBeforePro = currentTab;
  }
}

function goBackFromPro() {
  document.getElementById(lastTabBeforePro).checked = true;
}

function setLastTabBeforeLicense() {
  const checked = document.querySelector('input[name="tabs"]:checked');
  lastTabBeforeLicense = checked ? checked.id : 'tab-purchase';
}

function goBackFromLicense() {
  document.getElementById(lastTabBeforeLicense).checked = true;
}

function connectToBackend() {
  if (socket && socket.connected) return;
  
  document.querySelector('.tx-loading').style.display = 'block';
  document.querySelector('.tx-disconnected').style.display = 'none';
  
  socket = io('http://206.245.132.222:8888');
  
  socket.on('connect_error', (err) => {
    console.error('Connection error:', err);
    document.querySelector('.tx-loading').style.display = 'none';
    document.querySelector('.tx-disconnected').style.display = 'block';
  });
  
  socket.on('error', (err) => {
    console.error('Socket error:', err);
  });
  
  socket.on('connect', () => {
    console.log('Connected to backend');
    console.log('Connected to backend');
    checkSession();
    showTransactionBoxes();
    
    socket.on('tx:detected', (data) => {
      const panelMap = {
        'XMR': 'panel-monero-processing',
        'LTC': 'panel-litecoin-processing'
      };
      const panel = document.getElementById(panelMap[data.currency]);
      if (panel) {
        panel.innerHTML = `
          <label class="back-btn" for="tab-payment">&lt; back</label>
          <h1>Processing Payment</h1>
          <p>tx id: ${data.tx_id}</p>
          <p>amount: ${data.amount} ${data.currency}</p>
          <p>waiting for confirmations<span class="loader"><span>.</span><span>.</span><span>.</span></span></p>
          <p style="margin-top: 10px;> feel free to do something else while it confirms. your license will be issued automatically when it reaches the confirmation target.<p>
        `;
      }
    });
    
    socket.on('tx:confirmed', (data) => {
      const panelMap = {
        'XMR': 'panel-monero-processing',
        'LTC': 'panel-litecoin-processing'
      };
      const panel = document.getElementById(panelMap[data.currency]);
      if (panel) {
        panel.innerHTML = `
          <label class="back-btn" for="tab-transactions">&lt; back</label>
          <h1>Payment Complete!</h1>
          <p>license id: ${data.license_id}</p>
          <p>transaction complete</p>
        `;
        setTimeout(() => {
          document.getElementById('tab-profile').checked = true;
          updateProfileUI();
        }, 3000);
      }
    });
    
    socket.on('tx:expired', (data) => {
      console.log('Transaction expired:', data);
      const processingPanel = document.getElementById('monero-processing') || document.getElementById('litecoin-processing');
      if (processingPanel) {
        processingPanel.innerHTML = `
          <label class="back-btn" for="tab-payment">&lt; back</label>
          <h1>Transaction Expired</h1>
          <p>this transaction has expired</p>
        `;
      }
    });
    
    socket.on('license:relink:complete', (data) => {
      console.log('Relink complete:', data);
      const relinkingPanel = document.getElementById('panel-relinking');
      if (relinkingPanel) {
        relinkingPanel.innerHTML = `
          <label class="back-btn" for="tab-manage">&lt; back</label>
          <h1>Relink Complete!</h1>
          <p>license has been relinked successfully</p>
        `;
        setTimeout(() => {
          document.getElementById('tab-manage').checked = true;
          updateManageLicenseUI();
        }, 3000);
      }
    });
  });
  
  socket.on('disconnect', () => {
    console.log('Disconnected from backend');
    currentUser = null;
    document.querySelectorAll('.tx-section, .tx-title, .tx-grid').forEach(function(el) {
      el.style.display = 'none';
    });
    document.querySelector('.tx-loading').style.display = 'none';
    document.querySelector('.tx-disconnected').style.display = 'block';
    const authBtn = document.getElementById('auth-btn');
    if (authBtn) authBtn.style.display = 'none';
  });

  socket.on('session:timeout', (data) => {
    console.log('Session timeout:', data.message);
    currentUser = null;
    showLoggedOutUI();
    alert('Your session has expired due to inactivity. Please log in again.');
  });

  socket.on('auth:login:res', (data) => {
    if (data.success) {
      socket.emit('user:getProfile', {}, (response) => {
        currentUser = response;
        showLoggedInUI();
      });
    } else {
      alert(data.error || 'Login failed');
    }
  });

  socket.on('auth:register:res', (data) => {
    if (data.success) {
      socket.emit('user:getProfile', {}, (response) => {
        currentUser = response;
        showLoggedInUI();
      });
    } else {
      alert(data.error || 'Registration failed');
    }
  });
}

function showTransactionBoxes() {
  document.querySelector('.tx-loading').style.display = 'none';
  document.querySelectorAll('.tx-section, .tx-title, .tx-grid').forEach(function(el) {
    el.style.display = 'block';
  });
  const authBtn = document.getElementById('auth-btn');
  if (authBtn) {
    authBtn.style.display = 'inline-block';
    if (!currentUser) {
      authBtn.textContent = 'log in';
    }
  }
}

function checkSession() {
  socket.emit('user:getProfile', {}, (response) => {
    if (response && !response.error) {
      currentUser = response;
      showLoggedInUI();
    }
  });
}

function showLoggedInUI() {
  const authBtn = document.getElementById('auth-btn');
  if (authBtn) {
    authBtn.style.display = 'inline-block';
    authBtn.textContent = 'log out';
  }
  updateProfileUI();
  updateDownloadUI();
}

function showLoggedOutUI() {
  currentUser = null;
  const authBtn = document.getElementById('auth-btn');
  if (authBtn) {
    authBtn.textContent = 'log in';
  }
  document.getElementById('balance-xmr').textContent = 'monero balance: 0.000000 XMR';
  document.getElementById('balance-ltc').textContent = 'litecoin balance: 0.000000 LTC';
  document.getElementById('balance-usd').textContent = 'usd credits: $0.00 USD';
}

function updateProfileUI() {
  if (!currentUser) return;
  
  const profileContent = `
    <label class="back-btn" for="tab-transactions">&lt; back</label>
    <h1>Profile</h1>
    <p>account number: ${currentUser.account_number}</p>
    <p>license: ${currentUser.license || 'none'}</p>
    <p style="margin-top: 16px;"><span class="link-btn" onclick="document.getElementById('tab-manage').checked = true;">manage license</span></p>
  `;
  document.getElementById('panel-profile').innerHTML = profileContent;
  
  updateManageLicenseUI();
  
  const xmrEl = document.getElementById('balance-xmr');
  const ltcEl = document.getElementById('balance-ltc');
  const usdEl = document.getElementById('balance-usd');
  
  if (xmrEl) xmrEl.textContent = `monero balance: ${currentUser.balance.xmr.toFixed(6)} XMR`;
  if (ltcEl) ltcEl.textContent = `litecoin balance: ${currentUser.balance.ltc.toFixed(6)} LTC`;
  if (usdEl) usdEl.textContent = `usd credits: $${currentUser.balance.usd} USD`;
  
  const pending = currentUser.pending_transaction;
  const xmrBtn = document.getElementById('start-tx-btn');
  const ltcBtn = document.getElementById('start-ltc-btn');
  const xmrWarning = document.getElementById('pending-xmr-warning');
  const ltcWarning = document.getElementById('pending-ltc-warning');
  
  if (!pending) {
    if (xmrBtn) { xmrBtn.style.pointerEvents = 'auto'; xmrBtn.style.opacity = '1'; }
    if (ltcBtn) { ltcBtn.style.pointerEvents = 'auto'; ltcBtn.style.opacity = '1'; }
    if (xmrWarning) xmrWarning.style.display = 'none';
    if (ltcWarning) ltcWarning.style.display = 'none';
    return;
  }
  
  if (pending.currency === 'XMR') {
    if (xmrBtn) { xmrBtn.style.pointerEvents = 'none'; xmrBtn.style.opacity = '0.5'; }
    if (xmrWarning) xmrWarning.style.display = 'block';
  } else if (pending.currency === 'LTC') {
    if (ltcBtn) { ltcBtn.style.pointerEvents = 'none'; ltcBtn.style.opacity = '0.5'; }
    if (ltcWarning) ltcWarning.style.display = 'block';
  }
}

function updateManageLicenseUI() {
  if (!currentUser) {
    document.getElementById('panel-manage').innerHTML = `
      <label class="back-btn" for="tab-transactions">&lt; back</label>
      <h1>Manage License</h1>
      <p>not logged in</p>
    `;
    return;
  }
  
  const licenseIdEl = document.getElementById('manage-license-id');
  const timeRemainingEl = document.getElementById('manage-time-remaining');
  const licenseTypeEl = document.getElementById('manage-license-type');
  const hwidEl = document.getElementById('manage-hwid');
  
  if (licenseIdEl) licenseIdEl.textContent = 'license id: ' + (currentUser.license_id || 'none');
  if (timeRemainingEl) {
    if (currentUser.license && currentUser.license_status === 'active') {
      timeRemainingEl.textContent = 'license status: active';
    } else {
      timeRemainingEl.textContent = 'license status: ' + (currentUser.license_status || 'none');
    }
  }
  if (licenseTypeEl) licenseTypeEl.textContent = 'license type: ' + (currentUser.license || 'none');
  if (hwidEl) hwidEl.textContent = 'linked hwid: ' + (currentUser.hwid || 'N/A');
  
  updateDownloadUI();
}

function updateDownloadUI() {
  const msgEl = document.getElementById('download-message');
  const proDiv = document.getElementById('download-pro');
  const commDiv = document.getElementById('download-commercial');
  
  if (!currentUser) {
    if (msgEl) msgEl.textContent = 'not logged in';
    if (proDiv) proDiv.style.display = 'none';
    if (commDiv) commDiv.style.display = 'none';
    return;
  }
  
  if (!currentUser.license || currentUser.license_status !== 'active') {
    if (msgEl) msgEl.textContent = 'no active license';
    if (proDiv) proDiv.style.display = 'none';
    if (commDiv) commDiv.style.display = 'none';
    return;
  }
  
  if (msgEl) msgEl.textContent = '';
  if (currentUser.license === 'pro') {
    if (proDiv) proDiv.style.display = 'block';
    if (commDiv) commDiv.style.display = 'none';
  } else if (currentUser.license === 'commercial') {
    if (proDiv) proDiv.style.display = 'none';
    if (commDiv) commDiv.style.display = 'block';
  }
}

function doLogin(account_number, password, callback) {
  if (!socket || !socket.connected) {
    connectToBackend();
    setTimeout(() => doLogin(account_number, password, callback), 1000);
    return;
  }
  socket.emit('auth:login', { account_number, password }, (response) => {
    if (response.success) {
      socket.emit('user:getProfile', {}, (profile) => {
        currentUser = profile;
        showLoggedInUI();
        if (callback) callback(true, null);
      });
    } else {
      const feedback = document.getElementById('login-feedback');
      if (feedback) {
        feedback.textContent = response.error || 'login failed';
        setTimeout(() => { feedback.textContent = ''; }, 3000);
      }
      if (callback) callback(false, response.error);
    }
  });
}

function doRegister(password, callback) {
  if (!socket || !socket.connected) {
    connectToBackend();
    setTimeout(() => doRegister(password, callback), 500);
    return;
  }
  socket.emit('auth:register', { password, hwid: getHwid() }, (response) => {
    if (response.success) {
      socket.emit('user:getProfile', {}, (profile) => {
        currentUser = profile;
        showLoggedInUI();
        if (callback) callback(true);
      });
      document.getElementById('new-account-number').textContent = response.accountNumber;
      document.getElementById('tab-account-created').checked = true;
    } else {
      const feedback = document.getElementById('register-feedback');
      if (feedback) {
        feedback.textContent = response.error || 'registration failed';
        setTimeout(() => { feedback.textContent = ''; }, 3000);
      }
      if (callback) callback(false);
    }
  });
}

function verifyLicense(licenseId) {
  socket.emit('license:verify', { licenseId }, (response) => {
    if (response.valid) {
      currentUser = response;
      showLoggedInUI();
    } else {
      alert(response.error || 'Invalid license');
    }
  });
}

function createTransaction(currency, licenseType, hwid, callback) {
  socket.emit('tx:create', { currency, licenseType, hwid }, (response) => {
    if (response.success) {
      displayTransaction(response);
    } else {
      const isRateLimit = response.error && response.error.toLowerCase().includes('too many');
      if (isRateLimit) {
        if (currency === 'XMR') {
          document.getElementById('start-tx-btn').style.display = 'none';
          document.getElementById('rate-limit-msg').style.display = 'block';
        } else if (currency === 'LTC') {
          document.getElementById('start-ltc-btn').style.display = 'none';
          document.getElementById('rate-limit-msg-ltc').style.display = 'block';
        }
      } else {
        alert(response.error || 'Failed to create transaction');
      }
    }
    if (callback) callback(response);
  });
}

function displayTransaction(tx) {
  const tabMap = {
    'XMR': 'tab-monero-processing',
    'LTC': 'tab-litecoin-processing'
  };
  
  const panelMap = {
    'XMR': 'panel-monero-processing',
    'LTC': 'panel-litecoin-processing'
  };
  
  document.getElementById(tabMap[tx.currency]).checked = true;
  
  const content = `
    <div class="pgp-box">
      <pre>${tx.signed_address}</pre>
    </div>
    <p style="margin-top: 10px;">transaction id: ${(tx.tx_id || 'pending')}</p>
    <p style="margin-top: 10px;">amount: ${tx.amount} ${tx.currency}</p>
    <p style="margin-top: 10px;">waiting for transaction<span class="loader"><span>.</span><span>.</span><span>.</span></span></p>
  `;
  
  const panel = document.getElementById(panelMap[tx.currency]);
  if (panel) {
    panel.innerHTML = `<label class="back-btn" for="tab-payment">&lt; back</label>` + content;
  }
}

function doWithdraw(currency, amount, address) {
  socket.emit('tx:withdraw', { currency, amount, address }, (response) => {
    if (response.success) {
      const panel = document.getElementById('panel-withdrawing');
      panel.innerHTML = `
        <label class="back-btn" for="tab-withdraw">&lt; back</label>
        <h1>Withdrawing</h1>
        <p>broadcasting transaction<span class="loader"><span>.</span><span>.</span><span>.</span></span></p>
        <p style="margin-top: 10px;">transaction id: ${response.tx_id}</p>
      `;
    } else {
      alert(response.error || 'Withdrawal failed');
    }
  });
}

function getTransactionHistory() {
  socket.emit('history:get', {}, (response) => {
    if (response.history) {
      displayTransactionHistory(response.history);
    }
  });
}

function displayTransactionHistory(history) {
  let content = `
    <label class="back-btn" for="tab-transactions">&lt; back</label>
    <h1>History</h1>
  `;
  
  if (!history || history.length === 0) {
    content += '<p>no history to view</p>';
  } else {
    history.forEach(item => {
      if (item.type === 'transaction') {
        content += `
          <div style="border: 0.5px solid #fff; padding: 8px; margin-top: 8px;">
            <p><strong>Transaction</strong></p>
            <p>Type: ${item.subtype}</p>
            <p>Currency: ${item.currency}</p>
            <p>Amount: ${item.amount}</p>
            <p>Status: ${item.status}</p>
            ${item.tx_hash ? `<p>TX Hash: ${item.tx_hash}</p>` : ''}
            <p>Date: ${new Date(item.date).toLocaleString()}</p>
          </div>
        `;
      } else if (item.type === 'license') {
        content += `
          <div style="border: 0.5px solid #fff; padding: 8px; margin-top: 8px;">
            <p><strong>License</strong></p>
            <p>License ID: ${item.license_id}</p>
            <p>Type: ${item.license_type}</p>
            <p>Expires: ${item.expires_at ? new Date(item.expires_at).toLocaleString() : 'Never'}</p>
            <p>Created: ${new Date(item.date).toLocaleString()}</p>
          </div>
        `;
      }
    });
  }
  
  document.getElementById('panel-history').innerHTML = content;
}

function getHwid() {
  return null;
}

function initRelink(licenseId, callback) {
  socket.emit('license:initRelink', { licenseId }, (response) => {
    if (response.success) {
      callback(response);
    } else {
      alert(response.error || 'Failed to init relink');
      callback(null);
    }
  });
}

function doRelink(licenseId, machineInfo, callback) {
  socket.emit('license:relink', { licenseId, machineInfo }, (response) => {
    if (response.success) {
      alert('License relinked successfully');
    } else {
      alert(response.error || 'Failed to relink license');
    }
    callback(response);
  });
}

function canRelink(licenseId, callback) {
  socket.emit('license:canRelink', { licenseId }, (response) => {
    callback(response.canRelink);
  });
}

function doChangePassword(oldPassword, newPassword, callback) {
  socket.emit('user:changePassword', { oldPassword, newPassword }, (response) => {
    callback(response);
  });
}

function doDeleteAccount(password, callback) {
  socket.emit('user:deleteAccount', { password }, (response) => {
    if (response.success) {
      currentUser = null;
    }
    callback(response);
  });
}

function getSessions(callback) {
  socket.emit('user:getSessions', {}, (response) => {
    callback(response.sessions || []);
  });
}

function logoutAll(callback) {
  socket.emit('user:logoutAll', {}, (response) => {
    callback(response);
  });
}

window.obsidianClient = {
  connect: connectToBackend,
  login: doLogin,
  register: doRegister,
  verifyLicense,
  createTransaction,
  withdraw: doWithdraw,
  getHistory: getTransactionHistory,
  relink: doRelink,
  canRelink: canRelink,
  getHwid: getHwid,
  changePassword: doChangePassword,
  deleteAccount: doDeleteAccount,
  getSessions: getSessions,
  logoutAll: logoutAll,
  logout: function() {
    if (socket && socket.connected) {
      socket.emit('auth:logout', {}, () => {
        socket.disconnect();
        socket = null;
        currentUser = null;
        document.querySelectorAll('.tx-section, .tx-title, .tx-grid').forEach(function(el) {
          el.style.display = 'none';
        });
        document.querySelector('.tx-loading').style.display = 'none';
        document.querySelector('.tx-disconnected').style.display = 'block';
        document.getElementById('auth-btn').style.display = 'none';
      });
    }
  },
  connect: function() {
    connectToBackend();
  },
  goToPayment: function() {
    if (currentUser) {
      document.getElementById('tab-payment').checked = true;
    } else {
      document.getElementById('tab-login').checked = true;
    }
  },
  goToManage: function() {
    if (currentUser) {
      document.getElementById('tab-manage').checked = true;
    } else {
      document.getElementById('tab-login').checked = true;
    }
  },
  goToPaymentOption: function(type) {
    if (!currentUser) {
      document.getElementById('tab-login').checked = true;
      return;
    }
    const tabMap = {
      'creditcard': 'tab-creditcard-pay',
      'coinbase': 'tab-coinbase-pay',
      'monero': 'tab-monero-pay',
      'litecoin': 'tab-litecoin-pay'
    };
    document.getElementById(tabMap[type]).checked = true;
  },
  initRelink: initRelink,
  doRelink: doRelink
};
