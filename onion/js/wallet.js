const fetch = require('node-fetch');
const { SocksProxyAgent } = require('socks-proxy-agent');

const MONERO_RPC_URL = 'http://127.0.0.1:4331/json_rpc';
const ELECTRUM_LTC_URL = 'http://127.0.0.1:50001';

let cachedRates = { xmr: 0, ltc: 0, lastUpdate: 0, available: false };
const RATE_CACHE_MS = 5 * 60 * 1000;

const TOR_SOCKS_PROXY = process.env.TOR_SOCKS_PROXY || '127.0.0.1:9050';
const torAgent = new SocksProxyAgent('socks5h://' + TOR_SOCKS_PROXY);

async function getExchangeRates() {
  const now = Date.now();
  if (cachedRates.lastUpdate && (now - cachedRates.lastUpdate) < RATE_CACHE_MS) {
    return cachedRates;
  }
  
  try {
    const apiKey = process.env.COINGECKO_API_KEY;
    let url = 'https://api.coingecko.com/api/v3/simple/price?vs_currencies=usd&ids=monero,litecoin&names=Monero,Litecoin&symbols=xmr,ltc';
    if (apiKey) {
      url += '?x_cg_demo_api_key=' + apiKey;
    }
    
    const response = await fetch(url, { agent: torAgent });

    if (!response.ok) {
      console.error('CoinGecko error:', response.status, await response.text());
      throw new Error('CoinGecko API error');
    }
    const data = await response.json();
    
    cachedRates = {
      xmr: data.monero.usd,
      ltc: data.litecoin.usd,
      lastUpdate: now,
      available: true
    };

    console.log('[wallet] exchange rates updated - XMR: $' + cachedRates.xmr + ', LTC: $' + cachedRates.ltc);
    
    return cachedRates;
  } catch (error) {
    console.error('[wallet] failed to fetch exchange rates:', error.message);
    if (cachedRates.lastUpdate && cachedRates.available) {
      console.log('[wallet] using cached rates');
      return cachedRates;
    }
    cachedRates.available = false;
    return cachedRates;
  }
}

async function moneroRPC(method, params = {}) {
  const response = await fetch(MONERO_RPC_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: '0', method, params })
  });
  const data = await response.json();
  return data.result;
}

const ELECTRUM_LTC_USER = 'user';
const ELECTRUM_LTC_PASS = process.env.ELECTRUM_LTC_PASS;

async function electrumRPC(method, params = {}) {
  const response = await fetch(ELECTRUM_LTC_URL, {
    method: 'POST',
    headers: { 
      'Content-Type': 'application/json',
      'Authorization': 'Basic ' + Buffer.from(ELECTRUM_LTC_USER + ':' + ELECTRUM_LTC_PASS).toString('base64')
    },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method,
      params
    })
  });
  const data = await response.json();
  return data.result;
}

async function generateXMRAddress() {
  try {
    const result = await moneroRPC('create_address', { 
      account_index: 0 
    });
    return {
      address: result.address,
      subaddr_index: result.address_index
    };
  } catch (error) {
    console.error('XMR subaddress generation error:', error);
    throw new Error('Failed to generate XMR subaddress');
  }
}

async function generateLTCAddress() {
  try {
    const result = await electrumRPC('createnewaddress', {});
    return {
      address: result,
    };
  } catch (error) {
    console.error('LTC address generation error:', error);
    throw new Error('Failed to generate LTC address');
  }
}

async function getXMRBalance() {
  try {
    await moneroRPC('refresh', {});
    const result = await moneroRPC('get_balance', { account_index: 0 });
    return result.balance / 1e12;
  } catch (error) {
    console.error('XMR balance error:', error);
    return 0;
  }
}

async function getLTCBalance() {
  try {
    const result = await electrumRPC('getbalance', {});
    return result.confirmed || 0;
  } catch (error) {
    console.error('LTC balance error:', error);
    return 0;
  }
}

async function getXMRBalanceByAddress(subaddrIndex) {
  try {
    const result = await moneroRPC('get_transfers', {
      in: true,
      account_index: 0,
      subaddr_indices: [subaddrIndex]
    });
    if (!result.in) return 0;
	
    const transfer = result.in[0];
 
    return transfer.amount / 1e12; 
  } catch (error) {
    console.error('XMR balance error:', error);
    return 0;
  }
}

async function getXMRTransactionConfirmations(subaddrIndex) {
  try {
    const result = await moneroRPC('get_transfers', {
      in: true,
      account_index: 0,
      subaddr_indices: [subaddrIndex]
    });
    if (!result.in || result.in.length === 0) return 0;
    
    const transfer = result.in[0];
    return transfer.confirmations || 0;
    
  } catch (error) {
    console.error('XMR confirmations error:', error);
    return 0;
  }
}

async function getLTCTransactionConfirmations(address) {
  try {
    const info = await electrumRPC('getinfo', {});
    const currentHeight = info.height || info.blockchain_height || 0;
    const history = await electrumRPC('getaddresshistory', { address: address });
    if (!history || history.length === 0) return 0;
    if (history[0].height === 0 || history[0].height === -1) {
      return 0;
    }
    return Math.max(0, currentHeight - history[0].height + 1);
  } catch (error) {
    console.error('LTC confirmations error:', error);
    return 0;
  }
}

async function getLTCBalanceByAddress(address) {
  try {
    const result = await electrumRPC('getaddressbalance', { address: address });
    return result.confirmed || 0;
  } catch (error) {
    console.error('LTC balance by address error:', error);
    return 0;
  }
}

async function sendXMR(destination, amount) {
  try {
    const walletBalance = await getXMRBalance();
    if (walletBalance < amount) {
      throw new Error('Insufficient wallet funds');
    }
    const piconeroAmount = Math.round(amount * 1e12);
    const result = await moneroRPC('transfer', {
      destinations: [{ amount: piconeroAmount, address: destination }],
      priority: 1,
      ring_size: 16
    });
    return {
      txHash: result.tx_hash,
      fee: result.amount / 1e12
    };
  } catch (error) {
    console.error('XMR send error:', error);
    throw new Error('Failed to send XMR: ' + error.message);
  }
}

async function sendLTC(destination, amount) {
  try {
    const walletBalance = await getLTCBalance();
    if (walletBalance < amount) {
      throw new Error('Insufficient wallet funds');
    }
    const tx = await electrumRPC('payto', {
      destination: destination,
      amount: amount,
      fee_rate: 0.00001
    });
    const broadcast = await electrumRPC('broadcast', { tx: tx });
    return {
      txHash: broadcast[0].tx_hash,
      fee: tx.fee || 0
    };
  } catch (error) {
    console.error('LTC send error:', error);
    throw new Error('Failed to send LTC: ' + error.message);
  }
}

module.exports = {
  generateXMRAddress,
  generateLTCAddress,
  getXMRBalance,
  getLTCBalance,
  getXMRBalanceByAddress,
  getLTCBalanceByAddress,
  getExchangeRates,
  getXMRTransactionConfirmations,
  getLTCTransactionConfirmations,
  electrumRPC,
  moneroRPC,
  sendXMR,
  sendLTC
};
