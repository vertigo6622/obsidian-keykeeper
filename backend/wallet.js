const fetch = global.fetch || require('node-fetch');

const MONERO_RPC_URL = 'http://127.0.0.1:18086/json_rpc';
const ELECTRUM_LTC_URL = 'http://127.0.0.1:50001';

let cachedRates = { xmr: 0, ltc: 0, lastUpdate: 0, available: false };
const RATE_CACHE_MS = 5 * 60 * 1000;

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
    
    const response = await fetch(url);
    const data = await response.json();
    
    cachedRates = {
      xmr: data.monero.usd,
      ltc: data.litecoin.usd,
      lastUpdate: now,
      available: true
    };

    console.log('Exchange rates updated - XMR: $' + cachedRates.xmr + ', LTC: $' + cachedRates.ltc);
    
    return cachedRates;
  } catch (error) {
    console.error('Failed to fetch exchange rates:', error.message);
    if (cachedRates.lastUpdate && cachedRates.available) {
      console.log('Using cached rates');
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

async function electrumRPC(method, params = {}) {
  const response = await fetch(ELECTRUM_LTC_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ id: '0', method, params })
  });
  const data = await response.json();
  return data.result;
}

async function generateXMRAddress() {
  try {
    const result = await moneroRPC('make_integrated_address', { payment_id: null });
    return {
      address: result.integrated_address,
      payment_id: result.payment_id
    };
  } catch (error) {
    console.error('XMR address generation error:', error);
    throw new Error('Failed to generate XMR address');
  }
}

async function generateLTCAddress() {
  try {
    const result = await electrumRPC('create_address', { wallet_id: 'main' });
    return {
      address: result.address,
      wallet_id: result.wallet_id
    };
  } catch (error) {
    console.error('LTC address generation error:', error);
    throw new Error('Failed to generate LTC address');
  }
}

async function getXMRBalance() {
  try {
    const result = await moneroRPC('get_balance', { account_index: 0 });
    return result.balance / 1e12;
  } catch (error) {
    console.error('XMR balance error:', error);
    return 0;
  }
}

async function getLTCBalance() {
  try {
    const result = await electrumRPC('get_balance', { wallet_id: 'main' });
    return result.confirmed;
  } catch (error) {
    console.error('LTC balance error:', error);
    return 0;
  }
}

async function getXMRBalanceByAddress(address) {
  try {
    const parts = address.split(',');
    let paymentId = null;
    let integratedAddress = address;
    
    if (address.length === 106) {
      paymentId = address.slice(-64);
      integratedAddress = address.slice(0, -65);
    }
    
    const result = await moneroRPC('get_balance', { account_index: 0, address: integratedAddress });
    return result.balance / 1e12;
  } catch (error) {
    console.error('XMR balance by address error:', error);
    return 0;
  }
}

async function getLTCBalanceByAddress(address) {
  try {
    const result = await electrumRPC('get_address_balance', { address: address });
    return result.confirmed / 1e8;
  } catch (error) {
    console.error('LTC balance by address error:', error);
    return 0;
  }
}

module.exports = {
  generateXMRAddress,
  generateLTCAddress,
  getXMRBalance,
  getLTCBalance,
  getXMRBalanceByAddress,
  getLTCBalanceByAddress,
  getExchangeRates
};
