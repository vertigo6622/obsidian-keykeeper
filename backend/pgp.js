const fs = require('fs');
const path = require('path');
const openpgp = require('openpgp');

const PGP_KEY_PATH = process.env.PGP_KEY_PATH || '/srv/pgp/key.asc';

let privateKey = null;

async function loadPrivateKey() {
  if (privateKey) return privateKey;
  
  try {
    const armoredKey = fs.readFileSync(PGP_KEY_PATH, 'utf8');
    privateKey = await openpgp.readPrivateKey({ armoredKey });
    return privateKey;
  } catch (error) {
    console.error('Failed to load PGP key:', error);
    throw new Error('PGP key not available');
  }
}

async function signAddress(address, amount, currency, usdAmount) {
  const key = await loadPrivateKey();
  
  const messageText = `Payment Address: ${address}
Amount: ${amount.toFixed(6)} ${currency} ($${usdAmount.toFixed(2)} USD)`;
  
  const message = await openpgp.createMessage({ text: messageText });
  const signed = await openpgp.sign({
    message,
    signingKeys: key,
    format: 'armored'
  });
  
  return signed;
}

module.exports = {
  signAddress
};
