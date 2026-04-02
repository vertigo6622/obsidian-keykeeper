const fs = require('fs');
const path = require('path');
const openpgp = require('openpgp');

const PGP_KEY_PATH = '/srv/keys/obsidiantest.asc';
const PGP_KEY_PASSPHRASE = process.env.PGP_KEY_PASSPHRASE;

let privateKey = null;
let privateKey_import = null;

async function loadPrivateKey() {
  if (privateKey) return privateKey;
  try {
    const armoredKey = fs.readFileSync(PGP_KEY_PATH, 'utf8');
    privateKey_import = await openpgp.readPrivateKey({ armoredKey });
    privateKey = await openpgp.decryptKey({ privateKey: privateKey_import, passphrase: PGP_KEY_PASSPHRASE });
    return privateKey;
  } catch (error) {
    console.error('Failed to load PGP key:', error);
    throw new Error('PGP key not available');
  }
}

async function signAddress(address, amount, currency, usdAmount) {
  const key = await loadPrivateKey();
  
  const messageText = `payment address: ${address}
amount: ${amount.toFixed(6)} ${currency} ($${usdAmount.toFixed(2)} USD)

always verify the pgp signature on this message to prevent phishing\n`;
  const message = await openpgp.createCleartextMessage({ text: messageText });
  const signed = await openpgp.sign({ message, signingKeys: key, format: 'armored' });
  return signed;
}

module.exports = {
  signAddress,
  loadPrivateKey
};
