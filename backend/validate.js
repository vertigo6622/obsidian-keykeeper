function sanitizeEmail(email) {
  if (!email || typeof email !== 'string') return null;
  return email.trim().toLowerCase().substring(0, 255);
}

function isValidEmail(email) {
  const sanitized = sanitizeEmail(email);
  if (!sanitized) return false;
  const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
  return emailRegex.test(sanitized);
}

function sanitizePassword(password) {
  if (!password || typeof password !== 'string') return null;
  const cleaned = password.replace(/\x00/g, '');
  if (cleaned.length < 8 || cleaned.length > 128) return null;
  return cleaned;
}

function sanitizeString(str, maxLength = 255) {
  if (!str || typeof str !== 'string') return null;
  return str.trim().substring(0, maxLength).replace(/[\x00-\x1F\x7F]/g, '');
}

function sanitizeLicenseId(id) {
  if (!id || typeof id !== 'string') return null;
  const sanitized = id.trim().toUpperCase().replace(/[^A-Z0-9]/g, '');
  if (sanitized.length !== 32 && sanitized.length !== 36) return null;
  
  if (sanitized.length === 32) {
    return sanitized.substring(0, 8) + '-' + 
           sanitized.substring(8, 12) + '-' + 
           sanitized.substring(12, 16) + '-' + 
           sanitized.substring(16, 20) + '-' + 
           sanitized.substring(20, 32);
  }
  
  return sanitized;
}

function sanitizeHwid(hwid) {
  if (!hwid || typeof hwid !== 'string') return null;
  const sanitized = hwid.trim().toUpperCase().replace(/[^A-Z0-9]/g, '');
  if (sanitized.length !== 32 && sanitized.length !== 36) return null;
  return sanitized;
}

function sanitizeAddress(address) {
  if (!address || typeof address !== 'string') return null;
  return address.trim().replace(/[\x00-\x1F\x7F]/g, '');
}

function isValidXMRAddress(address) {
  const clean = sanitizeAddress(address);
  if (!clean) return false;
  if (clean.length === 95) {
    return /^4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}$/.test(clean);
  }
  if (clean.length === 106) {
    return /^1^[0-9AB][1-9A-HJ-NP-Za-km-z]{93}[a-zA-Z0-9]{12}$/.test(clean);
  }
  return false;
}

function isValidLTCAddress(address) {
  const clean = sanitizeAddress(address);
  if (!clean) return false;
  if (clean.length < 26 || clean.length > 35) return false;
  const validMainNet = /^[LM3][a-km-zA-HJ-NP-Z1-9]{26,34}$/.test(clean);
  const validTestNet = /^(Q|m|n|2)[a-km-zA-HJ-NP-Z1-9]{26,34}$/.test(clean);
  return validMainNet || validTestNet;
}

function sanitizeCurrency(currency) {
  if (!currency || typeof currency !== 'string') return null;
  const valid = ['XMR', 'LTC', 'USD'];
  const sanitized = currency.trim().toUpperCase();
  return valid.includes(sanitized) ? sanitized : null;
}

function sanitizeLicenseType(type) {
  if (!type || typeof type !== 'string') return null;
  const valid = ['pro', 'commercial'];
  const sanitized = type.trim().toLowerCase();
  return valid.includes(sanitized) ? sanitized : null;
}

function sanitizeAmount(amount) {
  const num = parseFloat(amount);
  if (isNaN(num) || num <= 0 || num > 100000) return null;
  return num;
}

function sanitizeBoolean(value) {
  if (typeof value === 'boolean') return value;
  if (value === 'true' || value === '1') return true;
  if (value === 'false' || value === '0') return false;
  return null;
}

module.exports = {
  sanitizeEmail,
  isValidEmail,
  sanitizePassword,
  sanitizeString,
  sanitizeLicenseId,
  sanitizeHwid,
  sanitizeAddress,
  isValidXMRAddress,
  isValidLTCAddress,
  sanitizeCurrency,
  sanitizeLicenseType,
  sanitizeAmount,
  sanitizeBoolean
};
